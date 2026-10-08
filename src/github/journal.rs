//! Synthetic-only append/sync journal. Trusted local storage, no authenticity or rollback claim.
use super::model::{Binding, Moment, Permission, Repository, MAX_RECORDS};
use super::{GithubError, JournalError, JournalRecovery};
use crate::types::{PrincipalId, ProfileId, RequestId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

#[cfg(test)]
const SCHEMA: u32 = 1;
const KIND: &str = "aegis.synthetic.github.intents.v1";
const BROKER_KIND: &str = "aegis.synthetic.github.broker-intents.v2";
const MAX_BYTES: usize = 512 * 1024;
const MAX_LINE: usize = 8 * 1024;
const MAX_EVENTS: usize = 512;
const FILE_NAME: &str = "intents.jsonl";

/// Flattened named fields avoid duplicate-map-key ambiguity in persisted authority context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    app_id: u64,
    client_id: String,
    installation_id: u64,
    account_id: u64,
    login: String,
    account_kind: String,
    selection: String,
    repository_id: u64,
    repository_name: String,
    repository_owner_id: u64,
    signer_id: String,
    signer_version: u64,
    binding_revision: u64,
    contents_ceiling: Permission,
    metadata_ceiling: Permission,
    requested_metadata: Permission,
    operation: String,
    output_revision: u32,
}
impl Enrollment {
    pub fn from_binding(binding: &Binding, repo: &Repository) -> Result<Self, JournalError> {
        // This storage experiment must never become a caller-configurable enrollment path.
        if *binding != Binding::fixture() || *repo != Binding::fixture().repositories[0] {
            return Err(JournalError::InvalidJournal);
        }
        Ok(Self {
            app_id: binding.app_id,
            client_id: binding.client_id.clone(),
            installation_id: binding.installation_id,
            account_id: binding.account_id,
            login: binding.login.clone(),
            account_kind: "User".into(),
            selection: "selected".into(),
            repository_id: repo.id,
            repository_name: repo.name.clone(),
            repository_owner_id: repo.owner_id,
            signer_id: binding.signer_id.clone(),
            signer_version: binding.signer_version,
            binding_revision: binding.revision,
            contents_ceiling: Permission::Write,
            metadata_ceiling: Permission::Read,
            requested_metadata: Permission::Read,
            operation: "synthetic.github.repository_metadata.v1".into(),
            output_revision: 1,
        })
    }
    fn fixture() -> Self {
        Self::from_binding(&Binding::fixture(), &Binding::fixture().repositories[0])
            .expect("fixed enrollment")
    }
    fn broker_fixture() -> Self {
        let mut value = Self::fixture();
        value.operation = "synthetic.github.repository-metadata.v1".into();
        value
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub request_id: RequestId,
    pub instance: [u8; 16],
    pub enrollment: Enrollment,
    pub approval_revision: u64,
    pub reserved_at: Moment,
    pub approval_expires_elapsed: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerContext {
    pub principal: PrincipalId,
    pub session: u64,
    pub profile_id: ProfileId,
    pub policy_generation: u64,
    pub initial_uses: u32,
    pub session_started_at: u64,
    pub maximum_requests: usize,
    pub maximum_concurrent: usize,
    pub idle_seconds: u64,
    pub maximum_seconds: u64,
    pub request_seconds: u64,
    pub approval_mode: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerReview {
    pub reviewed_request_id: RequestId,
    pub principal: PrincipalId,
    pub session: u64,
    pub profile_id: ProfileId,
    pub prepared_request_id: u64,
    pub profile_revision: u64,
    pub policy_generation: u64,
    pub credential_version: u64,
    pub adapter_contract: u32,
    pub output_contract: u32,
    pub reviewed_remaining_uses: u32,
    pub remaining_before: u32,
    pub remaining_after: u32,
    pub reviewed_expires_elapsed: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Terminal {
    Succeeded,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Event {
    Start {
        kind: String,
        instance: [u8; 16],
        enrollment: Enrollment,
        maximum_reservations: usize,
    },
    StartBroker {
        kind: String,
        instance: [u8; 16],
        enrollment: Enrollment,
        maximum_reservations: usize,
        context: BrokerContext,
    },
    Reserve {
        intent: Intent,
    },
    BrokerReserve {
        intent: Intent,
        review: BrokerReview,
    },
    MintIntent {
        request_id: RequestId,
    },
    TokenReceived {
        request_id: RequestId,
        reported_expires_at: u64,
    },
    TokenValidated {
        request_id: RequestId,
    },
    ReadIntent {
        request_id: RequestId,
        mint_request_id: RequestId,
    },
    Complete {
        request_id: RequestId,
        outcome: Terminal,
        blocks_new_requests: bool,
    },
    RevokeAuthority {},
    RevokeIntent {
        mint_request_id: RequestId,
    },
    RevokeComplete {
        mint_request_id: RequestId,
        confirmed: bool,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    schema_version: u32,
    sequence: usize,
    event: Event,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserved,
    Minting,
    Received,
    Validated,
    Reading,
}
#[derive(Clone)]
struct Operation {
    reserved_at: Moment,
    phase: Phase,
    terminal: Option<Terminal>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Revocation {
    NotStarted,
    InProgress,
    Confirmed,
    Unknown,
}
#[derive(Clone)]
struct LeaseRecord {
    reported_expires_at: u64,
    validated: bool,
    revocation: Revocation,
}
#[derive(Clone, Default)]
struct Replay {
    schema: u32,
    broker: Option<BrokerContext>,
    remaining: u32,
    prepared_handles: std::collections::BTreeSet<u64>,
    instance: Option<[u8; 16]>,
    operations: BTreeMap<RequestId, Operation>,
    leases: BTreeMap<RequestId, LeaseRecord>,
    authority_revoked: bool,
    blocked: bool,
    last_reservation: Option<Moment>,
    events: usize,
}
impl Replay {
    fn apply(&mut self, event: &Event) -> Result<(), JournalError> {
        if self.events >= MAX_EVENTS {
            return Err(JournalError::CapacityExceeded);
        }
        if self.instance.is_none()
            && !matches!(event, Event::Start { .. } | Event::StartBroker { .. })
        {
            return Err(JournalError::InvalidJournal);
        }
        match event {
            Event::Start {
                kind,
                instance,
                enrollment,
                maximum_reservations,
            } => {
                if self.schema != 1
                    || self.events != 0
                    || kind != KIND
                    || *instance == [0; 16]
                    || *enrollment != Enrollment::fixture()
                    || *maximum_reservations != MAX_RECORDS
                {
                    return Err(JournalError::InvalidJournal);
                }
                self.instance = Some(*instance);
            }
            Event::StartBroker {
                kind,
                instance,
                enrollment,
                maximum_reservations,
                context,
            } => {
                if self.schema != 2
                    || self.events != 0
                    || kind != BROKER_KIND
                    || *instance == [0; 16]
                    || *enrollment != Enrollment::broker_fixture()
                    || *maximum_reservations != MAX_RECORDS
                    || context.session != 1
                    || context.profile_id.as_str() != "github-metadata"
                    || context.policy_generation != 1
                    || context.initial_uses == 0
                    || context.initial_uses > 32
                    || context.maximum_requests == 0
                    || context.maximum_requests > 32
                    || context.maximum_concurrent != 1
                    || context.idle_seconds == 0
                    || context.idle_seconds > 600
                    || context.maximum_seconds == 0
                    || context.maximum_seconds > 1800
                    || context.request_seconds == 0
                    || context.request_seconds > 15
                    || context.approval_mode != "each_request_reviewed"
                {
                    return Err(JournalError::InvalidJournal);
                }
                self.instance = Some(*instance);
                self.remaining = context.initial_uses;
                self.broker = Some(context.clone());
            }
            Event::Reserve { intent } => {
                if self.schema != 1 {
                    return Err(JournalError::InvalidJournal);
                }
                self.reserve_intent(intent)?;
            }
            Event::BrokerReserve { intent, review } => {
                let context = self.broker.as_ref().ok_or(JournalError::InvalidJournal)?;
                if self.schema != 2
                    || review.reviewed_request_id != intent.request_id
                    || review.principal != context.principal
                    || review.session != context.session
                    || review.profile_id != context.profile_id
                    || review.policy_generation != context.policy_generation
                    || review.profile_revision != 1
                    || review.credential_version != 1
                    || review.adapter_contract != 1
                    || review.output_contract != 1
                    || review.prepared_request_id == 0
                    || review.prepared_request_id > context.maximum_requests as u64
                    || self.prepared_handles.contains(&review.prepared_request_id)
                    || review.remaining_before != self.remaining
                    || review.remaining_before == 0
                    || review.remaining_after.checked_add(1) != Some(review.remaining_before)
                    || review.reviewed_remaining_uses < review.remaining_before
                    || review.reviewed_remaining_uses > context.initial_uses
                    || review.reviewed_expires_elapsed != intent.approval_expires_elapsed
                    || intent.reserved_at.elapsed < context.session_started_at
                    || intent
                        .reserved_at
                        .elapsed
                        .saturating_sub(context.session_started_at)
                        >= context.maximum_seconds
                    || intent
                        .approval_expires_elapsed
                        .saturating_sub(intent.reserved_at.elapsed)
                        > context.request_seconds
                {
                    return Err(JournalError::InvalidJournal);
                }
                self.reserve_intent(intent)?;
                self.prepared_handles.insert(review.prepared_request_id);
                self.remaining = review.remaining_after;
            }
            Event::MintIntent { request_id } => {
                let operation = self.active(request_id)?;
                if operation.phase != Phase::Reserved {
                    return Err(JournalError::InvalidJournal);
                }
                operation.phase = Phase::Minting;
            }
            Event::TokenReceived {
                request_id,
                reported_expires_at,
            } => {
                let operation = self.active(request_id)?;
                if operation.phase != Phase::Minting {
                    return Err(JournalError::InvalidJournal);
                }
                operation.phase = Phase::Received;
                if self
                    .leases
                    .insert(
                        request_id.clone(),
                        LeaseRecord {
                            reported_expires_at: *reported_expires_at,
                            validated: false,
                            revocation: Revocation::NotStarted,
                        },
                    )
                    .is_some()
                {
                    return Err(JournalError::InvalidJournal);
                }
            }
            Event::TokenValidated { request_id } => {
                let operation = self.active(request_id)?;
                if operation.phase != Phase::Received {
                    return Err(JournalError::InvalidJournal);
                }
                let reserved_at = operation.reserved_at;
                let lease = self
                    .leases
                    .get_mut(request_id)
                    .ok_or(JournalError::InvalidJournal)?;
                if !matches!(lease.reported_expires_at.checked_sub(reserved_at.unix), Some(seconds) if seconds > super::model::REFRESH_MARGIN && seconds <= super::model::TOKEN_SECONDS)
                {
                    return Err(JournalError::InvalidJournal);
                }
                lease.validated = true;
                self.operations
                    .get_mut(request_id)
                    .expect("checked operation")
                    .phase = Phase::Validated;
            }
            Event::ReadIntent {
                request_id,
                mint_request_id,
            } => {
                let lease = self
                    .leases
                    .get(mint_request_id)
                    .ok_or(JournalError::InvalidJournal)?;
                if !lease.validated || lease.revocation != Revocation::NotStarted {
                    return Err(JournalError::InvalidJournal);
                }
                let operation = self.active(request_id)?;
                if !matches!(operation.phase, Phase::Reserved | Phase::Validated) {
                    return Err(JournalError::InvalidJournal);
                }
                operation.phase = Phase::Reading;
            }
            Event::Complete {
                request_id,
                outcome,
                blocks_new_requests,
            } => {
                let operation = self.active(request_id)?;
                if *outcome == Terminal::Succeeded && operation.phase != Phase::Reading {
                    return Err(JournalError::InvalidJournal);
                }
                if (*outcome == Terminal::Unknown || operation.phase == Phase::Received)
                    && !blocks_new_requests
                {
                    return Err(JournalError::InvalidJournal);
                }
                operation.terminal = Some(*outcome);
                self.blocked |= blocks_new_requests;
            }
            Event::RevokeAuthority {} => {
                if self.authority_revoked {
                    return Err(JournalError::InvalidJournal);
                }
                self.authority_revoked = true;
            }
            Event::RevokeIntent { mint_request_id } => {
                if !self.authority_revoked
                    || self
                        .operations
                        .values()
                        .any(|operation| operation.terminal.is_none())
                {
                    return Err(JournalError::InvalidJournal);
                }
                let lease = self
                    .leases
                    .get_mut(mint_request_id)
                    .ok_or(JournalError::InvalidJournal)?;
                if lease.revocation != Revocation::NotStarted {
                    return Err(JournalError::InvalidJournal);
                }
                lease.revocation = Revocation::InProgress;
            }
            Event::RevokeComplete {
                mint_request_id,
                confirmed,
            } => {
                let lease = self
                    .leases
                    .get_mut(mint_request_id)
                    .ok_or(JournalError::InvalidJournal)?;
                if lease.revocation != Revocation::InProgress {
                    return Err(JournalError::InvalidJournal);
                }
                lease.revocation = if *confirmed {
                    Revocation::Confirmed
                } else {
                    Revocation::Unknown
                };
            }
        }
        self.events += 1;
        Ok(())
    }
    fn reserve_intent(&mut self, intent: &Intent) -> Result<(), JournalError> {
        if self.authority_revoked
            || self.blocked
            || self.operations.len() >= MAX_RECORDS
            || self.operations.contains_key(&intent.request_id)
            || Some(intent.instance) != self.instance
            || intent.enrollment
                != if self.schema == 2 {
                    Enrollment::broker_fixture()
                } else {
                    Enrollment::fixture()
                }
            || intent.approval_revision != 1
            || intent.reserved_at.unix < 60
            || intent.approval_expires_elapsed <= intent.reserved_at.elapsed
            || intent
                .approval_expires_elapsed
                .saturating_sub(intent.reserved_at.elapsed)
                > 30
            || self
                .last_reservation
                .is_some_and(|old| intent.reserved_at.validate_after(old).is_err())
            || self
                .operations
                .values()
                .any(|operation| operation.terminal.is_none())
        {
            return Err(JournalError::InvalidJournal);
        }
        self.last_reservation = Some(intent.reserved_at);
        self.operations.insert(
            intent.request_id.clone(),
            Operation {
                reserved_at: intent.reserved_at,
                phase: Phase::Reserved,
                terminal: None,
            },
        );
        Ok(())
    }
    fn active(&mut self, id: &RequestId) -> Result<&mut Operation, JournalError> {
        let operation = self
            .operations
            .get_mut(id)
            .ok_or(JournalError::InvalidJournal)?;
        if operation.terminal.is_some() {
            return Err(JournalError::InvalidJournal);
        }
        Ok(operation)
    }
    fn recovery(&self) -> JournalRecovery {
        let incomplete_operations = self
            .operations
            .values()
            .filter(|op| op.terminal.is_none())
            .count();
        let unknown_operations = self
            .operations
            .values()
            .filter(|op| {
                op.terminal == Some(Terminal::Unknown)
                    || (op.terminal.is_none() && op.phase != Phase::Reserved)
            })
            .count();
        let uncertain_mints = self
            .operations
            .values()
            .filter(|op| op.phase == Phase::Minting && op.terminal != Some(Terminal::Failed))
            .count();
        let unresolved_tokens = self
            .leases
            .values()
            .filter(|lease| lease.revocation != Revocation::Confirmed)
            .count();
        let uncertain_revocations = self
            .leases
            .values()
            .filter(|lease| {
                matches!(
                    lease.revocation,
                    Revocation::InProgress | Revocation::Unknown
                )
            })
            .count();
        JournalRecovery {
            synthetic_only: true,
            reservations_consumed: self.operations.len(),
            incomplete_operations,
            unknown_operations,
            uncertain_mints,
            unresolved_tokens,
            uncertain_revocations,
            local_authority_revoked: self.authority_revoked,
            restored_grants: 0,
            restored_sessions: 0,
            automatic_retry_allowed: false,
            reconciliation_required: incomplete_operations > 0
                || unknown_operations > 0
                || uncertain_mints > 0
                || unresolved_tokens > 0
                || uncertain_revocations > 0,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Fault {
    BeforeWrite,
    PartialWrite,
    AfterWrite,
    AfterSync,
}
struct Writer {
    file: File,
    replay: Replay,
    bytes: usize,
    failed: bool,
    #[cfg(test)]
    fault: Option<(usize, Fault)>,
}
pub(super) struct Journal {
    writer: Mutex<Writer>,
}
impl Drop for Journal {
    fn drop(&mut self) {
        // Explicitly unlock rather than relying solely on final descriptor closure:
        // a concurrent process spawn can briefly inherit the open-file description
        // before CLOEXEC closes it. No writer handle escapes this private type.
        let writer = self
            .writer
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = writer.file.unlock();
    }
}
impl Journal {
    pub fn create(path: &Path, instance: [u8; 16]) -> Result<Self, JournalError> {
        Self::create_with_header(
            path,
            1,
            Event::Start {
                kind: KIND.into(),
                instance,
                enrollment: Enrollment::fixture(),
                maximum_reservations: MAX_RECORDS,
            },
        )
    }
    pub fn create_broker(
        path: &Path,
        instance: [u8; 16],
        context: BrokerContext,
    ) -> Result<Self, JournalError> {
        Self::create_with_header(
            path,
            2,
            Event::StartBroker {
                kind: BROKER_KIND.into(),
                instance,
                enrollment: Enrollment::broker_fixture(),
                maximum_reservations: MAX_RECORDS,
                context,
            },
        )
    }
    fn create_with_header(path: &Path, schema: u32, header: Event) -> Result<Self, JournalError> {
        validate_path(path)?;
        let parent = path.parent().ok_or(JournalError::InvalidPath)?;
        if !parent.is_dir() {
            return Err(JournalError::InvalidPath);
        }
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    JournalError::DestinationExists
                } else {
                    JournalError::Io
                }
            })?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path.join(FILE_NAME))
            .map_err(|_| JournalError::Io)?;
        file.try_lock().map_err(|_| JournalError::Busy)?;
        validate_file(&file)?;
        let journal = Self {
            writer: Mutex::new(Writer {
                file,
                replay: Replay {
                    schema,
                    ..Replay::default()
                },
                bytes: 0,
                failed: false,
                #[cfg(test)]
                fault: None,
            }),
        };
        journal.append(header)?;
        // Name durability is required before any runtime can attach or dispatch.
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| JournalError::Io)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| JournalError::Io)?;
        Ok(journal)
    }
    pub fn append(&self, event: Event) -> Result<(), JournalError> {
        let mut writer = self.writer.lock().map_err(|_| JournalError::Unavailable)?;
        if writer.failed {
            return Err(JournalError::Unavailable);
        }
        let mut replay = writer.replay.clone();
        if let Err(error) = replay.apply(&event) {
            writer.failed = true;
            return Err(error);
        }
        let mut bytes = serde_json::to_vec(&Frame {
            schema_version: writer.replay.schema,
            sequence: writer.replay.events + 1,
            event,
        })
        .map_err(|_| JournalError::InvalidJournal)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_LINE || writer.bytes.saturating_add(bytes.len()) > MAX_BYTES {
            writer.failed = true;
            return Err(JournalError::CapacityExceeded);
        }
        // Poison before writing. Any write/sync error or panic forbids later appends.
        writer.failed = true;
        #[cfg(test)]
        let fault = writer
            .fault
            .filter(|(sequence, _)| *sequence == replay.events)
            .map(|(_, fault)| fault);
        #[cfg(test)]
        if matches!(fault, Some(Fault::BeforeWrite)) {
            return Err(JournalError::Io);
        }
        #[cfg(test)]
        if matches!(fault, Some(Fault::PartialWrite)) {
            writer
                .file
                .write_all(&bytes[..bytes.len() / 2])
                .map_err(|_| JournalError::Io)?;
            writer.file.sync_all().map_err(|_| JournalError::Io)?;
            return Err(JournalError::Io);
        }
        writer
            .file
            .write_all(&bytes)
            .map_err(|_| JournalError::Io)?;
        #[cfg(test)]
        if matches!(fault, Some(Fault::AfterWrite)) {
            return Err(JournalError::Io);
        }
        writer.file.sync_all().map_err(|_| JournalError::Io)?;
        #[cfg(test)]
        if matches!(fault, Some(Fault::AfterSync)) {
            return Err(JournalError::Io);
        }
        writer.bytes += bytes.len();
        writer.replay = replay;
        writer.failed = false;
        Ok(())
    }
    pub fn reserve(
        &self,
        request_id: RequestId,
        instance: [u8; 16],
        binding: &Binding,
        repo: &Repository,
        time_bounds: (Moment, u64),
        review: Option<BrokerReview>,
    ) -> Result<(), JournalError> {
        let (at, expires_elapsed) = time_bounds;
        let mut enrollment = Enrollment::from_binding(binding, repo)?;
        if review.is_some() {
            enrollment.operation = Enrollment::broker_fixture().operation;
        }
        let intent = Intent {
            request_id,
            instance,
            enrollment,
            approval_revision: 1,
            reserved_at: at,
            approval_expires_elapsed: expires_elapsed,
        };
        self.append(match review {
            Some(review) => Event::BrokerReserve { intent, review },
            None => Event::Reserve { intent },
        })
    }
    #[cfg(test)]
    pub fn fault(&self, sequence: usize, fault: Fault) {
        self.writer.lock().unwrap().fault = Some((sequence, fault));
    }
}

fn validate_path(path: &Path) -> Result<(), JournalError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(JournalError::InvalidPath);
    }
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(JournalError::UnsafeFile)
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(JournalError::Io),
        }
    }
    Ok(())
}
fn validate_file(file: &File) -> Result<(), JournalError> {
    let metadata = file.metadata().map_err(|_| JournalError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(JournalError::UnsafeFile);
    }
    Ok(())
}
fn parse(bytes: &[u8]) -> Result<Replay, JournalError> {
    if bytes.len() > MAX_BYTES {
        return Err(JournalError::CapacityExceeded);
    }
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(JournalError::InvalidJournal);
    }
    let mut replay = Replay::default();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.len() > MAX_LINE {
            return Err(JournalError::CapacityExceeded);
        }
        let frame: Frame =
            serde_json::from_slice(line).map_err(|_| JournalError::InvalidJournal)?;
        if !matches!(frame.schema_version, 1 | 2) {
            return Err(JournalError::UnsupportedSchema);
        }
        if replay.events == 0 {
            replay.schema = frame.schema_version;
        }
        if replay.schema != frame.schema_version {
            return Err(JournalError::InvalidJournal);
        }
        if frame.sequence != replay.events + 1 {
            return Err(JournalError::InvalidJournal);
        }
        replay.apply(&frame.event)?;
    }
    Ok(replay)
}
pub(super) fn inspect(path: &Path) -> Result<JournalRecovery, JournalError> {
    validate_path(path)?;
    let directory = fs::symlink_metadata(path).map_err(|_| JournalError::Io)?;
    if !directory.is_dir()
        || directory.uid() != nix::unistd::Uid::effective().as_raw()
        || directory.mode() & 0o077 != 0
    {
        return Err(JournalError::UnsafeFile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path.join(FILE_NAME))
        .map_err(|_| JournalError::Io)?;
    validate_file(&file)?;
    // A cooperating writer holds the same inode lock until its fixture drops.
    file.try_lock_shared().map_err(|_| JournalError::Busy)?;
    if file.metadata().map_err(|_| JournalError::Io)?.len() > MAX_BYTES as u64 {
        return Err(JournalError::CapacityExceeded);
    }
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    Ok(parse(&bytes)?.recovery())
}
impl From<JournalError> for GithubError {
    fn from(_: JournalError) -> Self {
        Self::PersistenceUnavailable
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
