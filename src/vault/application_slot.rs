//! Fixed synthetic application-file installation through held directory handles.
//!
//! This optional drill installs only built-in canaries. The same UID can read or
//! alter the application and its fixture keys: all protection claims stay false.
//! Inspection checks evidence without completing an intent or restoring authority.
mod directory;

use self::directory::Directory;
use super::{
    crypto::{self, PrivateBytes, Signed, Verifier},
    model::DeliveryProfile,
    process_recipient::RecipientTarget,
    process_service,
    store::{self, Ack, ReceiptContract, RecipientMaterial, RecipientOutcome},
};
use crate::{ErrorCode, RequestId};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, Mutex},
};

const SLOT: &str = "provider-auth";
const STAGE: &str = ".provider-auth.stage";
const JOURNAL: &str = "installation.jws";
const MAX_LOG: usize = 512 * 1024;
const MAX_VALUE: usize = 4096;
const MAX_RECORDS: u64 = 5; // genesis plus two intent/completion pairs
const DURABILITY: &str = "file-sync-rename-directory-sync-v1";

/// Successful fixed import, authenticated delivery, duplicate, restart and revoke.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationSlotReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub authenticated_role_channels: usize,
    pub tls13_mutual_authentication_verified: bool,
    pub separate_broker_process: bool,
    pub separate_recipient_process: bool,
    pub broker_and_recipient_reaped: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub completed_installations: usize,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub installed_version: u64,
    pub incomplete_installations: usize,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub revoked: bool,
    pub revocation_survived_restart: bool,
    pub agent_transcript_contains_canary: bool,
    pub installation_receipt_verified: bool,
    pub handle_relative_operations: bool,
    pub application_slot: &'static str,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub independent_human_presence_verified: bool,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Read-only evidence. An intent can coexist with an old or new actual file;
/// neither fact upgrades an uncertain broker outcome to completed authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationSlotRecoveryReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub separate_broker_process: bool,
    pub separate_recipient_process: bool,
    pub broker_and_recipient_reaped: bool,
    pub completed_installations: usize,
    pub consumed_uses: usize,
    pub incomplete_deliveries: usize,
    pub unknown_deliveries: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub installed_version: u64,
    pub incomplete_installations: usize,
    pub revoked: bool,
    pub installation_receipt_verified: bool,
    pub handle_relative_operations: bool,
    pub application_slot: &'static str,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Create a new dummy fixture with one imported canary and a fixed file slot.
/// The executable must dispatch process_service::synthetic_child_entry first.
pub fn run_synthetic_application_slot_drill(
    root: &Path,
) -> Result<ApplicationSlotReport, ErrorCode> {
    let report = process_service::run_contract(root, ReceiptContract::Installation)?;
    let inspected = inspect_synthetic_application_slot(root)?;
    if inspected.completed_installations != 1
        || inspected.installed_version != 1
        || inspected.incomplete_installations != 0
        || !inspected.installation_receipt_verified
    {
        return Err(ErrorCode::ReconciliationRequired);
    }
    Ok(report_from_service(report, inspected))
}
pub(super) fn report_from_service(
    report: process_service::ProcessServiceReport,
    inspected: ApplicationSlotRecoveryReport,
) -> ApplicationSlotReport {
    ApplicationSlotReport {
        synthetic_only: true,
        input_import_bound: true,
        authenticated_role_channels: report.authenticated_role_channels,
        tls13_mutual_authentication_verified: report.tls13_mutual_authentication_verified,
        separate_broker_process: true,
        separate_recipient_process: true,
        broker_and_recipient_reaped: report.broker_and_recipient_reaped,
        unauthenticated_agent_denied: report.unauthenticated_agent_denied,
        unauthenticated_admin_denied: report.unauthenticated_admin_denied,
        completed_installations: inspected.completed_installations,
        consumed_uses: report.consumed_uses,
        remaining_uses: report.remaining_uses,
        recipient_generation: inspected.recipient_generation,
        installed_version: inspected.installed_version,
        incomplete_installations: inspected.incomplete_installations,
        duplicate_reused: report.duplicate_reused,
        cold_start_required_authentication: report.cold_start_required_authentication,
        revoked: report.revoked,
        revocation_survived_restart: report.revocation_survived_restart,
        agent_transcript_contains_canary: report.agent_transcript_contains_canary,
        installation_receipt_verified: true,
        handle_relative_operations: true,
        application_slot: SLOT,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    }
}

/// Inspect only. No directory/file is created, written, repaired or replayed.
pub fn inspect_synthetic_application_slot(
    root: &Path,
) -> Result<ApplicationSlotRecoveryReport, ErrorCode> {
    let r = process_service::inspect_contract(root, ReceiptContract::Installation)?;
    recovery_from_observation(r)
}
pub(super) fn recovery_from_observation(
    r: process_service::Observation,
) -> Result<ApplicationSlotRecoveryReport, ErrorCode> {
    let installed_version = r
        .installed_version
        .ok_or(ErrorCode::ReconciliationRequired)?;
    let incomplete_installations = r
        .incomplete_installations
        .ok_or(ErrorCode::ReconciliationRequired)?;
    Ok(ApplicationSlotRecoveryReport {
        synthetic_only: true,
        input_import_bound: true,
        separate_broker_process: true,
        separate_recipient_process: true,
        broker_and_recipient_reaped: true,
        completed_installations: r.generation as usize,
        consumed_uses: r.consumed,
        incomplete_deliveries: r.incomplete,
        unknown_deliveries: r.unknown,
        remaining_uses: r.remaining,
        recipient_generation: r.generation,
        installed_version,
        incomplete_installations,
        revoked: r.revoked,
        installation_receipt_verified: r.generation != 0,
        handle_relative_operations: true,
        application_slot: SLOT,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationReceipt {
    ack: Ack,
    profile: DeliveryProfile,
    prior_generation: u64,
    slot_filename: String,
    file_digest: String,
    directory_device: u64,
    directory_inode: u64,
    durability: String,
}
fn canary(version: u64) -> Result<&'static str, ErrorCode> {
    match version {
        1 => Ok(store::CANARY_ONE),
        2 => Ok(store::CANARY_TWO),
        _ => Err(ErrorCode::InvalidProviderResult),
    }
}
pub(super) fn receipt_ack(signed: &Signed, verifier: &Verifier) -> Result<Ack, ErrorCode> {
    Ok(verifier.verify::<InstallationReceipt>(signed)?.ack)
}
pub(super) fn verify_installation_receipt(
    signed: &Signed,
    verifier: &Verifier,
    vault: &str,
    id: &RequestId,
    profile: &DeliveryProfile,
    digest: &str,
) -> Result<Ack, ErrorCode> {
    let receipt: InstallationReceipt = verifier.verify(signed)?;
    let ack = &receipt.ack;
    if ack.kind != "aegis.synthetic.application-slot.installed.v1"
        || receipt.profile != *profile
        || receipt.prior_generation.checked_add(1) != Some(ack.generation)
        || receipt.slot_filename != SLOT
        || receipt.file_digest != crypto::hash(canary(ack.version)?.as_bytes())
        || receipt.directory_inode == 0
        || receipt.durability != DURABILITY
    {
        return Err(ErrorCode::InvalidProviderResult);
    }
    // Reuse all legacy tuple checks only after enforcing the installation domain.
    let mut tuple = ack.clone();
    tuple.kind = "aegis.synthetic.recipient.ack.v1".into();
    store::validate_ack(&tuple, vault, id, profile, digest)?;
    Ok(receipt.ack)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    capsule: String,
    capsule_digest: String,
    prior_generation: u64,
    next_generation: u64,
    file_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Genesis,
    Intent { intent: Intent },
    Complete { receipt: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    schema: u16,
    kind: String,
    vault_id: String,
    sequence: u64,
    previous: String,
    directory_device: u64,
    directory_inode: u64,
    slot: String,
    event: Event,
}
struct State {
    file: File,
    sequence: u64,
    head: String,
    bytes: usize,
    log_digest: String,
    generation: u64,
    pending: Option<Intent>,
    receipts: BTreeMap<RequestId, (String, String)>,
    failed: bool,
}
pub(super) struct SlotRecipient {
    directory: Directory,
    material: Arc<RecipientMaterial>,
    state: Mutex<State>,
    read_only: bool,
}
impl SlotRecipient {
    #[cfg(test)]
    pub(super) fn check_store(&self, store: &store::Store) -> Result<(), ErrorCode> {
        if store.receipt_contract() != ReceiptContract::Installation {
            return Err(ErrorCode::ReconciliationRequired);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        self.check_disk(&mut state)?;
        let received = state
            .receipts
            .iter()
            .map(|(id, (digest, _))| (id.clone(), digest.clone()))
            .collect();
        store.check_process_receipts(&received)
    }

    pub(super) fn acquire(
        root: &Path,
        material: Arc<RecipientMaterial>,
        create: bool,
        read_only: bool,
    ) -> Result<Arc<Self>, ErrorCode> {
        if create && read_only {
            return Err(ErrorCode::InvalidRequest);
        }
        let directory = Directory::acquire(root, create)?;
        let file = if create {
            directory.create(JOURNAL)?
        } else {
            directory.open(JOURNAL, !read_only)?
        };
        file.try_lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let mut state = State {
            file,
            sequence: 0,
            head: String::new(),
            bytes: 0,
            log_digest: crypto::hash(&[]),
            generation: 0,
            pending: None,
            receipts: BTreeMap::new(),
            failed: false,
        };
        if !create {
            let bytes = Self::read_log(&mut state.file)?;
            if bytes.is_empty() || bytes.last() != Some(&b'\n') {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            for line in bytes.split_inclusive(|b| *b == b'\n') {
                let signed = Signed::parse(&line[..line.len() - 1])?;
                Self::apply(&directory, &material, &mut state, &signed)?;
            }
            state.bytes = bytes.len();
            state.log_digest = crypto::hash(&bytes);
        }
        let this = Arc::new(Self {
            directory,
            material,
            state: Mutex::new(state),
            read_only,
        });
        {
            let mut state = this
                .state
                .lock()
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            if create {
                this.append(&mut state, Event::Genesis)?;
                this.directory.sync()?;
            }
            this.check_disk(&mut state)?;
        }
        Ok(this)
    }
    fn read_log(file: &mut File) -> Result<Vec<u8>, ErrorCode> {
        if file
            .metadata()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?
            .len()
            > MAX_LOG as u64
        {
            return Err(ErrorCode::CapacityExceeded);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let mut bytes = Vec::new();
        file.take((MAX_LOG + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if bytes.len() > MAX_LOG {
            return Err(ErrorCode::CapacityExceeded);
        }
        Ok(bytes)
    }
    fn apply(
        directory: &Directory,
        material: &RecipientMaterial,
        state: &mut State,
        signed: &Signed,
    ) -> Result<(), ErrorCode> {
        let frame: Frame = material.receipt.verifier().verify(signed)?;
        let (device, inode) = directory.identity()?;
        if frame.schema != 1
            || frame.kind != "aegis.synthetic.application-slot.journal.v1"
            || frame.vault_id != material.vault_id
            || frame.sequence != state.sequence + 1
            || frame.sequence > MAX_RECORDS
            || frame.previous != state.head
            || frame.directory_device != device
            || frame.directory_inode != inode
            || frame.slot != SLOT
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        match frame.event {
            Event::Genesis => {
                if state.sequence != 0 {
                    return Err(ErrorCode::PersistenceUnavailable);
                }
            }
            Event::Intent { intent } => {
                if state.sequence == 0 || state.pending.is_some() || state.generation >= 2 {
                    return Err(ErrorCode::PersistenceUnavailable);
                }
                let signed = Signed::parse(intent.capsule.as_bytes())?;
                let (capsule, value) =
                    store::decode_capsule_for(material, &signed, ReceiptContract::Installation)?;
                if intent.capsule_digest != crypto::hash(signed.bytes())
                    || intent.prior_generation != state.generation
                    || intent.next_generation != state.generation + 1
                    || capsule.expected_generation != state.generation
                    || capsule.profile.secret.version != intent.next_generation
                    || intent.file_digest != crypto::hash(value.value.as_bytes())
                    || state.receipts.contains_key(&capsule.delivery_id)
                {
                    return Err(ErrorCode::PersistenceUnavailable);
                }
                state.pending = Some(intent);
            }
            Event::Complete { receipt } => {
                let intent = state
                    .pending
                    .as_ref()
                    .ok_or(ErrorCode::PersistenceUnavailable)?;
                let (capsule, _) = store::decode_capsule_for(
                    material,
                    &Signed::parse(intent.capsule.as_bytes())?,
                    ReceiptContract::Installation,
                )?;
                let signed = Signed::parse(receipt.as_bytes())?;
                let ack = verify_installation_receipt(
                    &signed,
                    &material.receipt.verifier(),
                    &material.vault_id,
                    &capsule.delivery_id,
                    &capsule.profile,
                    &intent.capsule_digest,
                )?;
                let full: InstallationReceipt = material.receipt.verifier().verify(&signed)?;
                if full.directory_device != device
                    || full.directory_inode != inode
                    || full.file_digest != intent.file_digest
                    || ack.generation != intent.next_generation
                {
                    return Err(ErrorCode::PersistenceUnavailable);
                }
                state.generation = ack.generation;
                state
                    .receipts
                    .insert(ack.delivery_id, (ack.capsule_digest, receipt));
                state.pending = None;
            }
        }
        state.sequence = frame.sequence;
        state.head = crypto::hash(signed.bytes());
        Ok(())
    }
    fn append(&self, state: &mut State, event: Event) -> Result<(), ErrorCode> {
        let (directory_device, directory_inode) = self.directory.identity()?;
        let signed = self.material.receipt.sign(&Frame {
            schema: 1,
            kind: "aegis.synthetic.application-slot.journal.v1".into(),
            vault_id: self.material.vault_id.clone(),
            sequence: state.sequence + 1,
            previous: state.head.clone(),
            directory_device,
            directory_inode,
            slot: SLOT.into(),
            event,
        })?;
        let mut bytes = signed.bytes().to_vec();
        bytes.push(b'\n');
        if state.bytes.saturating_add(bytes.len()) > MAX_LOG {
            return Err(ErrorCode::CapacityExceeded);
        }
        self.directory.validate_file(JOURNAL, &state.file)?;
        state
            .file
            .seek(SeekFrom::End(0))
            .and_then(|_| state.file.write_all(&bytes))
            .and_then(|_| state.file.sync_all())
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        Self::apply(&self.directory, &self.material, state, &signed)?;
        state.bytes += bytes.len();
        state.log_digest = crypto::hash(&Self::read_log(&mut state.file)?);
        Ok(())
    }
    fn check_disk(&self, state: &mut State) -> Result<u64, ErrorCode> {
        self.directory.check()?;
        self.directory.validate_file(JOURNAL, &state.file)?;
        let bytes = Self::read_log(&mut state.file)?;
        if bytes.len() != state.bytes || crypto::hash(&bytes) != state.log_digest {
            return Err(ErrorCode::ReconciliationRequired);
        }
        let current = self
            .directory
            .read_optional(SLOT, MAX_VALUE)?
            .map(PrivateBytes);
        let installed = match current.as_ref().map(|b| b.0.as_slice()) {
            None if state.generation == 0 => 0,
            Some(value) if value == store::CANARY_ONE.as_bytes() => 1,
            Some(value) if value == store::CANARY_TWO.as_bytes() => 2,
            _ => return Err(ErrorCode::ReconciliationRequired),
        };
        let stage = self
            .directory
            .read_optional(STAGE, MAX_VALUE)?
            .map(PrivateBytes);
        match &state.pending {
            None => {
                if installed != state.generation || stage.is_some() {
                    return Err(ErrorCode::ReconciliationRequired);
                }
            }
            Some(intent) => {
                if installed != state.generation && installed != intent.next_generation {
                    return Err(ErrorCode::ReconciliationRequired);
                }
                if stage
                    .as_ref()
                    .is_some_and(|s| crypto::hash(&s.0) != intent.file_digest)
                    || (installed == intent.next_generation && stage.is_some())
                {
                    return Err(ErrorCode::ReconciliationRequired);
                }
            }
        }
        Ok(installed)
    }
    fn install(&self, state: &mut State, signed: &Signed) -> Result<Signed, ErrorCode> {
        let (capsule, payload) =
            store::decode_capsule_for(&self.material, signed, ReceiptContract::Installation)?;
        let capsule_digest = crypto::hash(signed.bytes());
        let intent = Intent {
            capsule: std::str::from_utf8(signed.bytes())
                .map_err(|_| ErrorCode::InvalidRequest)?
                .into(),
            capsule_digest: capsule_digest.clone(),
            prior_generation: state.generation,
            next_generation: state.generation + 1,
            file_digest: crypto::hash(payload.value.as_bytes()),
        };
        self.append(
            state,
            Event::Intent {
                intent: intent.clone(),
            },
        )?;
        fault(1);
        let mut stage = self.directory.create(STAGE)?;
        stage
            .write_all(payload.value.as_bytes())
            .and_then(|_| stage.sync_all())
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        self.directory.validate_file(STAGE, &stage)?;
        fault(2);
        self.directory.replace(STAGE, SLOT)?;
        fault(3);
        self.directory.validate_file(SLOT, &stage)?;
        self.directory.sync()?;
        fault(4);
        let (directory_device, directory_inode) = self.directory.identity()?;
        let ack = self.material.receipt.sign(&InstallationReceipt {
            ack: Ack {
                schema: 1,
                kind: "aegis.synthetic.application-slot.installed.v1".into(),
                vault_id: self.material.vault_id.clone(),
                delivery_id: capsule.delivery_id,
                recipient: capsule.profile.recipient.clone(),
                version: capsule.profile.secret.version,
                generation: intent.next_generation,
                capsule_digest,
            },
            profile: capsule.profile,
            prior_generation: intent.prior_generation,
            slot_filename: SLOT.into(),
            file_digest: intent.file_digest,
            directory_device,
            directory_inode,
            durability: DURABILITY.into(),
        })?;
        self.append(
            state,
            Event::Complete {
                receipt: std::str::from_utf8(ack.bytes())
                    .map_err(|_| ErrorCode::InvalidProviderResult)?
                    .into(),
            },
        )?;
        fault(5);
        self.check_disk(state)?;
        Ok(ack)
    }
}
impl RecipientTarget for SlotRecipient {
    fn contract(&self) -> ReceiptContract {
        ReceiptContract::Installation
    }
    fn process_receipts(&self) -> Result<(u64, Vec<String>), ErrorCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        if state.failed {
            return Err(ErrorCode::ReconciliationRequired);
        }
        self.check_disk(&mut state)?;
        Ok((
            state.generation,
            state
                .receipts
                .values()
                .map(|(_, receipt)| receipt.clone())
                .collect(),
        ))
    }
    fn installation_state(&self) -> Result<(Option<u64>, Option<usize>), ErrorCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        let installed = self.check_disk(&mut state)?;
        Ok((Some(installed), Some(usize::from(state.pending.is_some()))))
    }
    fn accept(&self, signed: Signed) -> RecipientOutcome {
        let Ok(mut state) = self.state.lock() else {
            return RecipientOutcome::Unknown;
        };
        if self.read_only || state.failed {
            return RecipientOutcome::Unknown;
        }
        if self.check_disk(&mut state).is_err() {
            state.failed = true;
            return RecipientOutcome::Unknown;
        }
        let Ok((capsule, _)) =
            store::decode_capsule_for(&self.material, &signed, ReceiptContract::Installation)
        else {
            return RecipientOutcome::Rejected;
        };
        let digest = crypto::hash(signed.bytes());
        if let Some((retained, receipt)) = state.receipts.get(&capsule.delivery_id) {
            return if *retained == digest {
                Signed::parse(receipt.as_bytes())
                    .map(RecipientOutcome::Acknowledged)
                    .unwrap_or(RecipientOutcome::Unknown)
            } else {
                RecipientOutcome::Rejected
            };
        }
        if state.pending.is_some() {
            return RecipientOutcome::Unknown;
        }
        if capsule.expected_generation != state.generation || state.generation >= 2 {
            return RecipientOutcome::Rejected;
        }
        state.failed = true;
        match self.install(&mut state, &signed) {
            Ok(receipt) => {
                state.failed = false;
                RecipientOutcome::Acknowledged(receipt)
            }
            Err(_) => RecipientOutcome::Unknown,
        }
    }
}
impl Drop for SlotRecipient {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        let _ = state.file.unlock();
    }
}

#[cfg(test)]
static CHILD_FAULT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) fn set_child_fault(mode: &str) -> Result<(), ErrorCode> {
    let point = match mode {
        "slot-recipient-exit-intent" | "slot-rotation-recipient-exit-intent" => 1,
        "slot-recipient-exit-stage" | "slot-rotation-recipient-exit-stage" => 2,
        "slot-recipient-exit-rename" | "slot-rotation-recipient-exit-rename" => 3,
        "slot-recipient-exit-directory" | "slot-rotation-recipient-exit-directory" => 4,
        "slot-recipient-exit-receipt" | "slot-rotation-recipient-exit-receipt" => 5,
        _ => return Err(ErrorCode::InvalidRequest),
    };
    CHILD_FAULT.store(point, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}
fn fault(point: usize) {
    #[cfg(test)]
    if CHILD_FAULT.load(std::sync::atomic::Ordering::SeqCst) == point {
        std::process::exit(93);
    }
    #[cfg(not(test))]
    let _ = point;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{vault::runtime::Host, Lifecycle, ManualClock};
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "aegis-application-unit-{}",
                crypto::random_id().unwrap()
            ));
            store::new_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Paths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn broker_authorized_two_version_replacement_preserves_old_receipt_without_rollback() {
        let paths = Paths::new();
        let kit = store::Kit::create(&paths.0.join("kit")).unwrap();
        let store =
            store::Store::create_installation(&paths.0.join("vault"), kit.broker_material())
                .unwrap();
        let recipient =
            SlotRecipient::acquire(&paths.0, kit.recipient_material(), true, false).unwrap();
        let host = Host::compose(
            kit.clone(),
            store,
            recipient.clone(),
            1,
            Arc::new(ManualClock::default()),
        )
        .unwrap();
        host.connect().unwrap();
        let id = host.prepare("application-version-one", 1).unwrap();
        let first = host.reviewed_invoke(id).unwrap();
        assert_eq!(first.state, Lifecycle::Succeeded);
        assert_eq!(host.agent.invoke_operation(id).unwrap(), first);
        let slot = paths.0.join("application/provider-auth");
        let mut old = File::open(&slot).unwrap();
        let first_inode = old.metadata().unwrap().ino();
        assert_eq!(fs::read(&slot).unwrap(), store::CANARY_ONE.as_bytes());
        let journal = fs::read(paths.0.join("application/installation.jws")).unwrap();
        let intent: Frame = kit
            .receipt
            .verifier()
            .verify(&Signed::parse(journal.split(|b| *b == b'\n').nth(1).unwrap()).unwrap())
            .unwrap();
        let Event::Intent { intent } = intent.event else {
            panic!("intent required")
        };
        let first_receipt = recipient
            .state
            .lock()
            .unwrap()
            .receipts
            .values()
            .next()
            .unwrap()
            .1
            .clone();
        drop(host);
        drop(recipient);

        let store = store::Store::open(&paths.0.join("vault"), kit.broker_material()).unwrap();
        assert_eq!(store.receipt_contract(), ReceiptContract::Installation);
        let recipient =
            SlotRecipient::acquire(&paths.0, kit.recipient_material(), false, false).unwrap();
        let host = Host::compose(
            kit.clone(),
            store.clone(),
            recipient.clone(),
            2,
            Arc::new(ManualClock::default()),
        )
        .unwrap();
        host.connect().unwrap();
        let id = host.prepare("application-version-two", 2).unwrap();
        let second = host.reviewed_invoke(id).unwrap();
        assert_eq!(second.state, Lifecycle::Succeeded);
        assert_eq!(host.agent.invoke_operation(id).unwrap(), second);
        assert_eq!(fs::read(&slot).unwrap(), store::CANARY_TWO.as_bytes());
        assert_ne!(fs::metadata(&slot).unwrap().ino(), first_inode);
        let mut old_bytes = Vec::new();
        old.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, store::CANARY_ONE.as_bytes());
        let RecipientOutcome::Acknowledged(duplicate) =
            recipient.accept(Signed::parse(intent.capsule.as_bytes()).unwrap())
        else {
            panic!("retained receipt required")
        };
        assert_eq!(duplicate.bytes(), first_receipt.as_bytes());
        assert_eq!(fs::read(&slot).unwrap(), store::CANARY_TWO.as_bytes());
        assert_eq!(store.history_counts().unwrap(), (2, 0, 0, 2, false));
        assert_eq!(recipient.process_receipts().unwrap().0, 2);
        drop(host);
        drop(store);
        drop(recipient);
        let inspected =
            SlotRecipient::acquire(&paths.0, kit.recipient_material(), false, true).unwrap();
        assert_eq!(inspected.installation_state().unwrap(), (Some(2), Some(0)));
        assert_eq!(inspected.process_receipts().unwrap().1.len(), 2);
    }

    #[test]
    fn correctly_signed_receipt_tuple_changes_and_legacy_ack_are_rejected() {
        let paths = Paths::new();
        let kit = store::Kit::create(&paths.0.join("kit")).unwrap();
        let id = RequestId::new("receipt-tuple").unwrap();
        let profile = ReceiptContract::Installation.profile(1);
        let digest = crypto::hash(b"fixed synthetic capsule");
        let receipt = InstallationReceipt {
            ack: Ack {
                schema: 1,
                kind: "aegis.synthetic.application-slot.installed.v1".into(),
                vault_id: kit.vault_id.clone(),
                delivery_id: id.clone(),
                recipient: profile.recipient.clone(),
                version: 1,
                generation: 1,
                capsule_digest: digest.clone(),
            },
            profile: profile.clone(),
            prior_generation: 0,
            slot_filename: SLOT.into(),
            file_digest: crypto::hash(store::CANARY_ONE.as_bytes()),
            directory_device: 1,
            directory_inode: 1,
            durability: DURABILITY.into(),
        };
        let signed = kit.receipt.sign(&receipt).unwrap();
        let verify = |s: &Signed| {
            verify_installation_receipt(
                s,
                &kit.receipt.verifier(),
                &kit.vault_id,
                &id,
                &profile,
                &digest,
            )
        };
        assert!(verify(&signed).is_ok());
        let mutations: Vec<fn(&mut InstallationReceipt)> = vec![
            |r| r.ack.schema += 1,
            |r| r.ack.kind = "aegis.synthetic.recipient.ack.v1".into(),
            |r| r.ack.vault_id.push('x'),
            |r| r.ack.delivery_id = RequestId::new("wrong-request").unwrap(),
            |r| r.ack.recipient.slot = "another-slot".into(),
            |r| r.ack.version = 2,
            |r| r.ack.generation = 2,
            |r| r.ack.capsule_digest = crypto::hash(b"other"),
            |r| r.profile.adapter_contract = 1,
            |r| r.profile.output_contract = 1,
            |r| r.prior_generation = 1,
            |r| r.slot_filename = ".provider-auth.stage".into(),
            |r| r.file_digest = crypto::hash(store::CANARY_TWO.as_bytes()),
            |r| r.directory_inode = 0,
            |r| r.durability = "accepted-encrypted-capsule".into(),
        ];
        for mutate in mutations {
            let mut changed: InstallationReceipt = kit.receipt.verifier().verify(&signed).unwrap();
            mutate(&mut changed);
            assert!(verify(&kit.receipt.sign(&changed).unwrap()).is_err());
        }
        let mut legacy = receipt.ack.clone();
        legacy.kind = "aegis.synthetic.recipient.ack.v1".into();
        assert!(verify(&kit.receipt.sign(&legacy).unwrap()).is_err());
        assert!(ReceiptContract::Acceptance
            .verify_ack(
                &signed,
                &kit.receipt.verifier(),
                &kit.vault_id,
                &id,
                &DeliveryProfile::fixture(1),
                &digest
            )
            .is_err());
    }

    #[test]
    fn legacy_import_cannot_be_reinterpreted_as_installation_and_reverse() {
        for contract in [ReceiptContract::Acceptance, ReceiptContract::Installation] {
            let paths = Paths::new();
            let kit = store::Kit::create(&paths.0.join("kit")).unwrap();
            let material = kit.broker_material();
            let imported = super::super::entry::protected_entry::import_delivery_canary_contract(
                &paths.0.join("input"),
                &material,
                contract,
            )
            .unwrap();
            let wrong = if contract == ReceiptContract::Acceptance {
                ReceiptContract::Installation
            } else {
                ReceiptContract::Acceptance
            };
            assert!(store::Store::create_imported_contract(
                &paths.0.join("vault"),
                material,
                imported,
                wrong
            )
            .is_err());
            assert!(!paths.0.join("vault").exists());
        }
    }
}
