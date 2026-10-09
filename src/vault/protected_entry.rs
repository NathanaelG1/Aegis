//! Bounded, zeroizing input and encrypted import exercised only with fixed canaries.
//!
//! No public reader, credential argument, terminal input or live import exists.
//! This is not authenticated human presence, a protected display, OS custody or
//! an operational vault. The public drill writes a disposable encrypted fixture.
//!
//! ```compile_fail
//! use aegis::vault::entry::protected_entry::ImportSession;
//! ```
//! ```compile_fail
//! aegis::vault::entry::protected_entry::run_synthetic_protected_entry_drill(
//!     std::path::Path::new("/tmp/fixture"), b"credential");
//! ```
use super::{reviewed_fixture, CanaryReservation, Ceremony, FrozenReview, RoleBinding};
use crate::{
    vault::{
        crypto::{self, Identity, PrivateBytes},
        store,
    },
    ErrorCode, ManualClock,
};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use zeroize::Zeroizing;

const MAX_INPUT: usize = 4096;
const MAX_METADATA: usize = 15 * 1024;
const INPUT_MAGIC: &[u8; 8] = b"AEGISIN1";
const ENVELOPE_MAGIC: &[u8; 8] = b"AEGISIM1";
const CANARY: &[u8] = b"AEGIS_DISPOSABLE_PROTECTED_ENTRY_CANARY_NOT_A_CREDENTIAL";
const STAGED: &str = "record.pending";
const COMMITTED: &str = "record.age";

/// Safe observations from a fixed, disposable input/import exercise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtectedEntryReport {
    pub synthetic_only: bool,
    pub maximum_reader_payload_bytes: usize,
    pub fixed_import_payload_bytes: usize,
    pub encrypted_fixture_imported: bool,
    pub exact_metadata_round_trip: bool,
    pub repeated_import: ErrorCode,
    pub cancellation: ErrorCode,
    pub trailing_input: ErrorCode,
    pub plaintext_in_persisted_fixture: bool,
    pub plaintext_in_report: bool,
    pub authenticated_human_verified: bool,
    pub protected_display_verified: bool,
    pub protected_custody_verified: bool,
    pub operational_recovery_verified: bool,
    pub ready_for_real_keys: bool,
}

// These are metadata only. Input itself deliberately has no Debug, Clone,
// Serialize, Display, callback or plaintext-export implementation.
#[derive(Clone, Eq, PartialEq, Serialize)]
struct ImportReview {
    entry: FrozenReview,
    destination: PathBuf,
    storage_recipient: String,
    input_contract: u32,
    maximum_input_bytes: usize,
}
struct Input {
    bytes: Zeroizing<[u8; MAX_INPUT]>,
    len: usize,
}
impl Input {
    fn read(
        reader: &mut impl Read,
        mut check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        // Fixed-size initialized allocations; no read_to_end, String or realloc.
        let mut header = Zeroizing::new([0u8; 12]);
        let mut attempts = MAX_INPUT * 2 + 64;
        read_exact(reader, &mut header[..], &mut attempts, &mut check)?;
        if &header[..8] != INPUT_MAGIC {
            return Err(ErrorCode::InvalidRequest);
        }
        let len = u32::from_be_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| ErrorCode::InvalidRequest)?,
        ) as usize;
        if len == 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        if len > MAX_INPUT {
            return Err(ErrorCode::CapacityExceeded);
        }
        let mut value = Self {
            bytes: Zeroizing::new([0; MAX_INPUT]),
            len,
        };
        read_exact(reader, &mut value.bytes[..len], &mut attempts, &mut check)?;
        let mut tail = Zeroizing::new([0u8; 1]);
        if read_once(reader, &mut tail[..], &mut attempts, &mut check)? != 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(value)
    }
}
fn read_once(
    reader: &mut impl Read,
    bytes: &mut [u8],
    attempts: &mut usize,
    check: &mut impl FnMut() -> Result<(), ErrorCode>,
) -> Result<usize, ErrorCode> {
    loop {
        check()?;
        *attempts = attempts.checked_sub(1).ok_or(ErrorCode::CapacityExceeded)?;
        let result = reader.read(bytes);
        check()?;
        match result {
            Ok(n) if n <= bytes.len() => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(ErrorCode::InvalidRequest),
        }
    }
}
fn read_exact(
    reader: &mut impl Read,
    bytes: &mut [u8],
    attempts: &mut usize,
    check: &mut impl FnMut() -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    let mut offset = 0;
    while offset < bytes.len() {
        let n = read_once(reader, &mut bytes[offset..], attempts, check)?;
        if n == 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        offset += n;
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Frozen,
    Approved,
    Reading,
    Canceled,
    Failed,
    Committed,
    Uncertain,
}
struct State {
    phase: Phase,
    last_time: u64,
    reservation: Option<CanaryReservation>,
}
struct ImportSession<'a> {
    ceremony: &'a Ceremony,
    review: ImportReview,
    state: Mutex<State>,
}
impl<'a> ImportSession<'a> {
    fn fixture(
        ceremony: &'a Ceremony,
        destination: &Path,
        identity: &Identity,
    ) -> Result<Self, ErrorCode> {
        validate_destination(destination)?;
        Ok(Self {
            ceremony,
            review: ImportReview {
                entry: reviewed_fixture(ceremony)?,
                destination: destination.into(),
                storage_recipient: identity.recipient().to_string(),
                input_contract: 1,
                maximum_input_bytes: MAX_INPUT,
            },
            state: Mutex::new(State {
                phase: Phase::Frozen,
                last_time: ceremony.started_at,
                reservation: None,
            }),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        self.state.lock().map_err(|_| ErrorCode::BrokerUnavailable)
    }
    fn check_view(&self, state: &mut State, current: &ImportReview) -> Result<(), ErrorCode> {
        if current != &self.review {
            state.phase = Phase::Failed;
            state.reservation = None;
            return Err(ErrorCode::PolicyChanged);
        }
        let now = self.ceremony.clock.now();
        if now < state.last_time {
            state.phase = Phase::Failed;
            state.reservation = None;
            return Err(ErrorCode::SessionExpired);
        }
        state.last_time = now;
        if now >= self.review.entry.expires_at {
            state.phase = Phase::Failed;
            state.reservation = None;
            return Err(ErrorCode::RequestExpired);
        }
        Ok(())
    }
    fn approve(&self, operator: &RoleBinding, expected: &ImportReview) -> Result<(), ErrorCode> {
        let mut state = self.lock()?;
        if state.phase != Phase::Frozen {
            return Err(ErrorCode::BudgetExhausted);
        }
        self.check_view(&mut state, expected)?;
        self.ceremony
            .approve(&expected.entry.bindings, operator, &expected.entry)?;
        let reservation = self
            .ceremony
            .reserve(&expected.entry.bindings, &expected.entry)?;
        if reservation.instance != self.review.entry.instance
            || reservation.review != self.review.entry
        {
            state.phase = Phase::Failed;
            return Err(ErrorCode::PolicyChanged);
        }
        state.reservation = Some(reservation);
        state.phase = Phase::Approved;
        Ok(())
    }
    fn cancel(&self, operator: &RoleBinding) -> Result<(), ErrorCode> {
        let mut state = self.lock()?;
        if operator != &self.review.entry.bindings.operator {
            return Err(ErrorCode::AuthenticationRequired);
        }
        match state.phase {
            Phase::Frozen | Phase::Approved | Phase::Reading => {
                state.phase = Phase::Canceled;
                state.reservation = None;
                Ok(())
            }
            Phase::Canceled => Ok(()),
            _ => Err(ErrorCode::BudgetExhausted),
        }
    }
    fn reading(&self, state: &mut State, current: &ImportReview) -> Result<(), ErrorCode> {
        if state.phase == Phase::Canceled {
            return Err(ErrorCode::RequestCanceled);
        }
        if state.phase != Phase::Reading {
            return Err(ErrorCode::BudgetExhausted);
        }
        self.check_view(state, current)
    }
    fn import(
        &self,
        reader: &mut impl Read,
        current: &ImportReview,
        identity: &Identity,
        fault: Fault,
    ) -> Result<(), ErrorCode> {
        {
            let mut state = self.lock()?;
            match state.phase {
                Phase::Canceled => return Err(ErrorCode::RequestCanceled),
                Phase::Frozen => return Err(ErrorCode::ApprovalRequired),
                Phase::Approved => {}
                _ => return Err(ErrorCode::BudgetExhausted),
            }
            // Consume before any input read or filesystem effect, including errors.
            state.phase = Phase::Reading;
            if state.reservation.take().is_none() {
                state.phase = Phase::Failed;
                return Err(ErrorCode::ApprovalRequired);
            }
        }
        let result = self.import_reserved(reader, current, identity, fault);
        if result.is_err() {
            let mut state = self.lock()?;
            if state.phase == Phase::Reading {
                state.phase = Phase::Failed;
            }
        }
        result
    }
    fn import_reserved(
        &self,
        reader: &mut impl Read,
        current: &ImportReview,
        identity: &Identity,
        fault: Fault,
    ) -> Result<(), ErrorCode> {
        self.reading(&mut *self.lock()?, current)?;
        if identity.recipient().to_string() != self.review.storage_recipient {
            return Err(ErrorCode::PolicyChanged);
        }
        let input = Input::read(reader, || self.reading(&mut *self.lock()?, current))?;
        // Defense in depth: even private integration cannot import arbitrary bytes.
        if input.bytes[..input.len] != *CANARY {
            return Err(ErrorCode::ScopeDenied);
        }
        let plaintext = envelope(&self.review, &input)?;
        let ciphertext = crypto::encrypt(&plaintext.0, &identity.recipient())?;
        drop(plaintext);
        drop(input);
        self.reading(&mut *self.lock()?, current)?;
        let mut transaction = Transaction::stage(&self.review.destination, &ciphertext, fault)?;
        let mut state = self.lock()?;
        if let Err(error) = self.reading(&mut state, current) {
            return transaction.abort(error);
        }
        // Cancellation and publication use the same lock. Once publication wins,
        // cancellation cannot claim that it removed a committed/uncertain import.
        match transaction.publish(fault) {
            Ok(()) => {
                state.phase = Phase::Committed;
                Ok(())
            }
            Err(_) if transaction.published => {
                state.phase = Phase::Uncertain;
                Err(ErrorCode::ReconciliationRequired)
            }
            Err(error) => {
                state.phase = Phase::Failed;
                transaction.abort(error)
            }
        }
    }
}
fn envelope(review: &ImportReview, input: &Input) -> Result<PrivateBytes, ErrorCode> {
    let metadata = serde_json::to_vec(review).map_err(|_| ErrorCode::InvalidRequest)?;
    let total = 16usize
        .checked_add(metadata.len())
        .and_then(|length| length.checked_add(input.len))
        .ok_or(ErrorCode::CapacityExceeded)?;
    if metadata.len() > MAX_METADATA || total > crypto::MAX_CLEAR {
        return Err(ErrorCode::CapacityExceeded);
    }
    let mut bytes = PrivateBytes(Vec::with_capacity(crypto::MAX_CLEAR));
    bytes.0.extend_from_slice(ENVELOPE_MAGIC);
    bytes
        .0
        .extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    bytes.0.extend_from_slice(&metadata);
    bytes.0.extend_from_slice(&(input.len as u32).to_be_bytes());
    bytes.0.extend_from_slice(&input.bytes[..input.len]);
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    PartialWrite,
    #[cfg(test)]
    BeforePublish,
    #[cfg(test)]
    AfterPublish,
    #[cfg(test)]
    Cleanup,
}
fn validate_destination(path: &Path) -> Result<(), ErrorCode> {
    if !path.is_absolute()
        || path.as_os_str().len() > 1024
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(m) if m.file_type().is_symlink() => return Err(ErrorCode::InvalidRequest),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ErrorCode::PersistenceUnavailable),
        }
    }
    Ok(())
}
// Trusted local namespace only: these identity checks limit accidental cleanup,
// but are NOT race-free descriptor-relative protection from a same-user attacker.
struct Transaction {
    root: PathBuf,
    directory: File,
    staged: Option<File>,
    published: bool,
    cleaned: bool,
}
fn same_object(file: &File, path: &Path) -> bool {
    file.metadata()
        .ok()
        .zip(fs::symlink_metadata(path).ok())
        .is_some_and(|(a, b)| {
            !b.file_type().is_symlink() && a.dev() == b.dev() && a.ino() == b.ino()
        })
}
impl Transaction {
    fn stage(root: &Path, ciphertext: &[u8], fault: Fault) -> Result<Self, ErrorCode> {
        if ciphertext.is_empty() || ciphertext.len() > crypto::MAX_DOCUMENT {
            return Err(ErrorCode::CapacityExceeded);
        }
        validate_destination(root)?;
        // Never reuse a destination, even when it appears empty.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let directory = match File::open(root) {
            Ok(file) => file,
            Err(_) => return Err(ErrorCode::ReconciliationRequired),
        };
        let mut transaction = Self {
            root: root.into(),
            directory,
            staged: None,
            published: false,
            cleaned: false,
        };
        let result = (|| {
            if !same_object(&transaction.directory, root) {
                return Err(ErrorCode::ReconciliationRequired);
            }
            store::safe_directory(root)?;
            store::sync_directory(root.parent().ok_or(ErrorCode::InvalidRequest)?)?;
            let file = OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(root.join(STAGED))
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            transaction.staged = Some(file);
            let staged = transaction
                .staged
                .as_mut()
                .ok_or(ErrorCode::PersistenceUnavailable)?;
            #[cfg(test)]
            if matches!(fault, Fault::PartialWrite) {
                staged
                    .write_all(&ciphertext[..ciphertext.len() / 2])
                    .map_err(|_| ErrorCode::PersistenceUnavailable)?;
                return Err(ErrorCode::PersistenceUnavailable);
            }
            let _ = fault;
            staged
                .write_all(ciphertext)
                .and_then(|_| staged.sync_all())
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            transaction
                .directory
                .sync_all()
                .map_err(|_| ErrorCode::PersistenceUnavailable)
        })();
        if let Err(error) = result {
            transaction.cleanup()?;
            return Err(error);
        }
        Ok(transaction)
    }
    fn publish(&mut self, fault: Fault) -> Result<(), ErrorCode> {
        #[cfg(test)]
        if matches!(fault, Fault::BeforePublish | Fault::Cleanup) {
            if matches!(fault, Fault::Cleanup) {
                // Simulate unexpected namespace content: cleanup must never recurse.
                fs::write(self.root.join("unexpected"), b"nonsecret fixture")
                    .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            }
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let _ = fault;
        let staged = self
            .staged
            .as_ref()
            .ok_or(ErrorCode::PersistenceUnavailable)?;
        if !same_object(&self.directory, &self.root)
            || !same_object(staged, &self.root.join(STAGED))
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
        // Atomic no-replace publication of one already-synced ciphertext object.
        fs::hard_link(self.root.join(STAGED), self.root.join(COMMITTED))
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        self.published = true;
        #[cfg(test)]
        if matches!(fault, Fault::AfterPublish) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        fs::remove_file(self.root.join(STAGED)).map_err(|_| ErrorCode::ReconciliationRequired)?;
        self.directory
            .sync_all()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        self.cleaned = true;
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), ErrorCode> {
        if self.cleaned || self.published {
            return Ok(());
        }
        if !same_object(&self.directory, &self.root) {
            return Err(ErrorCode::ReconciliationRequired);
        }
        if let Some(staged) = self.staged.as_ref() {
            if !same_object(staged, &self.root.join(STAGED)) {
                return Err(ErrorCode::ReconciliationRequired);
            }
            fs::remove_file(self.root.join(STAGED))
                .map_err(|_| ErrorCode::ReconciliationRequired)?;
            self.staged = None;
        }
        // Nonrecursive removal: foreign or unexpected files are never deleted.
        fs::remove_dir(&self.root).map_err(|_| ErrorCode::ReconciliationRequired)?;
        self.cleaned = true;
        store::sync_directory(self.root.parent().ok_or(ErrorCode::InvalidRequest)?)
            .map_err(|_| ErrorCode::ReconciliationRequired)
    }
    fn abort(&mut self, error: ErrorCode) -> Result<(), ErrorCode> {
        self.cleanup()?;
        Err(error)
    }
}
impl Drop for Transaction {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn fixture_frame() -> PrivateBytes {
    let mut frame = PrivateBytes(Vec::with_capacity(12 + CANARY.len()));
    frame.0.extend_from_slice(INPUT_MAGIC);
    frame
        .0
        .extend_from_slice(&(CANARY.len() as u32).to_be_bytes());
    frame.0.extend_from_slice(CANARY);
    frame
}
fn verified_fixture(review: &ImportReview, identity: &Identity) -> Result<bool, ErrorCode> {
    store::safe_directory(&review.destination)?;
    let mut entries =
        fs::read_dir(&review.destination).map_err(|_| ErrorCode::PersistenceUnavailable)?;
    let first = entries
        .next()
        .ok_or(ErrorCode::ReconciliationRequired)?
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    if first.file_name() != COMMITTED || entries.next().is_some() {
        return Err(ErrorCode::ReconciliationRequired);
    }
    let ciphertext = store::read_file(&review.destination.join(COMMITTED), crypto::MAX_DOCUMENT)?;
    if ciphertext
        .windows(CANARY.len())
        .any(|window| window == CANARY)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let decrypted = identity.decrypt(&ciphertext)?;
    let input = Input::read(&mut Cursor::new(&fixture_frame().0), || Ok(()))?;
    Ok(decrypted.0 == envelope(review, &input)?.0)
}

/// Read only a hard-coded disposable canary, encrypt it with a fresh ephemeral
/// fixture identity and transactionally publish NEW ciphertext-only fixture state.
/// No identity is saved. This cannot initialize, unlock or restore a live vault.
/// The sole argument is a new absolute destination beneath trusted local storage.
pub fn run_synthetic_protected_entry_drill(
    destination: &Path,
) -> Result<ProtectedEntryReport, ErrorCode> {
    let clock = Arc::new(ManualClock::default());
    let ceremony = Ceremony::fixture(clock.clone())?;
    let identity = Identity::generate();
    let session = ImportSession::fixture(&ceremony, destination, &identity)?;
    session.approve(&ceremony.bindings.operator, &session.review)?;
    session.import(
        &mut Cursor::new(&fixture_frame().0),
        &session.review,
        &identity,
        Fault::None,
    )?;
    let exact_metadata_round_trip = verified_fixture(&session.review, &identity)?;
    let repeated_import = session
        .import(
            &mut Cursor::new(&fixture_frame().0),
            &session.review,
            &identity,
            Fault::None,
        )
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;
    let canceled_ceremony = Ceremony::fixture(clock)?;
    let canceled = ImportSession::fixture(&canceled_ceremony, destination, &identity)?;
    canceled.approve(&canceled_ceremony.bindings.operator, &canceled.review)?;
    canceled.cancel(&canceled_ceremony.bindings.operator)?;
    let cancellation = canceled
        .import(
            &mut Cursor::new(&fixture_frame().0),
            &canceled.review,
            &identity,
            Fault::None,
        )
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;
    let mut trailing = fixture_frame();
    trailing.0.push(0);
    let trailing_input = Input::read(&mut Cursor::new(&trailing.0), || Ok(()))
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;
    if !exact_metadata_round_trip
        || repeated_import != ErrorCode::BudgetExhausted
        || cancellation != ErrorCode::RequestCanceled
        || trailing_input != ErrorCode::InvalidRequest
        || crate::vault::require_live_deployment() != Err(ErrorCode::UnsupportedDeployment)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let report = ProtectedEntryReport {
        synthetic_only: true,
        maximum_reader_payload_bytes: MAX_INPUT,
        fixed_import_payload_bytes: CANARY.len(),
        encrypted_fixture_imported: true,
        exact_metadata_round_trip,
        repeated_import,
        cancellation,
        trailing_input,
        plaintext_in_persisted_fixture: false,
        plaintext_in_report: false,
        authenticated_human_verified: false,
        protected_display_verified: false,
        protected_custody_verified: false,
        operational_recovery_verified: false,
        ready_for_real_keys: false,
    };
    let serialized = serde_json::to_vec(&report).map_err(|_| ErrorCode::BrokerUnavailable)?;
    if serialized
        .windows(CANARY.len())
        .any(|window| window == CANARY)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(report)
}

#[cfg(test)]
#[path = "protected_entry_tests.rs"]
mod tests;
