//! Fixed-canary recipient running in a separate child process.
//!
//! The child uses the existing age capsule, signed receipt and durable recipient
//! journal. The same UID remains UNISOLATED: this is process separation, not host
//! attestation, protected custody, or an operational credential interface.
//!
//! ```compile_fail
//! use aegis::vault::process_recipient::ProcessRecipient;
//! ```
use super::{
    crypto::{self, PrivateBytes, Signed},
    custody::{self, BrokerRole},
    model::{DeliveryProfile, DeliveryProjection, RecipientBinding},
    protocol::SyntheticProtocol,
    store::{self, Ack, BrokerMaterial, Recipient, RecipientMaterial, RecipientOutcome, Store},
};
use crate::{ErrorCode, Lifecycle, ManualClock, RequestId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, ExitCode, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CHILD_FLAG: &str = "--aegis-synthetic-recipient-child-v1";
const MAX_FRAME: usize = crypto::MAX_DOCUMENT;
const MAX_EXCHANGES: usize = 128;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) enum RecipientEndpoint {
    Local(Arc<Recipient>),
    Process(Arc<ProcessRecipient>),
}
impl From<Arc<Recipient>> for RecipientEndpoint {
    fn from(value: Arc<Recipient>) -> Self {
        Self::Local(value)
    }
}
impl From<Arc<ProcessRecipient>> for RecipientEndpoint {
    fn from(value: Arc<ProcessRecipient>) -> Self {
        Self::Process(value)
    }
}
impl RecipientEndpoint {
    pub(super) fn check_store(&self, store: &Store) -> Result<(), ErrorCode> {
        match self {
            Self::Local(recipient) => store.check_recipient(recipient),
            Self::Process(recipient) => {
                store.check_process_receipts(&recipient.snapshot()?.received)
            }
        }
    }
    pub(super) fn generation(&self) -> Result<u64, ErrorCode> {
        match self {
            Self::Local(recipient) => recipient.generation(),
            Self::Process(recipient) => Ok(recipient.snapshot()?.generation),
        }
    }
    pub(super) fn deliver(
        &self,
        store: &Store,
        id: &RequestId,
        at: u64,
    ) -> Result<DeliveryProjection, ErrorCode> {
        match self {
            Self::Local(recipient) => store.deliver(id, recipient, at),
            Self::Process(recipient) => store.deliver_via(id, at, |c| recipient.accept(c)),
        }
    }
    // Preserve the existing in-process fault harness without a production fault API.
    #[cfg(test)]
    pub(super) fn fault(&self, fault: store::RecipientFault) {
        let Self::Local(recipient) = self else {
            panic!("local test fixture required")
        };
        recipient.fault(fault);
    }
    #[cfg(test)]
    pub(super) fn contains_canary(&self, version: u64) -> bool {
        matches!(self, Self::Local(recipient) if recipient.contains_canary(version))
    }
    #[cfg(test)]
    pub(super) fn pause(&self) -> (std::sync::mpsc::Receiver<()>, Arc<store::RecipientPause>) {
        let Self::Local(recipient) = self else {
            panic!("local test fixture required")
        };
        recipient.pause()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status { nonce: String },
    Deliver { nonce: String, capsule: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    schema: u16,
    kind: String,
    nonce: String,
    vault_id: String,
    recipient: RecipientBinding,
    recipient_key: String,
    writer_key_digest: String,
    generation: u64,
    receipts: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Acceptance {
    Acknowledged,
    Rejected,
    Unknown,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: u16,
    kind: String,
    nonce: String,
    vault_id: String,
    capsule_digest: String,
    outcome: Acceptance,
    ack: Option<String>,
}
pub(super) struct Snapshot {
    pub(super) generation: u64,
    pub(super) received: BTreeMap<RequestId, String>,
}

/// Owns the sole child and its inherited socket. No path listener, shell, executable
/// selector or caller-controlled environment exists. Every failure is sticky.
struct Session {
    child: Option<Child>,
    stream: UnixStream,
    failed: bool,
    exchanges: usize,
    timeout: Duration,
}
impl Session {
    fn spawn(mode: &str, custody: &Path, state: Option<&Path>) -> Result<Self, ErrorCode> {
        let (stream, child_stream) =
            UnixStream::pair().map_err(|_| ErrorCode::BrokerUnavailable)?;
        let input: OwnedFd = child_stream
            .try_clone()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .into();
        let output: OwnedFd = child_stream.into();
        let mut command =
            Command::new(std::env::current_exe().map_err(|_| ErrorCode::BrokerUnavailable)?);
        command.arg(CHILD_FLAG).arg(mode).arg(custody);
        if let Some(state) = state {
            command.arg(state);
        }
        let child = command
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        Ok(Self {
            child: Some(child),
            stream,
            failed: false,
            exchanges: 0,
            timeout: EXCHANGE_TIMEOUT,
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    fn exchange(&mut self, request: &Request) -> Result<Signed, ErrorCode> {
        if self.failed || self.exchanges >= MAX_EXCHANGES {
            self.stop();
            return Err(ErrorCode::ReconciliationRequired);
        }
        self.exchanges += 1;
        let result = (|| {
            let bytes =
                PrivateBytes(serde_json::to_vec(request).map_err(|_| ErrorCode::InvalidRequest)?);
            let deadline = Instant::now() + self.timeout;
            write_timed_frame(&mut self.stream, &bytes.0, deadline)?;
            Signed::parse(&read_timed_frame(&mut self.stream, deadline)?.0)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

fn remaining(deadline: Instant, now: Instant) -> Result<Duration, ErrorCode> {
    deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(ErrorCode::ReconciliationRequired)
}
fn write_timed(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), ErrorCode> {
    write_timed_clock(stream, bytes, deadline, Instant::now)
}
fn write_timed_clock(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
    now: impl Fn() -> Instant,
) -> Result<(), ErrorCode> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline, now())?))
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        match stream.write(bytes) {
            Ok(0) => return Err(ErrorCode::ReconciliationRequired),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ErrorCode::ReconciliationRequired),
        }
    }
    remaining(deadline, now()).map(|_| ())
}
fn read_timed(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    read_timed_clock(stream, bytes, deadline, Instant::now)
}
fn read_timed_clock(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    now: impl Fn() -> Instant,
) -> Result<(), ErrorCode> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline, now())?))
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ErrorCode::ReconciliationRequired),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ErrorCode::ReconciliationRequired),
        }
    }
    remaining(deadline, now()).map(|_| ())
}
fn frame_length(header: [u8; 4]) -> Result<usize, ErrorCode> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        Err(ErrorCode::CapacityExceeded)
    } else {
        Ok(length)
    }
}
fn read_timed_frame(stream: &mut UnixStream, deadline: Instant) -> Result<PrivateBytes, ErrorCode> {
    let mut header = [0; 4];
    read_timed(stream, &mut header, deadline)?;
    let mut bytes = PrivateBytes(vec![0; frame_length(header)?]);
    read_timed(stream, &mut bytes.0, deadline)?;
    Ok(bytes)
}
fn write_timed_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    frame_length((bytes.len() as u32).to_be_bytes())?;
    write_timed(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_timed(stream, bytes, deadline)
}
fn read_frame(reader: &mut impl Read) -> Result<PrivateBytes, ErrorCode> {
    let mut header = [0; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let mut bytes = PrivateBytes(vec![0; frame_length(header)?]);
    reader
        .read_exact(&mut bytes.0)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    Ok(bytes)
}
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<(), ErrorCode> {
    frame_length((bytes.len() as u32).to_be_bytes())?;
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(bytes))
        .and_then(|_| writer.flush())
        .map_err(|_| ErrorCode::BrokerUnavailable)
}

pub(super) struct ProcessRecipient {
    material: Arc<BrokerMaterial>,
    session: Mutex<Session>,
}
impl ProcessRecipient {
    pub(super) fn start(
        material: Arc<BrokerMaterial>,
        custody: &Path,
        state: &Path,
        create: bool,
    ) -> Result<Arc<Self>, ErrorCode> {
        let recipient = Arc::new(Self {
            material,
            session: Mutex::new(Session::spawn(
                if create { "create" } else { "open" },
                custody,
                Some(state),
            )?),
        });
        recipient.snapshot()?;
        Ok(recipient)
    }
    pub(super) fn snapshot(&self) -> Result<Snapshot, ErrorCode> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        let nonce = crypto::random_id()?;
        let result = session
            .exchange(&Request::Status {
                nonce: nonce.clone(),
            })
            .and_then(|signed| verify_status(&self.material, &nonce, &signed));
        if result.is_err() {
            session.stop();
        }
        result
    }
    fn accept(&self, capsule: Signed) -> RecipientOutcome {
        let Ok(mut session) = self.session.lock() else {
            return RecipientOutcome::Unknown;
        };
        let result = (|| {
            let nonce = crypto::random_id()?;
            let signed = session.exchange(&Request::Deliver {
                nonce: nonce.clone(),
                capsule: String::from_utf8(capsule.bytes().to_vec())
                    .map_err(|_| ErrorCode::InvalidRequest)?,
            })?;
            verify_reply(
                &self.material,
                &nonce,
                &crypto::hash(capsule.bytes()),
                &signed,
            )
        })();
        match result {
            Ok(outcome) => outcome,
            Err(_) => {
                session.stop();
                RecipientOutcome::Unknown
            }
        }
    }
}
fn verify_status(
    material: &BrokerMaterial,
    nonce: &str,
    signed: &Signed,
) -> Result<Snapshot, ErrorCode> {
    let status: Status = material.receipt.verify(signed)?;
    if status.schema != 1
        || status.kind != "aegis.synthetic.recipient.status.v1"
        || status.nonce != nonce
        || status.vault_id != material.vault_id
        || status.recipient != RecipientBinding::fixture()
        || status.recipient_key != material.recipient.to_string()
        || status.writer_key_digest != crypto::hash(material.writer.verifier().fixture_der())
        || status.generation > 2
        || status.receipts.len() != status.generation as usize
    {
        return Err(ErrorCode::ReconciliationRequired);
    }
    let mut received = BTreeMap::new();
    let mut generations = BTreeSet::new();
    for receipt in status.receipts {
        let ack: Ack = material
            .receipt
            .verify(&Signed::parse(receipt.as_bytes())?)?;
        if !matches!(ack.version, 1 | 2)
            || ack.generation > status.generation
            || crypto::decode(&ack.capsule_digest, 32)?.0.len() != 32
            || !generations.insert(ack.generation)
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
        store::validate_ack(
            &ack,
            &material.vault_id,
            &ack.delivery_id,
            &DeliveryProfile::fixture(ack.version),
            &ack.capsule_digest,
        )?;
        if received
            .insert(ack.delivery_id, ack.capsule_digest)
            .is_some()
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
    }
    Ok(Snapshot {
        generation: status.generation,
        received,
    })
}
fn verify_reply(
    material: &BrokerMaterial,
    nonce: &str,
    digest: &str,
    signed: &Signed,
) -> Result<RecipientOutcome, ErrorCode> {
    let reply: Reply = material.receipt.verify(signed)?;
    if reply.schema != 1
        || reply.kind != "aegis.synthetic.recipient.reply.v1"
        || reply.nonce != nonce
        || reply.vault_id != material.vault_id
        || reply.capsule_digest != digest
    {
        return Err(ErrorCode::ReconciliationRequired);
    }
    match (reply.outcome, reply.ack) {
        (Acceptance::Acknowledged, Some(ack)) => Ok(RecipientOutcome::Acknowledged(Signed::parse(
            ack.as_bytes(),
        )?)),
        (Acceptance::Rejected, None) => Ok(RecipientOutcome::Rejected),
        (Acceptance::Unknown, None) => Ok(RecipientOutcome::Unknown),
        _ => Err(ErrorCode::ReconciliationRequired),
    }
}

fn serve(material: Arc<RecipientMaterial>, recipient: Arc<Recipient>) -> Result<(), ErrorCode> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    for _ in 0..MAX_EXCHANGES {
        let bytes = read_frame(&mut input)?;
        let request: Request =
            serde_json::from_slice(&bytes.0).map_err(|_| ErrorCode::InvalidRequest)?;
        let response = respond(&material, &recipient, request)?;
        write_frame(&mut output, response.bytes())?;
    }
    Ok(())
}

fn respond(
    material: &RecipientMaterial,
    recipient: &Recipient,
    request: Request,
) -> Result<Signed, ErrorCode> {
    let nonce = match &request {
        Request::Status { nonce } | Request::Deliver { nonce, .. } => nonce,
    };
    if crypto::decode(nonce, 32)?.0.len() != 32 {
        return Err(ErrorCode::InvalidRequest);
    }
    match request {
        Request::Status { nonce } => {
            let (generation, receipts) = recipient.process_receipts()?;
            material.receipt.sign(&Status {
                schema: 1,
                kind: "aegis.synthetic.recipient.status.v1".into(),
                nonce,
                vault_id: material.vault_id.clone(),
                recipient: RecipientBinding::fixture(),
                recipient_key: material.recipient.recipient().to_string(),
                writer_key_digest: crypto::hash(material.writer.fixture_der()),
                generation,
                receipts,
            })
        }
        Request::Deliver { nonce, capsule } => {
            let capsule = Signed::parse(capsule.as_bytes())?;
            let capsule_digest = crypto::hash(capsule.bytes());
            let (outcome, ack) = match recipient.accept(capsule) {
                RecipientOutcome::Acknowledged(ack) => (
                    Acceptance::Acknowledged,
                    Some(
                        String::from_utf8(ack.bytes().to_vec())
                            .map_err(|_| ErrorCode::InvalidRequest)?,
                    ),
                ),
                RecipientOutcome::Rejected => (Acceptance::Rejected, None),
                RecipientOutcome::Unknown => (Acceptance::Unknown, None),
            };
            material.receipt.sign(&Reply {
                schema: 1,
                kind: "aegis.synthetic.recipient.reply.v1".into(),
                nonce,
                vault_id: material.vault_id.clone(),
                capsule_digest,
                outcome,
                ack,
            })
        }
    }
}

/// Call before the embedding executable parses its ordinary arguments. Handles only
/// the fixed internal dummy-custody worker; no command, secret or provider selector.
/// Parent I/O has absolute deadlines and kills/reaps this child on failure or drop.
pub fn synthetic_child_entry() -> Option<ExitCode> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_none_or(|arg| arg != CHILD_FLAG) {
        return None;
    }
    let result = (|| match args.as_slice() {
        [_, mode, custody] if mode == "bootstrap" => {
            custody::bootstrap_synthetic_custody(Path::new(custody))?;
            write_frame(&mut std::io::stdout().lock(), b"created")
        }
        [_, mode, custody, state] if mode == "create" || mode == "open" => {
            let material = custody::open_recipient_role(Path::new(custody))?;
            let recipient = if mode == "create" {
                Recipient::create(Path::new(state), material.clone())?
            } else {
                Recipient::open(Path::new(state), material.clone())?
            };
            serve(material, recipient)
        }
        _ => Err(ErrorCode::InvalidRequest),
    })();
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Closed observations from the fixed dummy process drill, never host assurance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessRecipientReport {
    pub synthetic_only: bool,
    pub separate_recipient_process: bool,
    pub bootstrap_in_child: bool,
    pub broker_loaded_recipient_private_keys: bool,
    pub completed_deliveries: usize,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revocation_survived_restart: bool,
    pub delivery_responses_contain_canary: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub independent_human_presence_verified: bool,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Create NEW dummy paths, deliver, restart the recipient and broker, rotate and
/// durably revoke. The executable must dispatch `synthetic_child_entry` first.
/// The parent opens broker and simulated actor roles, never recipient private files.
pub fn run_synthetic_process_drill(
    root: &Path,
    custody: &Path,
    state: &Path,
) -> Result<ProcessRecipientReport, ErrorCode> {
    bootstrap_in_child(custody)?;
    let mut duplicate_reused = true;
    let mut unauthenticated = true;
    let mut transcript = String::new();
    for version in 1..=2 {
        let broker = BrokerRole::open(&custody.join("broker"))?;
        let recipient = ProcessRecipient::start(
            broker.material.clone(),
            &custody.join("recipient"),
            state,
            version == 1,
        )?;
        let vault_id = broker.material.vault_id.clone();
        let store = if version == 1 {
            Store::create(root, broker.material)?
        } else {
            Store::open(root, broker.material)?
        };
        let protocol = SyntheticProtocol::assemble(
            broker.enrollment,
            store,
            recipient,
            version,
            Arc::new(ManualClock::default()),
        )?;
        let (run, duplicate, denied) =
            custody::process_fixture_round(&protocol, custody, &vault_id, version)?;
        if run.state != Lifecycle::Succeeded {
            return Err(ErrorCode::BrokerUnavailable);
        }
        transcript
            .push_str(&serde_json::to_string(&run).map_err(|_| ErrorCode::BrokerUnavailable)?);
        duplicate_reused &= duplicate;
        unauthenticated &= denied;
        if version == 2 {
            custody::process_fixture_revoke(&protocol, custody, &vault_id)?;
        }
    }
    let broker = BrokerRole::open(&custody.join("broker"))?;
    let recipient = ProcessRecipient::start(
        broker.material.clone(),
        &custody.join("recipient"),
        state,
        false,
    )?;
    let store = Store::open(root, broker.material)?;
    let snapshot = recipient.snapshot()?;
    store.check_process_receipts(&snapshot.received)?;
    let (consumed, incomplete, unknown, remaining, revoked) = store.history_counts()?;
    let revoked_after_restart = revoked
        && matches!(
            SyntheticProtocol::assemble(
                broker.enrollment,
                store,
                recipient,
                2,
                Arc::new(ManualClock::default())
            ),
            Err(ErrorCode::GrantRevoked)
        );
    let contains_canary =
        transcript.contains(store::CANARY_ONE) || transcript.contains(store::CANARY_TWO);
    if !(duplicate_reused
        && unauthenticated
        && revoked_after_restart
        && !contains_canary
        && consumed == 2
        && incomplete == 0
        && unknown == 0
        && remaining == 2
        && snapshot.generation == 2)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(ProcessRecipientReport {
        synthetic_only: true,
        separate_recipient_process: true,
        bootstrap_in_child: true,
        broker_loaded_recipient_private_keys: false,
        completed_deliveries: 2,
        duplicate_reused,
        cold_start_required_authentication: unauthenticated,
        consumed_uses: consumed,
        remaining_uses: remaining,
        recipient_generation: snapshot.generation,
        revocation_survived_restart: revoked_after_restart,
        delivery_responses_contain_canary: contains_canary,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

pub(super) fn bootstrap_in_child(custody: &Path) -> Result<(), ErrorCode> {
    let mut bootstrap = Session::spawn("bootstrap", custody, None)?;
    if read_timed_frame(&mut bootstrap.stream, Instant::now() + BOOTSTRAP_TIMEOUT)?.0 != b"created"
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, thread};

    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aegis-process-test-{}",
                crypto::random_id().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn custody(&self) -> PathBuf {
            self.0.join("custody")
        }
        fn vault(&self) -> PathBuf {
            self.0.join("vault")
        }
        fn state(&self) -> PathBuf {
            self.0.join("recipient")
        }
    }
    impl Drop for Paths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn session(stream: UnixStream) -> Session {
        Session {
            child: None,
            stream,
            failed: false,
            exchanges: 0,
            timeout: Duration::from_millis(500),
        }
    }
    fn status(material: &RecipientMaterial, recipient: &Recipient, nonce: &str) -> Signed {
        respond(
            material,
            recipient,
            Request::Status {
                nonce: nonce.into(),
            },
        )
        .unwrap()
    }
    #[test]
    fn status_authenticates_enrollment_nonce_generation_and_receipts() {
        let paths = Paths::new();
        custody::bootstrap_synthetic_custody(&paths.custody()).unwrap();
        let broker = BrokerRole::open(&paths.custody().join("broker")).unwrap();
        let material = custody::open_recipient_role(&paths.custody().join("recipient")).unwrap();
        let recipient = Recipient::create(&paths.state(), material.clone()).unwrap();
        let nonce = crypto::random_id().unwrap();
        let valid = status(&material, &recipient, &nonce);
        assert_eq!(
            verify_status(&broker.material, &nonce, &valid)
                .unwrap()
                .generation,
            0
        );
        assert!(verify_status(&broker.material, &crypto::random_id().unwrap(), &valid).is_err());
        let changes: Vec<fn(&mut Status)> = vec![
            |s| s.schema += 1,
            |s| s.kind.push('x'),
            |s| s.vault_id = crypto::random_id().unwrap(),
            |s| s.recipient.slot = "stdout".into(),
            |s| s.recipient_key.push('x'),
            |s| s.writer_key_digest = crypto::random_id().unwrap(),
            |s| s.generation = 1,
            |s| s.receipts.push("malformed".into()),
        ];
        for change in changes {
            let mut altered: Status = broker.material.receipt.verify(&valid).unwrap();
            change(&mut altered);
            assert!(verify_status(
                &broker.material,
                &nonce,
                &material.receipt.sign(&altered).unwrap()
            )
            .is_err());
        }
        let wrong = crypto::SigningKey::generate().unwrap();
        let value: Status = broker.material.receipt.verify(&valid).unwrap();
        assert!(verify_status(&broker.material, &nonce, &wrong.sign(&value).unwrap()).is_err());
    }

    #[test]
    fn malformed_truncated_oversized_or_excess_transport_is_sticky() {
        for response in [
            vec![],
            vec![0, 0],
            vec![0, 0, 0, 5, b'a'],
            vec![0, 0, 0, 0],
            vec![0, 1, 0, 1],
        ] {
            let (parent, mut peer) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || {
                read_frame(&mut peer).unwrap();
                peer.write_all(&response).unwrap();
            });
            let mut session = session(parent);
            let request = Request::Status {
                nonce: crypto::random_id().unwrap(),
            };
            assert!(session.exchange(&request).is_err());
            assert!(session.failed);
            assert!(session.exchange(&request).is_err());
            assert_eq!(session.exchanges, 1);
            worker.join().unwrap();
        }
        let (parent, _peer) = UnixStream::pair().unwrap();
        let mut session = session(parent);
        session.exchanges = MAX_EXCHANGES;
        assert!(session
            .exchange(&Request::Status {
                nonce: crypto::random_id().unwrap()
            })
            .is_err());
        assert!(session.failed);
    }

    #[test]
    fn absolute_read_deadline_is_not_extended_by_trickling_bytes() {
        let (mut parent, mut peer) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            peer.write_all(&32u32.to_be_bytes()).unwrap();
            for _ in 0..32 {
                thread::sleep(Duration::from_millis(10));
                if peer.write_all(b"a").is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        assert!(read_timed_frame(&mut parent, start + Duration::from_millis(70)).is_err());
        drop(parent);
        worker.join().unwrap();
    }

    #[test]
    fn absolute_write_deadline_bounds_a_nonreading_peer() {
        let (mut parent, _peer) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let bytes = vec![0; 1024 * 1024];
        assert!(write_timed(&mut parent, &bytes, start + Duration::from_millis(70)).is_err());
    }

    #[test]
    fn final_successful_io_is_rejected_if_the_absolute_deadline_passed() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        let (mut parent, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"r").unwrap();
        let first = std::cell::Cell::new(true);
        let now = || {
            if first.replace(false) {
                start
            } else {
                deadline
            }
        };
        let mut byte = [0];
        assert!(read_timed_clock(&mut parent, &mut byte, deadline, now).is_err());
        assert_eq!(byte, *b"r");
        first.set(true);
        assert!(write_timed_clock(&mut parent, b"w", deadline, now).is_err());
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"w");
    }

    #[test]
    fn cleanup_child_fixture() {
        if std::env::var_os("AEGIS_RECIPIENT_CLEANUP_FIXTURE").is_some() {
            let _ = std::io::stdin().read_exact(&mut [0; 1]);
        }
    }

    #[test]
    fn dropping_transport_kills_and_reaps_its_child() {
        let (stream, child_stream) = UnixStream::pair().unwrap();
        let input: OwnedFd = child_stream.into();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vault::process_recipient::tests::cleanup_child_fixture",
                "--nocapture",
            ])
            .env_clear()
            .env("AEGIS_RECIPIENT_CLEANUP_FIXTURE", "1")
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        #[cfg(target_os = "linux")]
        let pid = child.id();
        let mut session = session(stream);
        session.child = Some(child);
        drop(session);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Failure {
        KnownRejection,
        Missing,
        Malformed,
        Truncated,
        Oversized,
        Timeout,
        WrongNonce,
        WrongDigest,
        BadReceipt,
    }

    #[test]
    fn process_failures_preserve_consumed_outcomes_without_retry_after_restart() {
        for failure in [
            Failure::KnownRejection,
            Failure::Missing,
            Failure::Malformed,
            Failure::Truncated,
            Failure::Oversized,
            Failure::Timeout,
            Failure::WrongNonce,
            Failure::WrongDigest,
            Failure::BadReceipt,
        ] {
            let paths = Paths::new();
            custody::bootstrap_synthetic_custody(&paths.custody()).unwrap();
            let broker = BrokerRole::open(&paths.custody().join("broker")).unwrap();
            let material =
                custody::open_recipient_role(&paths.custody().join("recipient")).unwrap();
            let local = Recipient::create(&paths.state(), material.clone()).unwrap();
            if failure == Failure::KnownRejection {
                local.fault(store::RecipientFault::Reject);
            }
            let store = Store::create(&paths.vault(), broker.material.clone()).unwrap();
            let (parent, mut peer) = UnixStream::pair().unwrap();
            let server_recipient = local.clone();
            let (release, wait) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                while let Ok(bytes) = read_frame(&mut peer) {
                    let request: Request = serde_json::from_slice(&bytes.0).unwrap();
                    let delivery = matches!(request, Request::Deliver { .. });
                    let response = respond(&material, &server_recipient, request).unwrap();
                    if !delivery {
                        write_frame(&mut peer, response.bytes()).unwrap();
                        continue;
                    }
                    assert_eq!(
                        server_recipient.generation(),
                        Ok(u64::from(failure != Failure::KnownRejection))
                    );
                    match failure {
                        Failure::KnownRejection => {
                            write_frame(&mut peer, response.bytes()).unwrap()
                        }
                        Failure::Missing => {}
                        Failure::Malformed => {
                            write_frame(&mut peer, b"not-a-signed-receipt").unwrap()
                        }
                        Failure::Truncated => peer.write_all(&[0, 0, 0, 20, b'a']).unwrap(),
                        Failure::Oversized => peer
                            .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                            .unwrap(),
                        Failure::Timeout => {
                            let _ = wait.recv();
                        }
                        Failure::WrongNonce | Failure::WrongDigest | Failure::BadReceipt => {
                            let mut reply: Reply =
                                material.receipt.verifier().verify(&response).unwrap();
                            match failure {
                                Failure::WrongNonce => reply.nonce = crypto::random_id().unwrap(),
                                Failure::WrongDigest => {
                                    reply.capsule_digest = crypto::random_id().unwrap()
                                }
                                Failure::BadReceipt => {
                                    let mut ack: Ack = material
                                        .receipt
                                        .verifier()
                                        .verify(
                                            &Signed::parse(reply.ack.as_ref().unwrap().as_bytes())
                                                .unwrap(),
                                        )
                                        .unwrap();
                                    ack.recipient.slot = "other-slot".into();
                                    reply.ack = Some(
                                        String::from_utf8(
                                            material.receipt.sign(&ack).unwrap().bytes().to_vec(),
                                        )
                                        .unwrap(),
                                    );
                                }
                                _ => unreachable!(),
                            }
                            write_frame(&mut peer, material.receipt.sign(&reply).unwrap().bytes())
                                .unwrap();
                        }
                    }
                    break;
                }
            });
            let remote = Arc::new(ProcessRecipient {
                material: broker.material.clone(),
                session: Mutex::new(session(parent)),
            });
            let protocol = SyntheticProtocol::assemble(
                broker.enrollment,
                store.clone(),
                remote,
                1,
                Arc::new(ManualClock::default()),
            )
            .unwrap();
            let (run, reused, _) = custody::process_fixture_round(
                &protocol,
                &paths.custody(),
                &broker.material.vault_id,
                1,
            )
            .unwrap();
            let unknown = failure != Failure::KnownRejection;
            let expected_ready = if unknown {
                Err(ErrorCode::ReconciliationRequired)
            } else {
                Ok(())
            };
            assert_eq!(
                run.state,
                if unknown {
                    Lifecycle::OutcomeUnknown
                } else {
                    Lifecycle::Failed
                }
            );
            assert!(reused);
            assert_eq!(
                store.history_counts().unwrap(),
                (1, 0, usize::from(unknown), 3, false)
            );
            assert_eq!(local.generation(), Ok(u64::from(unknown)));
            assert_eq!(store.ready(), expected_ready);
            drop(protocol);
            drop(store);
            let _ = release.send(());
            worker.join().unwrap();
            drop(local);
            let recovered = Store::open(&paths.vault(), broker.material).unwrap();
            assert_eq!(recovered.ready(), expected_ready);
            assert_eq!(
                recovered.history_counts().unwrap(),
                (1, 0, usize::from(unknown), 3, false)
            );
        }
    }

    #[test]
    fn startup_rejects_missing_or_unrelated_durable_receipts() {
        let paths = Paths::new();
        custody::bootstrap_synthetic_custody(&paths.custody()).unwrap();
        let broker = BrokerRole::open(&paths.custody().join("broker")).unwrap();
        let material = custody::open_recipient_role(&paths.custody().join("recipient")).unwrap();
        let recipient = Recipient::create(&paths.state(), material.clone()).unwrap();
        let store = Store::create(&paths.vault(), broker.material.clone()).unwrap();
        let protocol = SyntheticProtocol::assemble(
            broker.enrollment,
            store.clone(),
            recipient.clone(),
            1,
            Arc::new(ManualClock::default()),
        )
        .unwrap();
        custody::process_fixture_round(&protocol, &paths.custody(), &broker.material.vault_id, 1)
            .unwrap();
        let nonce = crypto::random_id().unwrap();
        let response = status(&material, &recipient, &nonce);
        let snapshot = verify_status(&broker.material, &nonce, &response).unwrap();
        store.check_process_receipts(&snapshot.received).unwrap();
        assert_eq!(
            store.check_process_receipts(&BTreeMap::new()),
            Err(ErrorCode::ReconciliationRequired)
        );
        let mut altered = snapshot.received;
        altered.insert(
            RequestId::new("unrelated").unwrap(),
            crypto::random_id().unwrap(),
        );
        assert_eq!(
            store.check_process_receipts(&altered),
            Err(ErrorCode::ReconciliationRequired)
        );
        let mut s: Status = material.receipt.verifier().verify(&response).unwrap();
        s.generation = 2;
        s.receipts.push(s.receipts[0].clone());
        assert!(verify_status(
            &broker.material,
            &nonce,
            &material.receipt.sign(&s).unwrap()
        )
        .is_err());
    }
}
