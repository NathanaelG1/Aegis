//! A fixed dummy broker child, external simulated clients and recipient child.
//!
//! The supervisor owns both child handles. Only the broker opens the Store and
//! protocol; only the external clients open actor signing and TLS client keys.
//! Disposable bootstrap temporarily holds all keys. All processes and persisted
//! fixture files remain in one trusted UID. There is no human-presence proof,
//! protected custody, listener, arbitrary input or operational deployment route.
//!
//! ```compile_fail
//! use aegis::vault::process_service::Supervisor;
//! ```
use super::{
    crypto::PrivateBytes,
    custody::{self, ActorRole, BrokerRole},
    entry::protected_entry,
    process_recipient::{self, ProcessRecipient},
    protocol::{self, SyntheticProtocol},
    store::{self, ReceiptContract, Store},
    tls::socket::{self, ClientFactory, ServerMaterial, SocketClient},
};
use crate::{
    ErrorCode, Lifecycle, ManualClock, OperationIntent, OperationPrepareInput, OperationRunView,
    ProfileId, RequestId,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::{Child, Command, ExitCode, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const CHILD_FLAG: &str = "--aegis-synthetic-process-service-child-v1";
const PROCESS_TIME: Duration = Duration::from_secs(35);
const MAX_OBSERVATION: usize = 4096;

/// Closed observations from the fixed imported-canary service exercise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessServiceReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub authenticated_role_channels: usize,
    pub tls13_mutual_authentication_verified: bool,
    pub separate_broker_process: bool,
    pub separate_recipient_process: bool,
    pub bootstrap_in_child: bool,
    pub client_signers_outside_broker: bool,
    pub broker_loaded_actor_private_keys: bool,
    pub broker_loaded_tls_client_private_keys: bool,
    pub broker_loaded_recipient_private_keys: bool,
    pub broker_and_recipient_reaped: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub completed_deliveries: usize,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub revocation_survived_restart: bool,
    pub agent_transcript_contains_canary: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub independent_human_presence_verified: bool,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// A fresh inspection child reads evidence without restoring sessions or grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessServiceRecoveryReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub separate_broker_process: bool,
    pub broker_and_recipient_reaped: bool,
    pub consumed_uses: usize,
    pub incomplete_deliveries: usize,
    pub unknown_deliveries: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    vault_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub(super) consumed: usize,
    pub(super) incomplete: usize,
    pub(super) unknown: usize,
    pub(super) remaining: u32,
    pub(super) generation: u64,
    pub(super) revoked: bool,
    pub(super) revoked_admission_denied: bool,
    pub(super) installed_version: Option<u64>,
    pub(super) incomplete_installations: Option<usize>,
}

// Every spawned process immediately enters a guard. No fallible setup can lose
// a Child between spawn and ownership. Both runtime processes are direct children
// so abrupt broker termination cannot leave the supervisor unable to reap its
// recipient. This is not a guarantee if the supervisor itself is killed.
#[derive(Default)]
struct Supervisor {
    broker: Option<Child>,
    recipient: Option<Child>,
}
impl Supervisor {
    fn finish(&mut self, deadline: Instant) -> Result<(), ErrorCode> {
        let broker = self.broker.as_mut().ok_or(ErrorCode::BrokerUnavailable)?;
        loop {
            if Instant::now() >= deadline {
                return Err(ErrorCode::BrokerUnavailable);
            }
            match broker
                .try_wait()
                .map_err(|_| ErrorCode::BrokerUnavailable)?
            {
                Some(status) => {
                    self.broker = None;
                    if !status.success() {
                        return Err(ErrorCode::BrokerUnavailable);
                    }
                    break;
                }
                None => thread::sleep(Duration::from_millis(2)),
            }
        }
        Self::terminate(&mut self.recipient)?;
        Ok(())
    }
    fn terminate(child: &mut Option<Child>) -> Result<(), ErrorCode> {
        if let Some(mut child) = child.take() {
            let already_exited = child.try_wait().ok().flatten().is_some();
            if !already_exited {
                let _ = child.kill();
            }
            child.wait().map_err(|_| ErrorCode::BrokerUnavailable)?;
        }
        Ok(())
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = Self::terminate(&mut self.broker);
        let _ = Self::terminate(&mut self.recipient);
    }
}

fn child_command(mode: &str, root: &Path) -> Result<Command, ErrorCode> {
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| ErrorCode::BrokerUnavailable)?);
    command.env_clear();
    #[cfg(not(test))]
    command.arg(CHILD_FLAG).arg(mode).arg(root);
    // A fixed private libtest entry is the only test alternative. Production
    // builds have neither these environment selectors nor fault modes.
    #[cfg(test)]
    command
        .args([
            "--exact",
            "vault::process_service::tests::child_fixture",
            "--nocapture",
        ])
        .env("AEGIS_PROCESS_SERVICE_TEST_MODE", mode)
        .env("AEGIS_PROCESS_SERVICE_TEST_ROOT", root);
    Ok(command)
}
fn stdio(stream: UnixStream) -> Stdio {
    let fd: OwnedFd = stream.into();
    Stdio::from(fd)
}
fn inherited(fd: impl AsFd) -> Result<UnixStream, ErrorCode> {
    Ok(UnixStream::from(
        fd.as_fd()
            .try_clone_to_owned()
            .map_err(|_| ErrorCode::BrokerUnavailable)?,
    ))
}
fn pair() -> Result<(UnixStream, UnixStream), ErrorCode> {
    UnixStream::pair().map_err(|_| ErrorCode::BrokerUnavailable)
}
fn remaining(deadline: Instant) -> Result<Duration, ErrorCode> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ErrorCode::BrokerUnavailable)
}
fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ErrorCode::BrokerUnavailable),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ErrorCode::BrokerUnavailable),
        }
    }
    remaining(deadline).map(|_| ())
}
fn read_observation<T: DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T, ErrorCode> {
    let mut header = [0; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_OBSERVATION {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let mut bytes = PrivateBytes(vec![0; length]);
    read_exact(stream, &mut bytes.0, deadline)?;
    serde_json::from_slice(&bytes.0).map_err(|_| ErrorCode::BrokerUnavailable)
}
#[cfg(test)]
fn read_test_banner(stream: &mut UnixStream) -> Result<(), ErrorCode> {
    let expected = b"\nrunning 1 test\n";
    let mut bytes = [0; 16];
    read_exact(stream, &mut bytes, Instant::now() + PROCESS_TIME)?;
    if bytes == *expected {
        Ok(())
    } else {
        Err(ErrorCode::BrokerUnavailable)
    }
}
fn write_observation(value: &impl Serialize) -> Result<(), ErrorCode> {
    let bytes = PrivateBytes(serde_json::to_vec(value).map_err(|_| ErrorCode::BrokerUnavailable)?);
    if bytes.0.is_empty() || bytes.0.len() > MAX_OBSERVATION {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let mut stream = inherited(std::io::stdout())?;
    let deadline = Instant::now() + PROCESS_TIME;
    for buffer in [&(bytes.0.len() as u32).to_be_bytes()[..], &bytes.0] {
        let mut pending = buffer;
        while !pending.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| ErrorCode::BrokerUnavailable)?;
            match stream.write(pending) {
                Ok(0) => return Err(ErrorCode::BrokerUnavailable),
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(ErrorCode::BrokerUnavailable),
            }
        }
    }
    remaining(deadline).map(|_| ())
}
fn bootstrap(root: &Path) -> Result<Bootstrap, ErrorCode> {
    let deadline = Instant::now() + PROCESS_TIME;
    let (mut stream, child_stream) = pair()?;
    let mut supervisor = Supervisor::default();
    supervisor.broker = Some(
        child_command("bootstrap", root)?
            .stdin(Stdio::null())
            .stdout(stdio(child_stream))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ErrorCode::BrokerUnavailable)?,
    );
    #[cfg(test)]
    read_test_banner(&mut stream)?;
    let report = read_observation(&mut stream, deadline)?;
    supervisor.finish(deadline)?;
    Ok(report)
}
fn spawn_recipient_mode(
    root: &Path,
    mode: &str,
    supervisor: &mut Supervisor,
) -> Result<UnixStream, ErrorCode> {
    let (stream, child_stream) = pair()?;
    let output = child_stream
        .try_clone()
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    supervisor.recipient = Some(
        child_command(mode, root)?
            .stdin(stdio(child_stream))
            .stdout(stdio(output))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ErrorCode::BrokerUnavailable)?,
    );
    #[cfg(test)]
    {
        let mut stream = stream;
        read_test_banner(&mut stream)?;
        Ok(stream)
    }
    #[cfg(not(test))]
    Ok(stream)
}

struct ClientChannels {
    contract: ReceiptContract,
    version: u64,
    agent: SocketClient,
    admin: SocketClient,
    agent_actor: ActorRole,
    admin_actor: ActorRole,
    transcript_contains_canary: bool,
}
impl ClientChannels {
    fn connect(&mut self) -> Result<(bool, bool), ErrorCode> {
        let agent_denied = is_error(
            &self.agent("discover_operations", json!({}))?,
            ErrorCode::AuthenticationRequired,
        );
        let admin_denied = is_error(
            &exchange(&mut self.admin, "revoke_challenge", json!({}))?,
            ErrorCode::AuthenticationRequired,
        );
        let challenge = value(self.agent("connect_challenge", json!({}))?, "challenge")?;
        let proof = self.agent_actor.proof(&challenge)?;
        if !is_error(
            &exchange(&mut self.admin, "connect", &proof)?,
            ErrorCode::AuthenticationRequired,
        ) || !is_kind(&self.agent("connect", proof)?, "connected")
        {
            return Err(ErrorCode::BrokerUnavailable);
        }
        let challenge = value(
            exchange(&mut self.admin, "connect_challenge", json!({}))?,
            "challenge",
        )?;
        if !is_kind(
            &exchange(
                &mut self.admin,
                "connect",
                self.admin_actor.proof(&challenge)?,
            )?,
            "connected",
        ) || !is_error(
            &self.agent("revoke_challenge", json!({}))?,
            ErrorCode::InvalidRequest,
        ) {
            return Err(ErrorCode::BrokerUnavailable);
        }
        Ok((agent_denied, admin_denied))
    }
    fn agent(&mut self, method: &str, params: impl Serialize) -> Result<Value, ErrorCode> {
        let response = exchange(&mut self.agent, method, params)?;
        let bytes = serde_json::to_vec(&response).map_err(|_| ErrorCode::BrokerUnavailable)?;
        self.transcript_contains_canary |= [store::CANARY_ONE, store::CANARY_TWO]
            .iter()
            .any(|s| bytes.windows(s.len()).any(|w| w == s.as_bytes()));
        Ok(response)
    }
    fn approve(&mut self) -> Result<Value, ErrorCode> {
        let version = self.version;
        let request_id = RequestId::new(if version == 1 {
            "process-service-import-one"
        } else {
            "process-service-import-two"
        })?;
        let prepared: OperationRunView = value(
            self.agent(
                "prepare_operation",
                OperationPrepareInput {
                    request_id: request_id.clone(),
                    profile_id: ProfileId::new("vault-delivery")?,
                    operation: OperationIntent::Delivery(super::DeliveryParameters::fixture(
                        version,
                    )),
                },
            )?,
            "run",
        )?;
        let handle = json!({"prepared_request_id": prepared.prepared_request_id});
        let awaiting: OperationRunView = value(self.agent("request_approval", &handle)?, "run")?;
        if awaiting.state != Lifecycle::AwaitingApproval {
            return Err(ErrorCode::BrokerUnavailable);
        }
        let expected: protocol::ReviewPlan = value(
            exchange(&mut self.admin, "inspect_review", &handle)?,
            "review",
        )?;
        if expected.profile != self.contract.profile(version)
            || expected.operation != super::DeliveryParameters::fixture(version)
            || expected.request_id != request_id
            || expected.prepared != prepared.prepared_request_id
        {
            return Err(ErrorCode::PolicyChanged);
        }
        let challenge = value(
            exchange(&mut self.admin, "approval_challenge", &expected)?,
            "challenge",
        )?;
        let proof = self.admin_actor.reviewed_proof(&challenge, &expected)?;
        let approved: OperationRunView = value(
            exchange(
                &mut self.admin,
                "approve",
                json!({"expected":expected,"proof":proof}),
            )?,
            "run",
        )?;
        if approved.state != Lifecycle::Approved {
            return Err(ErrorCode::BrokerUnavailable);
        }
        let challenge = value(self.agent("invocation_challenge", &handle)?, "challenge")?;
        Ok(
            json!({"prepared_request_id": prepared.prepared_request_id, "proof": self.agent_actor.proof(&challenge)?}),
        )
    }
    fn revoke(&mut self) -> Result<(), ErrorCode> {
        let challenge = value(
            exchange(&mut self.admin, "revoke_challenge", json!({}))?,
            "challenge",
        )?;
        if is_kind(
            &exchange(
                &mut self.admin,
                "revoke",
                self.admin_actor.proof(&challenge)?,
            )?,
            "revoked",
        ) {
            Ok(())
        } else {
            Err(ErrorCode::BrokerUnavailable)
        }
    }
    fn close(&mut self) -> Result<(), ErrorCode> {
        self.agent.close()?;
        self.admin.close()
    }
}
fn exchange(
    connection: &mut SocketClient,
    method: &str,
    params: impl Serialize,
) -> Result<Value, ErrorCode> {
    let bytes = PrivateBytes(serde_json::to_vec(&json!({"protocol":protocol::PROTOCOL,"version":protocol::VERSION,"action":{"method":method,"params":params}})).map_err(|_| ErrorCode::InvalidRequest)?);
    let response = connection.exchange(&bytes.0)?;
    serde_json::from_slice(&response.0).map_err(|_| ErrorCode::BrokerUnavailable)
}
fn value<T: DeserializeOwned>(response: Value, kind: &str) -> Result<T, ErrorCode> {
    if is_kind(&response, kind) {
        serde_json::from_value(response["result"]["value"].clone())
            .map_err(|_| ErrorCode::BrokerUnavailable)
    } else {
        Err(ErrorCode::BrokerUnavailable)
    }
}
fn is_kind(response: &Value, kind: &str) -> bool {
    response["error"].is_null() && response["result"]["kind"] == kind
}
fn is_error(response: &Value, error: ErrorCode) -> bool {
    response["result"].is_null()
        && matches!(serde_json::from_value::<ErrorCode>(response["error"].clone()), Ok(found) if found == error)
}

fn recipient_mode(mode: &str, create: bool) -> &'static str {
    #[cfg(feature = "application-slot")]
    if mode.starts_with("slot-") {
        #[cfg(test)]
        match mode {
            "slot-create-exit-intent" => return "slot-recipient-exit-intent",
            "slot-create-exit-stage" => return "slot-recipient-exit-stage",
            "slot-create-exit-rename" => return "slot-recipient-exit-rename",
            "slot-create-exit-directory" => return "slot-recipient-exit-directory",
            "slot-create-exit-receipt" => return "slot-recipient-exit-receipt",
            "slot-rotation-two-exit-intent" => return "slot-rotation-recipient-exit-intent",
            "slot-rotation-two-exit-stage" => return "slot-rotation-recipient-exit-stage",
            "slot-rotation-two-exit-rename" => return "slot-rotation-recipient-exit-rename",
            "slot-rotation-two-exit-directory" => return "slot-rotation-recipient-exit-directory",
            "slot-rotation-two-exit-receipt" => return "slot-rotation-recipient-exit-receipt",
            _ => {}
        }
        return if create {
            "slot-recipient-create"
        } else {
            "slot-recipient-open"
        };
    }
    #[cfg(test)]
    if mode == "create-lost-recipient-reply" {
        return "recipient-create-drop-reply";
    }
    let _ = mode;
    if create {
        "recipient-create"
    } else {
        "recipient-open"
    }
}
fn service_mode(contract: ReceiptContract, create: bool) -> &'static str {
    match contract {
        ReceiptContract::Acceptance => {
            if create {
                "create"
            } else {
                "open"
            }
        }
        #[cfg(feature = "application-slot")]
        ReceiptContract::Installation => {
            if create {
                "slot-create"
            } else {
                "slot-open"
            }
        }
    }
}
#[cfg(test)]
fn start_phase(
    root: &Path,
    vault_id: &str,
    create: bool,
) -> Result<(Supervisor, ClientChannels, Instant), ErrorCode> {
    start_phase_mode(
        root,
        vault_id,
        if create { "create" } else { "open" },
        create,
    )
}
fn start_phase_mode(
    root: &Path,
    vault_id: &str,
    mode: &str,
    create: bool,
) -> Result<(Supervisor, ClientChannels, Instant), ErrorCode> {
    let deadline = Instant::now() + PROCESS_TIME;
    // These loaders read only their own client keys and public enrollment. They
    // cannot initialize or open a Store or protocol in the supervisor process.
    let agent_factory = ClientFactory::agent(&root.join("tls/agent"))?;
    let admin_factory = ClientFactory::admin(&root.join("tls/admin"))?;
    let agent_actor = ActorRole::agent(&root.join("custody"), vault_id)?;
    let admin_actor = ActorRole::admin(&root.join("custody"), vault_id)?;
    let mut supervisor = Supervisor::default();
    let recipient_mode = recipient_mode(mode, create);
    let recipient = spawn_recipient_mode(root, recipient_mode, &mut supervisor)?;
    let (agent, broker_agent) = pair()?;
    let (admin, broker_admin) = pair()?;
    supervisor.broker = Some(
        child_command(mode, root)?
            .stdin(stdio(broker_agent))
            .stdout(stdio(broker_admin))
            .stderr(stdio(recipient))
            .spawn()
            .map_err(|_| ErrorCode::BrokerUnavailable)?,
    );
    #[cfg(test)]
    let admin = {
        let mut stream = admin;
        read_test_banner(&mut stream)?;
        stream
    };
    let channels = ClientChannels {
        version: if mode.starts_with("slot-rotation-two") || mode == "slot-rotation-open" {
            2
        } else {
            1
        },
        contract: {
            #[cfg(feature = "application-slot")]
            {
                if mode.starts_with("slot-") {
                    ReceiptContract::Installation
                } else {
                    ReceiptContract::Acceptance
                }
            }
            #[cfg(not(feature = "application-slot"))]
            {
                ReceiptContract::Acceptance
            }
        },
        agent: agent_factory.connect(agent)?,
        admin: admin_factory.connect(admin)?,
        agent_actor,
        admin_actor,
        transcript_contains_canary: false,
    };
    remaining(deadline)?;
    Ok((supervisor, channels, deadline))
}
fn inspect(root: &Path) -> Result<Observation, ErrorCode> {
    inspect_contract(root, ReceiptContract::Acceptance)
}
pub(super) fn inspect_contract(
    root: &Path,
    contract: ReceiptContract,
) -> Result<Observation, ErrorCode> {
    inspect_fixture(root, contract, false)
}
#[cfg(feature = "application-slot")]
pub(super) fn inspect_rotation(root: &Path) -> Result<Observation, ErrorCode> {
    inspect_fixture(root, ReceiptContract::Installation, true)
}
fn inspect_fixture(
    root: &Path,
    contract: ReceiptContract,
    rotation: bool,
) -> Result<Observation, ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::safe_directory(root)?;
    let deadline = Instant::now() + PROCESS_TIME;
    let mut supervisor = Supervisor::default();
    let (recipient_mode, mode) = match contract {
        ReceiptContract::Acceptance => ("recipient-open", "inspect"),
        #[cfg(feature = "application-slot")]
        ReceiptContract::Installation => (
            "slot-recipient-inspect",
            if rotation {
                "slot-rotation-inspect"
            } else {
                "slot-inspect"
            },
        ),
    };
    #[cfg(not(feature = "application-slot"))]
    let _ = rotation;
    let recipient = spawn_recipient_mode(root, recipient_mode, &mut supervisor)?;
    let (mut stream, output) = pair()?;
    supervisor.broker = Some(
        child_command(mode, root)?
            .stdin(stdio(recipient))
            .stdout(stdio(output))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ErrorCode::BrokerUnavailable)?,
    );
    #[cfg(test)]
    read_test_banner(&mut stream)?;
    let observation = read_observation(&mut stream, deadline)?;
    supervisor.finish(deadline)?;
    Ok(observation)
}

/// Run the fixed workflow in a NEW absolute directory. The embedding executable
/// must call `synthetic_child_entry` before normal argument parsing. Only its
/// current executable can be launched; this accepts no credential, command,
/// address, caller policy, fault control or claimed deployment readiness.
pub fn run_synthetic_process_service_drill(root: &Path) -> Result<ProcessServiceReport, ErrorCode> {
    run_contract(root, ReceiptContract::Acceptance)
}
pub(super) fn run_contract(
    root: &Path,
    contract: ReceiptContract,
) -> Result<ProcessServiceReport, ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::new_directory(root)?;
    let fixture = bootstrap(root)?;
    let (mut supervisor, mut channels, deadline) =
        start_phase_mode(root, &fixture.vault_id, service_mode(contract, true), true)?;
    let (agent_denied, admin_denied) = channels.connect()?;
    let invocation = channels.approve()?;
    let run: OperationRunView = value(channels.agent("invoke_approved", &invocation)?, "run")?;
    let duplicate: OperationRunView =
        value(channels.agent("invoke_approved", &invocation)?, "run")?;
    let duplicate_reused = run == duplicate;
    let transcript = channels.transcript_contains_canary;
    channels.close()?;
    drop(channels);
    supervisor.finish(deadline)?;

    let (mut supervisor, mut channels, deadline) = start_phase_mode(
        root,
        &fixture.vault_id,
        service_mode(contract, false),
        false,
    )?;
    let (cold_agent, cold_admin) = channels.connect()?;
    channels.revoke()?;
    let transcript = transcript || channels.transcript_contains_canary;
    channels.close()?;
    drop(channels);
    supervisor.finish(deadline)?;
    let observation = inspect_contract(root, contract)?;
    if !(run.state == Lifecycle::Succeeded
        && duplicate_reused
        && agent_denied
        && admin_denied
        && cold_agent
        && cold_admin
        && !transcript
        && observation.consumed == 1
        && observation.incomplete == 0
        && observation.unknown == 0
        && observation.remaining == 3
        && observation.generation == 1
        && observation.revoked
        && observation.revoked_admission_denied
        && super::require_live_deployment() == Err(ErrorCode::UnsupportedDeployment))
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(ProcessServiceReport {
        synthetic_only: true,
        input_import_bound: true,
        authenticated_role_channels: 2,
        tls13_mutual_authentication_verified: true,
        separate_broker_process: true,
        separate_recipient_process: true,
        bootstrap_in_child: true,
        client_signers_outside_broker: true,
        broker_loaded_actor_private_keys: false,
        broker_loaded_tls_client_private_keys: false,
        broker_loaded_recipient_private_keys: false,
        broker_and_recipient_reaped: true,
        unauthenticated_agent_denied: agent_denied,
        unauthenticated_admin_denied: admin_denied,
        completed_deliveries: 1,
        duplicate_reused,
        cold_start_required_authentication: cold_agent && cold_admin,
        consumed_uses: observation.consumed,
        remaining_uses: observation.remaining,
        recipient_generation: observation.generation,
        revoked: observation.revoked,
        revocation_survived_restart: observation.revoked_admission_denied,
        agent_transcript_contains_canary: transcript,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

/// Read fixed durable evidence in a fresh broker child and get a signed recipient
/// snapshot from a separately supervised child. This never authenticates a
/// session, constructs a grant, delivers again, or rewrites fixture artifacts.
pub fn inspect_synthetic_process_service(
    root: &Path,
) -> Result<ProcessServiceRecoveryReport, ErrorCode> {
    let observation = inspect(root)?;
    Ok(ProcessServiceRecoveryReport {
        synthetic_only: true,
        input_import_bound: true,
        separate_broker_process: true,
        broker_and_recipient_reaped: true,
        consumed_uses: observation.consumed,
        incomplete_deliveries: observation.incomplete,
        unknown_deliveries: observation.unknown,
        remaining_uses: observation.remaining,
        recipient_generation: observation.generation,
        revoked: observation.revoked,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

// The runtime freezes one exact profile per broker lifetime. Rotation deliberately
// uses successive fresh broker phases over the same durable Store, never a
// second authority or a mutable-profile command on the agent/admin protocol.
#[cfg(feature = "application-slot")]
pub(super) fn run_rotation(root: &Path) -> Result<ProcessServiceReport, ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::new_directory(root)?;
    let fixture = bootstrap(root)?;
    let mut previous_invocation = None;
    let mut transcript = false;
    for (version, mode, create) in [
        (1, "slot-rotation-create", true),
        (2, "slot-rotation-two", false),
    ] {
        let (mut supervisor, mut channels, deadline) =
            start_phase_mode(root, &fixture.vault_id, mode, create)?;
        if channels.connect()? != (true, true) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        if let Some(previous) = &previous_invocation {
            // Authentication is fresh, but the prior broker's run/approval is not
            // restored. Reject before a new handle can have the same local ID.
            if !is_error(
                &channels.agent("invoke_approved", previous)?,
                ErrorCode::NotFound,
            ) {
                return Err(ErrorCode::BrokerUnavailable);
            }
        }
        let invocation = channels.approve()?;
        let run: OperationRunView = value(channels.agent("invoke_approved", &invocation)?, "run")?;
        let duplicate: OperationRunView =
            value(channels.agent("invoke_approved", &invocation)?, "run")?;
        let Some(crate::OperationResult::Delivery(projection)) = &run.result else {
            return Err(ErrorCode::BrokerUnavailable);
        };
        if run.state != Lifecycle::Succeeded
            || run != duplicate
            || !projection.matches(
                &RequestId::new(if version == 1 {
                    "process-service-import-one"
                } else {
                    "process-service-import-two"
                })?,
                &super::DeliveryParameters::fixture(version),
            )
        {
            return Err(ErrorCode::BrokerUnavailable);
        }
        if version == 2
            && !is_error(
                &channels.agent(
                    "prepare_operation",
                    OperationPrepareInput {
                        request_id: RequestId::new("process-service-import-one")?,
                        profile_id: ProfileId::new("vault-delivery")?,
                        operation: OperationIntent::Delivery(super::DeliveryParameters::fixture(1)),
                    },
                )?,
                ErrorCode::ScopeDenied,
            )
        {
            return Err(ErrorCode::BrokerUnavailable);
        }
        previous_invocation = Some(invocation);
        transcript |= channels.transcript_contains_canary;
        channels.close()?;
        drop(channels);
        supervisor.finish(deadline)?;
        // A new inspection process verifies both imported identities and the
        // recipient's signed state after each phase, including the stale request.
        let observed = inspect_rotation(root)?;
        if observed.consumed != version as usize
            || observed.remaining != 4 - version as u32
            || observed.generation != version
            || observed.installed_version != Some(version)
            || observed.incomplete_installations != Some(0)
            || observed.incomplete != 0
            || observed.unknown != 0
            || observed.revoked
        {
            return Err(ErrorCode::ReconciliationRequired);
        }
    }
    let (mut supervisor, mut channels, deadline) =
        start_phase_mode(root, &fixture.vault_id, "slot-rotation-open", false)?;
    if channels.connect()? != (true, true) {
        return Err(ErrorCode::AuthenticationRequired);
    }
    if !is_error(
        &channels.agent(
            "invoke_approved",
            previous_invocation.ok_or(ErrorCode::BrokerUnavailable)?,
        )?,
        ErrorCode::NotFound,
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    channels.revoke()?;
    transcript |= channels.transcript_contains_canary;
    channels.close()?;
    drop(channels);
    supervisor.finish(deadline)?;
    let observed = inspect_rotation(root)?;
    if transcript
        || observed.consumed != 2
        || observed.remaining != 2
        || observed.generation != 2
        || observed.installed_version != Some(2)
        || observed.incomplete_installations != Some(0)
        || observed.incomplete != 0
        || observed.unknown != 0
        || !observed.revoked
        || !observed.revoked_admission_denied
        || super::require_live_deployment() != Err(ErrorCode::UnsupportedDeployment)
    {
        return Err(ErrorCode::ReconciliationRequired);
    }
    Ok(ProcessServiceReport {
        synthetic_only: true,
        input_import_bound: true,
        authenticated_role_channels: 2,
        tls13_mutual_authentication_verified: true,
        separate_broker_process: true,
        separate_recipient_process: true,
        bootstrap_in_child: true,
        client_signers_outside_broker: true,
        broker_loaded_actor_private_keys: false,
        broker_loaded_tls_client_private_keys: false,
        broker_loaded_recipient_private_keys: false,
        broker_and_recipient_reaped: true,
        unauthenticated_agent_denied: true,
        unauthenticated_admin_denied: true,
        completed_deliveries: 2,
        duplicate_reused: true,
        cold_start_required_authentication: true,
        consumed_uses: observed.consumed,
        remaining_uses: observed.remaining,
        recipient_generation: observed.generation,
        revoked: observed.revoked,
        revocation_survived_restart: observed.revoked_admission_denied,
        agent_transcript_contains_canary: transcript,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

fn broker_service(root: &Path, create: bool, contract: ReceiptContract) -> Result<(), ErrorCode> {
    broker_service_fixture(root, create, contract, false, 1)
}
fn broker_service_fixture(
    root: &Path,
    create: bool,
    contract: ReceiptContract,
    rotation: bool,
    version: u64,
) -> Result<(), ErrorCode> {
    let broker = BrokerRole::open(&root.join("custody/broker"))?;
    let store = if create {
        #[cfg(feature = "application-slot")]
        if rotation {
            let imports = protected_entry::import_delivery_rotation_canaries(
                &root.join("input-1"),
                &root.join("input-2"),
                &broker.material,
            )?;
            Store::create_imported_rotation(&root.join("vault"), broker.material.clone(), imports)?
        } else {
            create_single_import(root, &broker, contract)?
        }
        #[cfg(not(feature = "application-slot"))]
        create_single_import(root, &broker, contract)?
    } else {
        Store::open(&root.join("vault"), broker.material.clone())?
    };
    check_imports(&store, root, rotation)?;
    if store.receipt_contract() != contract {
        return Err(ErrorCode::ReconciliationRequired);
    }
    let recipient = ProcessRecipient::from_supervised_stream_contract(
        broker.material,
        inherited(std::io::stderr())?,
        contract,
    )?;
    // Preserve the existing fixed-fixture journal clock across cold starts.
    // TLS I/O and the owning supervisor enforce real absolute wall-time bounds.
    let protocol = SyntheticProtocol::assemble(
        broker.enrollment,
        store,
        recipient,
        version,
        Arc::new(ManualClock::default()),
    )?;
    serve_protocol(root, protocol)
}
fn create_single_import(
    root: &Path,
    broker: &BrokerRole,
    contract: ReceiptContract,
) -> Result<Arc<Store>, ErrorCode> {
    let imported = protected_entry::import_delivery_canary_contract(
        &root.join("input"),
        &broker.material,
        contract,
    )?;
    Store::create_imported_contract(
        &root.join("vault"),
        broker.material.clone(),
        imported,
        contract,
    )
}
fn check_imports(store: &Store, root: &Path, rotation: bool) -> Result<(), ErrorCode> {
    #[cfg(feature = "application-slot")]
    if rotation {
        return store.check_imported_rotation(&root.join("input-1"), &root.join("input-2"));
    }
    #[cfg(not(feature = "application-slot"))]
    let _ = rotation;
    store.check_imported_record(&root.join("input"))
}
fn serve_protocol(root: &Path, protocol: SyntheticProtocol) -> Result<(), ErrorCode> {
    let material = ServerMaterial::open(&root.join("tls/broker"))?;
    let agent_stream = inherited(std::io::stdin())?;
    let admin_stream = inherited(std::io::stdout())?;
    let stop_agent = agent_stream
        .try_clone()
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    let stop_admin = admin_stream
        .try_clone()
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let result = (|| {
                let mut server = material.agent(agent_stream, protocol.agent)?;
                #[cfg(test)]
                let discard_response = std::env::var("AEGIS_PROCESS_SERVICE_TEST_MODE").as_deref()
                    == Ok("create-drop-response");
                for frame in 0..protocol::MAX_ENDPOINT_FRAMES {
                    #[cfg(test)]
                    if discard_response && frame == 7 {
                        server.discard_next_response_for_test();
                    }
                    #[cfg(not(test))]
                    let _ = frame;
                    if !server.serve_one()? {
                        return Ok(());
                    }
                }
                Err(ErrorCode::CapacityExceeded)
            })();
            if result.is_err() {
                let _ = stop_admin.shutdown(Shutdown::Both);
            }
            result
        });
        let result = (|| {
            let mut server = material.admin(admin_stream, protocol.admin)?;
            while server.serve_one()? {}
            Ok(())
        })();
        if result.is_err() {
            let _ = stop_agent.shutdown(Shutdown::Both);
        }
        let agent_result = worker.join().map_err(|_| ErrorCode::BrokerUnavailable)?;
        result.and(agent_result)
    })
}
fn broker_inspect(root: &Path, contract: ReceiptContract) -> Result<(), ErrorCode> {
    broker_inspect_fixture(root, contract, false)
}
fn broker_inspect_fixture(
    root: &Path,
    contract: ReceiptContract,
    rotation: bool,
) -> Result<(), ErrorCode> {
    let broker = BrokerRole::open(&root.join("custody/broker"))?;
    let store = Store::open(&root.join("vault"), broker.material.clone())?;
    check_imports(&store, root, rotation)?;
    if store.receipt_contract() != contract {
        return Err(ErrorCode::ReconciliationRequired);
    }
    let recipient = ProcessRecipient::from_supervised_stream_contract(
        broker.material,
        inherited(std::io::stdin())?,
        contract,
    )?;
    let snapshot = recipient.snapshot()?;
    store.check_process_receipts(&snapshot.received)?;
    let (consumed, incomplete, unknown, remaining, revoked) = store.history_counts()?;
    write_observation(&Observation {
        consumed,
        incomplete,
        unknown,
        remaining,
        generation: snapshot.generation,
        revoked,
        revoked_admission_denied: store.ready() == Err(ErrorCode::GrantRevoked),
        installed_version: snapshot.installed_version,
        incomplete_installations: snapshot.incomplete_installations,
    })
}
fn child(mode: &str, root: &Path) -> Result<(), ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::safe_directory(root)?;
    match mode {
        "bootstrap" => {
            let fixture = custody::bootstrap_synthetic_custody(&root.join("custody"))?;
            socket::bootstrap_fixture(&root.join("tls"))?;
            write_observation(&Bootstrap {
                vault_id: fixture.vault_id,
            })
        }
        "create" => broker_service(root, true, ReceiptContract::Acceptance),
        "open" => broker_service(root, false, ReceiptContract::Acceptance),
        "inspect" => broker_inspect(root, ReceiptContract::Acceptance),
        #[cfg(test)]
        "create-drop-response" | "create-lost-recipient-reply" => {
            broker_service(root, true, ReceiptContract::Acceptance)
        }
        #[cfg(test)]
        "recipient-create-drop-reply" => {
            process_recipient::supervised_child_discard_delivery_reply(
                &root.join("custody/recipient"),
                &root.join("recipient"),
            )
        }
        "recipient-create" | "recipient-open" => process_recipient::supervised_child(
            &root.join("custody/recipient"),
            &root.join("recipient"),
            mode == "recipient-create",
        ),
        #[cfg(feature = "application-slot")]
        "slot-create" => broker_service(root, true, ReceiptContract::Installation),
        #[cfg(feature = "application-slot")]
        "slot-open" => broker_service(root, false, ReceiptContract::Installation),
        #[cfg(feature = "application-slot")]
        "slot-inspect" => broker_inspect(root, ReceiptContract::Installation),
        #[cfg(feature = "application-slot")]
        "slot-rotation-create" => {
            broker_service_fixture(root, true, ReceiptContract::Installation, true, 1)
        }
        #[cfg(feature = "application-slot")]
        "slot-rotation-two" | "slot-rotation-open" => {
            broker_service_fixture(root, false, ReceiptContract::Installation, true, 2)
        }
        #[cfg(feature = "application-slot")]
        "slot-rotation-inspect" => {
            broker_inspect_fixture(root, ReceiptContract::Installation, true)
        }
        #[cfg(feature = "application-slot")]
        "slot-recipient-create" | "slot-recipient-open" | "slot-recipient-inspect" => {
            process_recipient::supervised_application_child(
                &root.join("custody/recipient"),
                root,
                mode == "slot-recipient-create",
                mode == "slot-recipient-inspect",
            )
        }
        #[cfg(all(test, feature = "application-slot"))]
        "slot-create-exit-intent"
        | "slot-create-exit-stage"
        | "slot-create-exit-rename"
        | "slot-create-exit-directory"
        | "slot-create-exit-receipt" => broker_service(root, true, ReceiptContract::Installation),
        #[cfg(all(test, feature = "application-slot"))]
        "slot-rotation-two-exit-intent"
        | "slot-rotation-two-exit-stage"
        | "slot-rotation-two-exit-rename"
        | "slot-rotation-two-exit-directory"
        | "slot-rotation-two-exit-receipt" => {
            broker_service_fixture(root, false, ReceiptContract::Installation, true, 2)
        }
        #[cfg(all(test, feature = "application-slot"))]
        "slot-recipient-exit-intent"
        | "slot-recipient-exit-stage"
        | "slot-recipient-exit-rename"
        | "slot-recipient-exit-directory"
        | "slot-recipient-exit-receipt"
        | "slot-rotation-recipient-exit-intent"
        | "slot-rotation-recipient-exit-stage"
        | "slot-rotation-recipient-exit-rename"
        | "slot-rotation-recipient-exit-directory"
        | "slot-rotation-recipient-exit-receipt" => {
            super::application_slot::set_child_fault(mode)?;
            process_recipient::supervised_application_child(
                &root.join("custody/recipient"),
                root,
                !mode.starts_with("slot-rotation-"),
                false,
            )
        }
        _ => Err(ErrorCode::InvalidRequest),
    }
}

/// Dispatch only the fixed internal subprocess roles before CLI argument parsing.
/// Runtime descriptors are agent TLS on stdin, admin TLS on stdout and recipient
/// IPC on stderr. No diagnostics are written to those protocol descriptors.
pub fn synthetic_child_entry() -> Option<ExitCode> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_none_or(|arg| arg != CHILD_FLAG) {
        return None;
    }
    std::panic::set_hook(Box::new(|_| {}));
    let result = match args.as_slice() {
        [_, mode, root] => mode
            .to_str()
            .ok_or(ErrorCode::InvalidRequest)
            .and_then(|mode| child(mode, root.as_ref())),
        _ => Err(ErrorCode::InvalidRequest),
    };
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            let parent = std::env::temp_dir().canonicalize().unwrap();
            let path = parent.join(format!(
                "aegis-service-unit-{}",
                super::super::crypto::random_id().unwrap()
            ));
            Self(path)
        }
        fn bootstrap(&self) -> Bootstrap {
            store::new_directory(&self.0).unwrap();
            super::bootstrap(&self.0).unwrap()
        }
    }
    impl Drop for Paths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn pids(supervisor: &mut Supervisor) -> [u32; 2] {
        let broker = supervisor.broker.as_mut().unwrap();
        let recipient = supervisor.recipient.as_mut().unwrap();
        assert!(broker.try_wait().unwrap().is_none());
        assert!(recipient.try_wait().unwrap().is_none());
        [broker.id(), recipient.id()]
    }
    fn reaped(pids: [u32; 2]) {
        #[cfg(target_os = "linux")]
        for pid in pids {
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "owned subprocess survived its guard"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = pids;
    }

    #[test]
    fn actual_broker_import_tls_delivery_restart_revoke_and_inspect() {
        let paths = Paths::new();
        let report = run_synthetic_process_service_drill(&paths.0).unwrap();
        assert!(report.broker_and_recipient_reaped);
        assert!(report.duplicate_reused);
        assert!(report.cold_start_required_authentication);
        assert!(report.revocation_survived_restart);
        assert!(!report.agent_transcript_contains_canary);
        let inspected = inspect_synthetic_process_service(&paths.0).unwrap();
        assert_eq!(
            (
                inspected.consumed_uses,
                inspected.recipient_generation,
                inspected.remaining_uses
            ),
            (1, 1, 3)
        );
    }

    #[test]
    fn elapsed_first_phase_can_reopen_and_append_cold_revocation() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, mut channels, deadline) =
            start_phase(&paths.0, &fixture.vault_id, true).unwrap();
        channels.connect().unwrap();
        let invocation = channels.approve().unwrap();
        let handle = json!({"prepared_request_id": invocation["prepared_request_id"]});
        // Keep both bounded TLS streams active while the first process's real
        // clock crosses one second. A reset elapsed-time journal clock would
        // then reject a new process's earlier revocation timestamp.
        let started = Instant::now();
        for _ in 0..12 {
            thread::sleep(Duration::from_millis(100));
            assert!(is_kind(
                &channels.agent("discover_operations", json!({})).unwrap(),
                "catalog"
            ));
            assert!(is_kind(
                &exchange(&mut channels.admin, "inspect_review", &handle).unwrap(),
                "review"
            ));
        }
        assert!(started.elapsed() >= Duration::from_secs(1));
        let run: OperationRunView = value(
            channels.agent("invoke_approved", &invocation).unwrap(),
            "run",
        )
        .unwrap();
        assert_eq!(run.state, Lifecycle::Succeeded);
        channels.close().unwrap();
        drop(channels);
        supervisor.finish(deadline).unwrap();

        let (mut supervisor, mut channels, deadline) =
            start_phase(&paths.0, &fixture.vault_id, false).unwrap();
        assert_eq!(channels.connect().unwrap(), (true, true));
        channels.revoke().unwrap();
        channels.close().unwrap();
        drop(channels);
        supervisor.finish(deadline).unwrap();
        let observation = inspect(&paths.0).unwrap();
        assert_eq!((observation.consumed, observation.generation), (1, 1));
        assert!(observation.revoked && observation.revoked_admission_denied);
    }

    #[test]
    fn killing_actual_broker_reaps_its_live_recipient_without_dispatch() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, mut channels, _) =
            start_phase(&paths.0, &fixture.vault_id, true).unwrap();
        let ids = pids(&mut supervisor);
        supervisor.broker.as_mut().unwrap().kill().unwrap();
        assert!(channels.agent("discover_operations", json!({})).is_err());
        drop(channels);
        drop(supervisor);
        reaped(ids);
        let observation = inspect(&paths.0).unwrap();
        assert_eq!(
            (
                observation.consumed,
                observation.generation,
                observation.remaining
            ),
            (0, 0, 4)
        );
    }

    #[test]
    fn dropping_actual_clients_reaps_both_owned_processes() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, channels, _) = start_phase(&paths.0, &fixture.vault_id, true).unwrap();
        let ids = pids(&mut supervisor);
        drop(channels);
        drop(supervisor);
        reaped(ids);
        assert_eq!(inspect(&paths.0).unwrap().consumed, 0);
    }

    #[test]
    fn expired_supervisor_deadline_reaps_both_live_children() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, channels, _) = start_phase(&paths.0, &fixture.vault_id, true).unwrap();
        let ids = pids(&mut supervisor);
        assert_eq!(
            supervisor.finish(Instant::now()),
            Err(ErrorCode::BrokerUnavailable)
        );
        drop(channels);
        drop(supervisor);
        reaped(ids);
        assert_eq!(inspect(&paths.0).unwrap().consumed, 0);
    }

    #[test]
    fn lost_agent_reply_retains_completed_effect_and_rejects_cold_retry() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, mut channels, _) =
            start_phase_mode(&paths.0, &fixture.vault_id, "create-drop-response", true).unwrap();
        let ids = pids(&mut supervisor);
        channels.connect().unwrap();
        let invocation = channels.approve().unwrap();
        assert!(channels.agent("invoke_approved", &invocation).is_err());
        assert!(channels.agent("invoke_approved", &invocation).is_err());
        drop(channels);
        drop(supervisor);
        reaped(ids);
        let observation = inspect(&paths.0).unwrap();
        assert_eq!(
            (
                observation.consumed,
                observation.incomplete,
                observation.unknown,
                observation.generation,
                observation.remaining
            ),
            (1, 0, 0, 1, 3)
        );
        let (mut supervisor, mut channels, deadline) =
            start_phase(&paths.0, &fixture.vault_id, false).unwrap();
        assert_eq!(channels.connect().unwrap(), (true, true));
        let response = channels
            .agent(
                "prepare_operation",
                OperationPrepareInput {
                    request_id: RequestId::new("process-service-import-one").unwrap(),
                    profile_id: ProfileId::new("vault-delivery").unwrap(),
                    operation: OperationIntent::Delivery(
                        super::super::DeliveryParameters::fixture(1),
                    ),
                },
            )
            .unwrap();
        assert!(is_error(&response, ErrorCode::RequestIdConflict));
        channels.close().unwrap();
        drop(channels);
        supervisor.finish(deadline).unwrap();
        assert_eq!(inspect(&paths.0).unwrap().generation, 1);
    }

    #[test]
    fn lost_recipient_reply_retains_consumed_unknown_without_automatic_retry() {
        let paths = Paths::new();
        let fixture = paths.bootstrap();
        let (mut supervisor, mut channels, deadline) = start_phase_mode(
            &paths.0,
            &fixture.vault_id,
            "create-lost-recipient-reply",
            true,
        )
        .unwrap();
        let ids = pids(&mut supervisor);
        channels.connect().unwrap();
        let invocation = channels.approve().unwrap();
        let run: OperationRunView = value(
            channels.agent("invoke_approved", &invocation).unwrap(),
            "run",
        )
        .unwrap();
        assert_eq!(run.state, Lifecycle::OutcomeUnknown);
        let duplicate: OperationRunView = value(
            channels.agent("invoke_approved", &invocation).unwrap(),
            "run",
        )
        .unwrap();
        assert_eq!(run, duplicate);
        channels.close().unwrap();
        drop(channels);
        supervisor.finish(deadline).unwrap();
        reaped(ids);
        let observation = inspect(&paths.0).unwrap();
        assert_eq!(
            (
                observation.consumed,
                observation.incomplete,
                observation.unknown,
                observation.generation,
                observation.remaining
            ),
            (1, 0, 1, 1, 3)
        );
        assert!(start_phase(&paths.0, &fixture.vault_id, false).is_err());
        let recovered = inspect_synthetic_process_service(&paths.0).unwrap();
        assert_eq!(recovered.unknown_deliveries, 1);
        assert_eq!(recovered.consumed_uses, 1);
        assert_eq!(recovered.recipient_generation, 1);
        assert!(!recovered.automatic_retry_allowed);
    }

    #[cfg(feature = "application-slot")]
    #[test]
    fn application_slot_actual_child_exits_retain_consumed_uncertainty_at_five_boundaries() {
        let scenarios = [
            ("slot-create-exit-intent", 0, 0, 1, false),
            ("slot-create-exit-stage", 0, 0, 1, true),
            ("slot-create-exit-rename", 0, 1, 1, false),
            ("slot-create-exit-directory", 0, 1, 1, false),
            ("slot-create-exit-receipt", 1, 1, 0, false),
        ];
        for (mode, generation, installed, pending, staged) in scenarios {
            let paths = Paths::new();
            let fixture = paths.bootstrap();
            let (mut supervisor, mut channels, deadline) =
                start_phase_mode(&paths.0, &fixture.vault_id, mode, true).unwrap();
            let ids = pids(&mut supervisor);
            channels.connect().unwrap();
            let invocation = channels.approve().unwrap();
            let run: OperationRunView = value(
                channels.agent("invoke_approved", &invocation).unwrap(),
                "run",
            )
            .unwrap();
            assert_eq!(run.state, Lifecycle::OutcomeUnknown, "{mode}");
            let duplicate: OperationRunView = value(
                channels.agent("invoke_approved", &invocation).unwrap(),
                "run",
            )
            .unwrap();
            assert_eq!(run, duplicate, "{mode}");
            channels.close().unwrap();
            drop(channels);
            supervisor.finish(deadline).unwrap();
            reaped(ids);
            let before = fs::read(paths.0.join("application/installation.jws")).unwrap();
            let report =
                super::super::application_slot::inspect_synthetic_application_slot(&paths.0)
                    .unwrap();
            assert_eq!(
                (
                    report.consumed_uses,
                    report.remaining_uses,
                    report.unknown_deliveries
                ),
                (1, 3, 1),
                "{mode}"
            );
            assert_eq!(
                (
                    report.recipient_generation,
                    report.installed_version,
                    report.incomplete_installations
                ),
                (generation, installed, pending),
                "{mode}"
            );
            assert!(!report.automatic_retry_allowed);
            assert_eq!(
                paths.0.join("application/.provider-auth.stage").exists(),
                staged,
                "{mode}"
            );
            assert_eq!(
                fs::read(paths.0.join("application/installation.jws")).unwrap(),
                before
            );
            assert!(
                start_phase_mode(&paths.0, &fixture.vault_id, "slot-open", false).is_err(),
                "{mode}"
            );
            let again =
                super::super::application_slot::inspect_synthetic_application_slot(&paths.0)
                    .unwrap();
            assert_eq!(again, report, "{mode}");
        }
    }

    #[test]
    fn child_fixture() {
        let Some(mode) = std::env::var_os("AEGIS_PROCESS_SERVICE_TEST_MODE") else {
            return;
        };
        // Exit before libtest can print its result into a protocol descriptor.
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::env::var_os("AEGIS_PROCESS_SERVICE_TEST_ROOT")
            .ok_or(ErrorCode::InvalidRequest)
            .and_then(|root| {
                child(
                    mode.to_str().ok_or(ErrorCode::InvalidRequest)?,
                    Path::new(&root),
                )
            });
        std::process::exit(if result.is_ok() { 0 } else { 2 });
    }

    #[cfg(feature = "application-slot")]
    #[test]
    fn application_rotation_composes_both_imports_fresh_phases_and_durable_revoke() {
        let paths = Paths::new();
        let report =
            super::super::application_rotation::run_synthetic_application_rotation_drill(&paths.0)
                .unwrap();
        assert_eq!(report.imported_versions, [1, 2]);
        assert_eq!(report.completed_installation_generations, [1, 2]);
        assert_eq!(report.delivery_broker_phases, 2);
        assert_eq!(report.retained_duplicate_outcomes, 2);
        assert!(report.exact_import_ciphertexts_verified);
        assert!(report.distinct_import_bindings_verified);
        assert!(report.exact_approvals_verified);
        assert!(report.fresh_authentication_between_versions);
        assert!(report.old_version_rollback_prevented);
        assert!(report.installation.revocation_survived_restart);
        assert_eq!(
            (
                report.installation.consumed_uses,
                report.installation.remaining_uses
            ),
            (2, 2)
        );
        assert_eq!(
            fs::read(paths.0.join("application/provider-auth")).unwrap(),
            store::CANARY_TWO.as_bytes()
        );
        for version in [1, 2] {
            assert_eq!(
                fs::read(paths.0.join(format!("input-{version}/record.age"))).unwrap(),
                fs::read(paths.0.join(format!("vault/secret-{version}.age"))).unwrap()
            );
        }
        assert_ne!(
            fs::read(paths.0.join("input-1/record.age")).unwrap(),
            fs::read(paths.0.join("input-2/record.age")).unwrap()
        );
        // Neither inspector can silently treat one imported version as the pair.
        assert!(
            super::super::application_slot::inspect_synthetic_application_slot(&paths.0).is_err()
        );
        let single = Paths::new();
        super::super::application_slot::run_synthetic_application_slot_drill(&single.0).unwrap();
        assert!(
            super::super::application_rotation::inspect_synthetic_application_rotation(&single.0)
                .is_err()
        );
    }

    #[cfg(feature = "application-slot")]
    #[test]
    fn application_rotation_second_child_exits_preserve_old_new_state_without_refund_or_replay() {
        use std::os::unix::fs::MetadataExt;
        let scenarios = [
            ("slot-rotation-two-exit-intent", 1, 1, 1, false),
            ("slot-rotation-two-exit-stage", 1, 1, 1, true),
            ("slot-rotation-two-exit-rename", 1, 2, 1, false),
            ("slot-rotation-two-exit-directory", 1, 2, 1, false),
            ("slot-rotation-two-exit-receipt", 2, 2, 0, false),
        ];
        for (mode, generation, installed, pending, staged) in scenarios {
            let paths = Paths::new();
            let fixture = paths.bootstrap();
            let (mut supervisor, mut channels, deadline) =
                start_phase_mode(&paths.0, &fixture.vault_id, "slot-rotation-create", true)
                    .unwrap();
            assert_eq!(channels.connect().unwrap(), (true, true));
            let first_invocation = channels.approve().unwrap();
            let first: OperationRunView = value(
                channels
                    .agent("invoke_approved", &first_invocation)
                    .unwrap(),
                "run",
            )
            .unwrap();
            assert_eq!(first.state, Lifecycle::Succeeded);
            channels.close().unwrap();
            drop(channels);
            supervisor.finish(deadline).unwrap();
            let first_history = fs::read(paths.0.join("application/installation.jws")).unwrap();
            let mut predecessor =
                fs::File::open(paths.0.join("application/provider-auth")).unwrap();
            let predecessor_inode = predecessor.metadata().unwrap().ino();

            let (mut supervisor, mut channels, deadline) =
                start_phase_mode(&paths.0, &fixture.vault_id, mode, false).unwrap();
            let ids = pids(&mut supervisor);
            assert_eq!(channels.connect().unwrap(), (true, true));
            assert!(is_error(
                &channels
                    .agent("invoke_approved", &first_invocation)
                    .unwrap(),
                ErrorCode::NotFound
            ));
            let invocation = channels.approve().unwrap();
            let run: OperationRunView = value(
                channels.agent("invoke_approved", &invocation).unwrap(),
                "run",
            )
            .unwrap();
            assert_eq!(run.state, Lifecycle::OutcomeUnknown, "{mode}");
            let before_duplicate = fs::read(paths.0.join("vault/journal.jws")).unwrap();
            let duplicate: OperationRunView = value(
                channels.agent("invoke_approved", &invocation).unwrap(),
                "run",
            )
            .unwrap();
            assert_eq!(run, duplicate, "{mode}");
            assert_eq!(
                fs::read(paths.0.join("vault/journal.jws")).unwrap(),
                before_duplicate,
                "{mode}"
            );
            channels.close().unwrap();
            drop(channels);
            supervisor.finish(deadline).unwrap();
            reaped(ids);

            let snapshot = || {
                [
                    "vault/journal.jws",
                    "application/installation.jws",
                    "application/provider-auth",
                    "application/.provider-auth.stage",
                ]
                .map(|name| {
                    let path = paths.0.join(name);
                    match fs::metadata(&path) {
                        Ok(metadata) => Some((
                            fs::read(path).unwrap(),
                            metadata.ino(),
                            metadata.mode(),
                            metadata.modified().unwrap(),
                        )),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(_) => panic!("fixture object unreadable"),
                    }
                })
            };
            let evidence = snapshot();
            let report =
                super::super::application_rotation::inspect_synthetic_application_rotation(
                    &paths.0,
                )
                .unwrap();
            let state = &report.installation;
            assert_eq!(
                (
                    state.consumed_uses,
                    state.remaining_uses,
                    state.incomplete_deliveries,
                    state.unknown_deliveries
                ),
                (2, 2, 0, 1),
                "{mode}"
            );
            assert_eq!(
                (
                    state.recipient_generation,
                    state.installed_version,
                    state.incomplete_installations
                ),
                (generation, installed, pending),
                "{mode}"
            );
            assert!(state.installation_receipt_verified);
            assert!(!state.automatic_retry_allowed);
            assert_eq!(state.restored_sessions, 0);
            assert_eq!(
                paths.0.join("application/.provider-auth.stage").exists(),
                staged,
                "{mode}"
            );
            assert!(fs::read(paths.0.join("application/installation.jws"))
                .unwrap()
                .starts_with(&first_history));
            let mut prior_bytes = Vec::new();
            predecessor.read_to_end(&mut prior_bytes).unwrap();
            assert_eq!(prior_bytes, store::CANARY_ONE.as_bytes());
            let current = paths.0.join("application/provider-auth");
            assert_eq!(
                fs::read(&current).unwrap(),
                if installed == 1 {
                    store::CANARY_ONE
                } else {
                    store::CANARY_TWO
                }
                .as_bytes()
            );
            assert_eq!(
                fs::metadata(current).unwrap().ino() == predecessor_inode,
                installed == 1
            );
            assert_eq!(snapshot(), evidence, "{mode}");
            assert!(
                start_phase_mode(&paths.0, &fixture.vault_id, "slot-rotation-two", false).is_err(),
                "{mode}"
            );
            assert_eq!(
                super::super::application_rotation::inspect_synthetic_application_rotation(
                    &paths.0
                )
                .unwrap(),
                report,
                "{mode}"
            );
            assert_eq!(snapshot(), evidence, "{mode}");
        }
    }
}
