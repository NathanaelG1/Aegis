//! Transport-neutral, separately authenticated agent and administrator endpoints.
//!
//! This module binds serialized requests to the main core. It starts no listener and
//! accepts no secret values. Public constructors are explicitly fixed-canary fixtures;
//! production bootstrap, trusted transport, clock and custody remain unavailable.
use super::{
    auth::{self, AdminSession, Purpose, Review},
    crypto::Signed,
    runtime::{assemble_runtime, Adapter},
    store::{Kit, Recipient, Store},
};
use crate::{
    AgentClient, Clock, Control, ErrorCode, OperationDiscovery, OperationPrepareInput,
    OperationRunView,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use zeroize::Zeroize;

pub use super::auth::{Challenge as ProofChallenge, Purpose as ProofPurpose, Review as ReviewPlan};
pub const PROTOCOL: &str = "aegis.synthetic.vault.v1";
pub const VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_ENDPOINT_FRAMES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEnvelope {
    protocol: String,
    version: u32,
    action: AgentAction,
}
#[derive(Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum AgentAction {
    ConnectChallenge(Empty),
    Connect(Proof),
    DiscoverOperations(Empty),
    PrepareOperation(OperationPrepareInput),
    RequestApproval(Handle),
    InvocationChallenge(Handle),
    InvokeApproved(Invocation),
    GetRunStatus(Handle),
    Cancel(Handle),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminEnvelope {
    protocol: String,
    version: u32,
    action: AdminAction,
}
#[derive(Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum AdminAction {
    ConnectChallenge(Empty),
    Connect(Proof),
    InspectReview(Handle),
    ApprovalChallenge(ReviewPlan),
    Approve(Approval),
    RevokeChallenge(Empty),
    Revoke(Proof),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handle {
    prepared_request_id: u64,
}
// Assertions are caller-owned authentication proofs, never provider credentials.
// No Debug or serialization implementation can echo them into responses/diagnostics.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    assertion: String,
}
impl Proof {
    fn parsed(&self) -> Result<Signed, ErrorCode> {
        if self.assertion.len() > 4096 {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Signed::parse(self.assertion.as_bytes())
    }
}
impl Drop for Proof {
    fn drop(&mut self) {
        self.assertion.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    prepared_request_id: u64,
    proof: Proof,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    expected: ReviewPlan,
    proof: Proof,
}

/// Closed output contract. It contains no assertions, capsule bytes, private keys or values.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProtocolResult {
    Challenge(ProofChallenge),
    Connected,
    Catalog(OperationDiscovery),
    Run(OperationRunView),
    Review(Box<ReviewPlan>),
    Revoked,
}
#[derive(Debug, Serialize)]
pub struct ProtocolResponse {
    pub protocol: &'static str,
    pub version: u32,
    pub synthetic_only: bool,
    pub result: Option<ProtocolResult>,
    pub error: Option<ErrorCode>,
}
impl ProtocolResponse {
    fn from_result(result: Result<ProtocolResult, ErrorCode>) -> Self {
        let (result, error) = match result {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        Self {
            protocol: PROTOCOL,
            version: VERSION,
            synthetic_only: true,
            result,
            error,
        }
    }
}
struct Service {
    control: Arc<Control>,
    adapter: Arc<Adapter>,
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.control.stop();
        self.adapter.gate.revoke();
    }
}
/// One agent connection. Possessing another endpoint's connection does not authenticate it.
pub struct AgentEndpoint {
    service: Arc<Service>,
    initial: AgentClient,
    client: Mutex<Option<AgentClient>>,
    frames: AtomicUsize,
}
/// Independent human-control connection. Key possession is not human presence.
pub struct AdminEndpoint {
    service: Arc<Service>,
    session: Mutex<Option<Arc<AdminSession>>>,
    frames: AtomicUsize,
}
/// Trusted-host fixture assembly. Give each endpoint only to its intended simulated role.
/// The runtime retains no actor signer; the on-disk all-role kit is still dummy-only.
pub struct SyntheticProtocol {
    pub agent: AgentEndpoint,
    pub admin: AdminEndpoint,
}
impl SyntheticProtocol {
    /// Create new fixed canary records and disposable actor keys. No arbitrary value input.
    pub fn create(
        root: &Path,
        fixture_kit: &Path,
        recipient: &Path,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let kit = Kit::create(fixture_kit)?;
        let store = Store::create(root, kit.broker_material())?;
        let recipient = Recipient::create(recipient, kit.recipient_material())?;
        Self::assemble(kit.actors.enrollment(), store, recipient, 1, clock)
    }
    /// Cold-start the fixed fixture. Sessions/proofs are absent and fresh authentication is required.
    pub fn open(
        root: &Path,
        fixture_kit: &Path,
        recipient: &Path,
        version: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let kit = Kit::open(fixture_kit)?;
        let store = Store::open(root, kit.broker_material())?;
        let recipient = Recipient::open(recipient, kit.recipient_material())?;
        Self::assemble(kit.actors.enrollment(), store, recipient, version, clock)
    }
    pub(super) fn assemble(
        enrollment: auth::Enrollment,
        store: Arc<Store>,
        recipient: Arc<Recipient>,
        version: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let (control, initial, adapter) =
            assemble_runtime(enrollment, store, recipient, version, clock)?;
        let service = Arc::new(Service { control, adapter });
        Ok(Self {
            agent: AgentEndpoint {
                service: service.clone(),
                initial,
                client: Mutex::new(None),
                frames: AtomicUsize::new(0),
            },
            admin: AdminEndpoint {
                service,
                session: Mutex::new(None),
                frames: AtomicUsize::new(0),
            },
        })
    }
}
fn bounded(frame: &[u8], frames: &AtomicUsize) -> Result<(), ErrorCode> {
    frames
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_ENDPOINT_FRAMES).then_some(n + 1)
        })
        .map_err(|_| ErrorCode::CapacityExceeded)?;
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}
fn version(protocol: &str, version: u32) -> Result<(), ErrorCode> {
    if protocol != PROTOCOL || version != VERSION {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(())
}
impl AgentEndpoint {
    /// Process one bounded frame; transport must separately provide confidentiality and peer isolation.
    pub fn handle(&self, frame: &[u8]) -> ProtocolResponse {
        ProtocolResponse::from_result(self.process(frame))
    }
    fn client(&self) -> Result<AgentClient, ErrorCode> {
        self.client
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .clone()
            .ok_or(ErrorCode::AuthenticationRequired)
    }
    fn process(&self, frame: &[u8]) -> Result<ProtocolResult, ErrorCode> {
        bounded(frame, &self.frames)?;
        let envelope: AgentEnvelope =
            serde_json::from_slice(frame).map_err(|_| ErrorCode::InvalidRequest)?;
        version(&envelope.protocol, envelope.version)?;
        let gate = &self.service.adapter.gate;
        match envelope.action {
            AgentAction::ConnectChallenge(_) => Ok(ProtocolResult::Challenge(
                gate.challenge(Purpose::Connect, gate.context_digest(Purpose::Connect)?)?,
            )),
            AgentAction::Connect(proof) => {
                let mut client = self
                    .client
                    .lock()
                    .map_err(|_| ErrorCode::BrokerUnavailable)?;
                if client.is_some() {
                    return Err(ErrorCode::AuthenticationRequired);
                }
                *client = Some(
                    self.initial
                        .with_vault_session(gate.connect(proof.parsed()?)?),
                );
                Ok(ProtocolResult::Connected)
            }
            AgentAction::DiscoverOperations(_) => Ok(ProtocolResult::Catalog(
                self.client()?.discover_versioned_operations()?,
            )),
            AgentAction::PrepareOperation(input) => Ok(ProtocolResult::Run(
                self.client()?.prepare_operation(input)?,
            )),
            AgentAction::RequestApproval(h) => Ok(ProtocolResult::Run(
                self.client()?
                    .request_operation_approval(h.prepared_request_id)?,
            )),
            AgentAction::GetRunStatus(h) => Ok(ProtocolResult::Run(
                self.client()?.operation_status(h.prepared_request_id)?,
            )),
            AgentAction::Cancel(h) => Ok(ProtocolResult::Run(
                self.client()?.cancel_operation(h.prepared_request_id)?,
            )),
            AgentAction::InvocationChallenge(h) => {
                self.client()?.operation_status(h.prepared_request_id)?;
                let d = self
                    .service
                    .control
                    .delivery_context(h.prepared_request_id)?;
                Ok(ProtocolResult::Challenge(
                    gate.challenge(Purpose::Invoke, auth::dispatch_digest(&d)?)?,
                ))
            }
            AgentAction::InvokeApproved(i) => {
                let client = self.client()?;
                // Check this connection before staging any assertion, including terminal/replay calls.
                client.operation_status(i.prepared_request_id)?;
                gate.stage_agent(i.prepared_request_id, i.proof.parsed()?)?;
                let result = client.invoke_operation(i.prepared_request_id);
                gate.discard(i.prepared_request_id, false);
                Ok(ProtocolResult::Run(result?))
            }
        }
    }
}
impl AdminEndpoint {
    /// Process one admin frame. No agent method can route through this endpoint implicitly.
    pub fn handle(&self, frame: &[u8]) -> ProtocolResponse {
        ProtocolResponse::from_result(self.process(frame))
    }
    fn session(&self) -> Result<Arc<AdminSession>, ErrorCode> {
        let session = self
            .session
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .clone();
        self.service.adapter.gate.check_admin(session.as_ref())?;
        session.ok_or(ErrorCode::AuthenticationRequired)
    }
    fn exact_review(
        &self,
        expected: &ReviewPlan,
    ) -> Result<crate::OperationApprovalView, ErrorCode> {
        let actual = self
            .service
            .control
            .inspect_operation_approval(expected.prepared)?;
        if Review::of(&actual)? != *expected {
            return Err(ErrorCode::ApprovalRequired);
        }
        Ok(actual)
    }
    fn process(&self, frame: &[u8]) -> Result<ProtocolResult, ErrorCode> {
        bounded(frame, &self.frames)?;
        let envelope: AdminEnvelope =
            serde_json::from_slice(frame).map_err(|_| ErrorCode::InvalidRequest)?;
        version(&envelope.protocol, envelope.version)?;
        let gate = &self.service.adapter.gate;
        match envelope.action {
            AdminAction::ConnectChallenge(_) => Ok(ProtocolResult::Challenge(gate.challenge(
                Purpose::AdminConnect,
                gate.context_digest(Purpose::AdminConnect)?,
            )?)),
            AdminAction::Connect(proof) => {
                let mut session = self
                    .session
                    .lock()
                    .map_err(|_| ErrorCode::BrokerUnavailable)?;
                if session.is_some() {
                    return Err(ErrorCode::AuthenticationRequired);
                }
                *session = Some(gate.connect_admin(proof.parsed()?)?);
                Ok(ProtocolResult::Connected)
            }
            AdminAction::InspectReview(h) => {
                self.session()?;
                Ok(ProtocolResult::Review(Box::new(Review::of(
                    &self
                        .service
                        .control
                        .inspect_operation_approval(h.prepared_request_id)?,
                )?)))
            }
            AdminAction::ApprovalChallenge(expected) => {
                self.session()?;
                self.exact_review(&expected)?;
                Ok(ProtocolResult::Challenge(
                    gate.challenge(Purpose::Approve, expected.digest()?)?,
                ))
            }
            AdminAction::Approve(a) => {
                let session = self.session()?;
                let actual = self.exact_review(&a.expected)?;
                gate.stage_admin(a.expected.prepared, session, a.proof.parsed()?)?;
                let result = self
                    .service
                    .control
                    .approve_operation_reviewed(a.expected.prepared, &actual);
                gate.discard(a.expected.prepared, true);
                Ok(ProtocolResult::Run(result?))
            }
            AdminAction::RevokeChallenge(_) => {
                self.session()?;
                Ok(ProtocolResult::Challenge(gate.challenge(
                    Purpose::Revoke,
                    gate.context_digest(Purpose::Revoke)?,
                )?))
            }
            AdminAction::Revoke(proof) => {
                gate.stage_admin(0, self.session()?, proof.parsed()?)?;
                let result = self.service.control.revoke();
                gate.discard(0, true);
                result?;
                Ok(ProtocolResult::Revoked)
            }
        }
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
