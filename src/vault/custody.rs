//! Fixed-canary custody bootstrap with separately loaded broker, recipient and actor roles.
//!
//! No all-role kit is persisted or opened on this path. These ordinary fixture files
//! share the host's trust domain; they are not protected custody or human presence.
//! The bootstrap process temporarily generates every disposable key. Production
//! provisioning, real-secret entry and independent recovery remain unavailable.
//!
//! ```compile_fail
//! use aegis::vault::custody::ActorRole;
//! ```
//! ```compile_fail
//! use aegis::vault::custody::BrokerRole;
//! ```
use super::{
    auth::{ActorSigner, Enrollment, Purpose},
    crypto::{self, Identity, PrivateBytes, Signed, SigningKey, Verifier},
    model::DeliveryParameters,
    protocol::{ProofChallenge, ProtocolResponse, ProtocolResult, ReviewPlan, SyntheticProtocol},
    store::{self, BrokerMaterial, Recipient, RecipientMaterial, Store},
    VaultRecoveryReport,
};
use crate::{
    Clock, ErrorCode, Lifecycle, ManualClock, OperationIntent, OperationPrepareInput,
    OperationRunView, ProfileId, RequestId,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};
use zeroize::Zeroize;

const SCHEMA: u16 = 1;
const MAX_ROLE_DOCUMENT: usize = 16 * 1024;
const ROLE_FILE: &str = "custody.json";
const BROKER_KIND: &str = "aegis.synthetic.custody.broker.v1";
const RECIPIENT_KIND: &str = "aegis.synthetic.custody.recipient.v1";
const AGENT_KIND: &str = "aegis.synthetic.custody.agent.v1";
const ADMIN_KIND: &str = "aegis.synthetic.custody.admin.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerDocument {
    schema: u16,
    kind: String,
    vault_id: String,
    storage: String,
    writer: String,
    recipient_public: String,
    receipt_public: String,
    agent_public: String,
    admin_public: String,
}
impl Drop for BrokerDocument {
    fn drop(&mut self) {
        self.storage.zeroize();
        self.writer.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientDocument {
    schema: u16,
    kind: String,
    vault_id: String,
    recipient: String,
    receipt: String,
    writer_public: String,
}
impl Drop for RecipientDocument {
    fn drop(&mut self) {
        self.recipient.zeroize();
        self.receipt.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorDocument {
    schema: u16,
    kind: String,
    vault_id: String,
    signer: String,
}
impl Drop for ActorDocument {
    fn drop(&mut self) {
        self.signer.zeroize();
    }
}
fn validate_header(
    schema: u16,
    kind: &str,
    expected: &str,
    vault_id: &str,
) -> Result<(), ErrorCode> {
    if schema != SCHEMA || kind != expected || crypto::decode(vault_id, 32)?.0.len() != 32 {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}
fn key(encoded: &str) -> Result<Arc<SigningKey>, ErrorCode> {
    Ok(Arc::new(SigningKey::from_fixture_der(
        &crypto::decode(encoded, 4096)?.0,
    )?))
}
fn verifier(encoded: &str) -> Result<Verifier, ErrorCode> {
    Verifier::from_fixture_der(&crypto::decode(encoded, 1024)?.0)
}
fn identity(encoded: &str) -> Result<Arc<Identity>, ErrorCode> {
    Ok(Arc::new(Identity::fixture_parse(
        &crypto::decode(encoded, 256)?.0,
    )?))
}
fn write_role(path: &Path, document: &impl Serialize) -> Result<(), ErrorCode> {
    store::new_directory(path)?;
    let bytes =
        PrivateBytes(serde_json::to_vec(document).map_err(|_| ErrorCode::PersistenceUnavailable)?);
    if bytes.0.len() > MAX_ROLE_DOCUMENT {
        return Err(ErrorCode::CapacityExceeded);
    }
    store::write_new(&path.join(ROLE_FILE), &bytes.0)?;
    store::sync_directory(path)
}
fn read_role<T: DeserializeOwned>(path: &Path) -> Result<T, ErrorCode> {
    store::safe_directory(path)?;
    let bytes = PrivateBytes(store::read_file(&path.join(ROLE_FILE), MAX_ROLE_DOCUMENT)?);
    serde_json::from_slice(&bytes.0).map_err(|_| ErrorCode::PersistenceUnavailable)
}

/// Safe bootstrap observations; not evidence of separate operating-system identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CustodyBootstrapReport {
    pub synthetic_only: bool,
    /// Public fixture identity for role-bound loading, not a secret or authority.
    pub vault_id: String,
    pub role_documents: usize,
    pub all_role_kit_created: bool,
    pub protected_custody_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Generate disposable keys into a NEW directory with broker/recipient/agent/admin
/// children. The bootstrap temporarily owns all roles, returns no keys, and creates
/// no combined key file. Failed bootstrap leaves its partial destination for explicit
/// inspection; it never silently overwrites or repairs existing custody.
pub fn bootstrap_synthetic_custody(path: &Path) -> Result<CustodyBootstrapReport, ErrorCode> {
    store::new_directory(path)?;
    let vault_id = crypto::random_id()?;
    let storage = Identity::generate();
    let writer = SigningKey::generate()?;
    let recipient = Identity::generate();
    let receipt = SigningKey::generate()?;
    let agent = SigningKey::generate()?;
    let admin = SigningKey::generate()?;
    write_role(
        &path.join("broker"),
        &BrokerDocument {
            schema: SCHEMA,
            kind: BROKER_KIND.into(),
            vault_id: vault_id.clone(),
            storage: crypto::encode(&storage.fixture_encode().0),
            writer: crypto::encode(writer.fixture_der()),
            recipient_public: recipient.recipient().to_string(),
            receipt_public: crypto::encode(receipt.verifier().fixture_der()),
            agent_public: crypto::encode(agent.verifier().fixture_der()),
            admin_public: crypto::encode(admin.verifier().fixture_der()),
        },
    )?;
    write_role(
        &path.join("recipient"),
        &RecipientDocument {
            schema: SCHEMA,
            kind: RECIPIENT_KIND.into(),
            vault_id: vault_id.clone(),
            recipient: crypto::encode(&recipient.fixture_encode().0),
            receipt: crypto::encode(receipt.fixture_der()),
            writer_public: crypto::encode(writer.verifier().fixture_der()),
        },
    )?;
    for (role, kind, signer) in [("agent", AGENT_KIND, agent), ("admin", ADMIN_KIND, admin)] {
        write_role(
            &path.join(role),
            &ActorDocument {
                schema: SCHEMA,
                kind: kind.into(),
                vault_id: vault_id.clone(),
                signer: crypto::encode(signer.fixture_der()),
            },
        )?;
    }
    store::sync_directory(path)?;
    Ok(CustodyBootstrapReport {
        synthetic_only: true,
        vault_id,
        role_documents: 4,
        all_role_kit_created: false,
        protected_custody_verified: false,
        ready_for_real_keys: false,
    })
}

// A broker loader never takes an actor or recipient-private path. Its public
// enrollment is trusted fixture configuration, not caller-supplied wire authority.
pub(super) struct BrokerRole {
    pub(super) material: Arc<BrokerMaterial>,
    pub(super) enrollment: Enrollment,
}
impl BrokerRole {
    pub(super) fn open(path: &Path) -> Result<Self, ErrorCode> {
        let d: BrokerDocument = read_role(path)?;
        validate_header(d.schema, &d.kind, BROKER_KIND, &d.vault_id)?;
        let storage = identity(&d.storage)?;
        let writer = key(&d.writer)?;
        let recipient = d
            .recipient_public
            .parse()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let receipt = verifier(&d.receipt_public)?;
        let agent = verifier(&d.agent_public)?;
        let admin = verifier(&d.admin_public)?;
        let writer_public = writer.verifier();
        let signers = [&writer_public, &receipt, &agent, &admin];
        if storage.recipient() == recipient
            || signers
                .iter()
                .enumerate()
                .any(|(i, key)| signers[..i].iter().any(|other| key.same_key(other)))
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        Ok(Self {
            material: Arc::new(BrokerMaterial {
                vault_id: d.vault_id.clone(),
                storage,
                writer,
                recipient,
                receipt,
                directory: path.into(),
            }),
            enrollment: Enrollment::from_verifiers(agent, admin),
        })
    }
}
pub(super) fn open_recipient_role(path: &Path) -> Result<Arc<RecipientMaterial>, ErrorCode> {
    let d: RecipientDocument = read_role(path)?;
    validate_header(d.schema, &d.kind, RECIPIENT_KIND, &d.vault_id)?;
    Ok(Arc::new(RecipientMaterial {
        vault_id: d.vault_id.clone(),
        recipient: identity(&d.recipient)?,
        receipt: key(&d.receipt)?,
        writer: verifier(&d.writer_public)?,
    }))
}
pub(super) struct ActorRole {
    signer: ActorSigner,
}
impl ActorRole {
    pub(super) fn agent(custody: &Path, vault_id: &str) -> Result<Self, ErrorCode> {
        Self::open(&custody.join("agent"), AGENT_KIND, vault_id)
    }
    pub(super) fn admin(custody: &Path, vault_id: &str) -> Result<Self, ErrorCode> {
        Self::open(&custody.join("admin"), ADMIN_KIND, vault_id)
    }
    fn open(path: &Path, expected: &str, vault_id: &str) -> Result<Self, ErrorCode> {
        let d: ActorDocument = read_role(path)?;
        validate_header(d.schema, &d.kind, expected, &d.vault_id)?;
        if d.vault_id != vault_id {
            return Err(ErrorCode::AuthenticationRequired);
        }
        let key = key(&d.signer)?;
        let signer = match expected {
            AGENT_KIND => ActorSigner::agent(key),
            ADMIN_KIND => ActorSigner::admin(key),
            _ => return Err(ErrorCode::InvalidRequest),
        };
        Ok(Self { signer })
    }
    pub(super) fn proof(&self, challenge: &ProofChallenge) -> Result<Value, ErrorCode> {
        let signed = self.signer.sign(challenge)?;
        proof_value(&signed)
    }
    pub(super) fn reviewed_proof(
        &self,
        challenge: &ProofChallenge,
        expected: &ReviewPlan,
    ) -> Result<Value, ErrorCode> {
        if challenge.purpose != Purpose::Approve || challenge.digest != expected.digest()? {
            return Err(ErrorCode::ApprovalRequired);
        }
        self.proof(challenge)
    }
}
fn proof_value(signed: &Signed) -> Result<Value, ErrorCode> {
    Ok(
        json!({"assertion": std::str::from_utf8(signed.bytes()).map_err(|_| ErrorCode::InvalidRequest)?}),
    )
}

/// Create the existing fixed-canary protocol using two role-specific fixture paths.
/// Actor files are never opened. Both runtime roles still execute in this process.
/// This accepts no arbitrary secret or caller-supplied protected-deployment claim.
pub fn create_synthetic_protocol(
    root: &Path,
    broker_custody: &Path,
    recipient_custody: &Path,
    recipient_state: &Path,
    clock: Arc<dyn Clock>,
) -> Result<SyntheticProtocol, ErrorCode> {
    let broker = BrokerRole::open(broker_custody)?;
    let recipient_material = open_recipient_role(recipient_custody)?;
    // Check the full custody tuple before creating any vault/recipient state.
    check_roles(&broker.material, &recipient_material)?;
    let store = Store::create(root, broker.material)?;
    let recipient = Recipient::create(recipient_state, recipient_material)?;
    SyntheticProtocol::assemble(broker.enrollment, store, recipient, 1, clock)
}
/// Cold-start the same durable path without loading any actor signer or combined kit.
/// Sessions and executable approvals are never restored.
pub fn open_synthetic_protocol(
    root: &Path,
    broker_custody: &Path,
    recipient_custody: &Path,
    recipient_state: &Path,
    version: u64,
    clock: Arc<dyn Clock>,
) -> Result<SyntheticProtocol, ErrorCode> {
    let broker = BrokerRole::open(broker_custody)?;
    let recipient_material = open_recipient_role(recipient_custody)?;
    check_roles(&broker.material, &recipient_material)?;
    let store = Store::open(root, broker.material)?;
    let recipient = Recipient::open(recipient_state, recipient_material)?;
    SyntheticProtocol::assemble(broker.enrollment, store, recipient, version, clock)
}
fn check_roles(b: &BrokerMaterial, r: &RecipientMaterial) -> Result<(), ErrorCode> {
    b.check_recipient_material(r)
}
/// Inspect existing separated fixture paths with no actor signers and no authority
/// restoration. The anchor remains beside the broker's dummy custody on this host.
pub fn inspect_synthetic_custody(
    root: &Path,
    custody: &Path,
    recipient_state: &Path,
) -> Result<VaultRecoveryReport, ErrorCode> {
    let broker = BrokerRole::open(&custody.join("broker"))?;
    let recipient_material = open_recipient_role(&custody.join("recipient"))?;
    check_roles(&broker.material, &recipient_material)?;
    let store = Store::open(root, broker.material)?;
    let recipient = Recipient::open(recipient_state, recipient_material)?;
    store.check_recipient(&recipient)?;
    let (consumed, incomplete, unknown, remaining, revoked) = store.history_counts()?;
    Ok(VaultRecoveryReport {
        synthetic_only: true,
        consumed_uses: consumed,
        incomplete_deliveries: incomplete,
        unknown_deliveries: unknown,
        remaining_uses: remaining,
        recipient_generation: recipient.generation()?,
        revoked,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        protected_anchor_verified: false,
        ready_for_real_keys: false,
    })
}

/// Closed observations from actual separated-file loading and the durable protocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CustodyDrillReport {
    pub synthetic_only: bool,
    pub separate_role_documents: usize,
    pub all_role_kit_created: bool,
    pub wrong_role_signing_denied: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub changed_review_denied: bool,
    pub completed_deliveries: usize,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub previous_request_id_denied: bool,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revocation_survived_restart: bool,
    pub delivery_responses_contain_canary: bool,
    pub restored_sessions: usize,
    pub independent_human_presence_verified: bool,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}
fn frame(method: &str, params: impl Serialize) -> Result<PrivateBytes, ErrorCode> {
    serde_json::to_vec(&json!({
        "protocol": super::protocol::PROTOCOL,
        "version": super::protocol::VERSION,
        "action": { "method": method, "params": params }
    }))
    .map(PrivateBytes)
    .map_err(|_| ErrorCode::InvalidRequest)
}
fn challenge(response: ProtocolResponse) -> Result<ProofChallenge, ErrorCode> {
    if let Some(ProtocolResult::Challenge(c)) = response.result {
        Ok(c)
    } else {
        Err(response.error.unwrap_or(ErrorCode::BrokerUnavailable))
    }
}
fn review(response: ProtocolResponse) -> Result<ReviewPlan, ErrorCode> {
    if let Some(ProtocolResult::Review(r)) = response.result {
        Ok(*r)
    } else {
        Err(response.error.unwrap_or(ErrorCode::BrokerUnavailable))
    }
}
fn run(response: ProtocolResponse) -> Result<OperationRunView, ErrorCode> {
    if let Some(ProtocolResult::Run(r)) = response.result {
        Ok(r)
    } else {
        Err(response.error.unwrap_or(ErrorCode::BrokerUnavailable))
    }
}
fn connect(p: &SyntheticProtocol, agent: &ActorRole, admin: &ActorRole) -> Result<(), ErrorCode> {
    let a = challenge(p.agent.handle(&frame("connect_challenge", json!({}))?.0))?;
    let h = challenge(p.admin.handle(&frame("connect_challenge", json!({}))?.0))?;
    for response in [
        p.agent.handle(&frame("connect", agent.proof(&a)?)?.0),
        p.admin.handle(&frame("connect", admin.proof(&h)?)?.0),
    ] {
        if !matches!(response.result, Some(ProtocolResult::Connected)) {
            return Err(response.error.unwrap_or(ErrorCode::BrokerUnavailable));
        }
    }
    Ok(())
}
fn prepare_input(id: &str, version: u64) -> Result<OperationPrepareInput, ErrorCode> {
    Ok(OperationPrepareInput {
        request_id: RequestId::new(id)?,
        profile_id: ProfileId::new("vault-delivery")?,
        operation: OperationIntent::Delivery(DeliveryParameters::fixture(version)),
    })
}
fn prepare(p: &SyntheticProtocol, id: &str, version: u64) -> Result<u64, ErrorCode> {
    let prepared = run(p
        .agent
        .handle(&frame("prepare_operation", prepare_input(id, version)?)?.0))?;
    let id = prepared.prepared_request_id;
    let awaiting = run(p
        .agent
        .handle(&frame("request_approval", json!({"prepared_request_id":id}))?.0))?;
    if awaiting.state != Lifecycle::AwaitingApproval {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(id)
}
fn approve(p: &SyntheticProtocol, admin: &ActorRole, id: u64) -> Result<(), ErrorCode> {
    let expected = review(
        p.admin
            .handle(&frame("inspect_review", json!({"prepared_request_id":id}))?.0),
    )?;
    let c = challenge(p.admin.handle(&frame("approval_challenge", &expected)?.0))?;
    let proof = admin.reviewed_proof(&c, &expected)?;
    let approved = run(p
        .admin
        .handle(&frame("approve", json!({"expected":expected,"proof":proof}))?.0))?;
    if approved.state != Lifecycle::Approved {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(())
}
fn invocation(
    p: &SyntheticProtocol,
    agent: &ActorRole,
    id: u64,
) -> Result<PrivateBytes, ErrorCode> {
    let c = challenge(
        p.agent
            .handle(&frame("invocation_challenge", json!({"prepared_request_id":id}))?.0),
    )?;
    frame(
        "invoke_approved",
        json!({"prepared_request_id":id,"proof":agent.proof(&c)?}),
    )
}

/// Simulated actor ceremony for the fixed process drill. Runtime constructors
/// never load these signers and this helper never opens recipient custody.
pub(super) fn process_fixture_round(
    p: &SyntheticProtocol,
    custody: &Path,
    vault_id: &str,
    version: u64,
) -> Result<(OperationRunView, bool, bool), ErrorCode> {
    let unauthenticated_denied = p
        .agent
        .handle(
            &frame(
                "prepare_operation",
                prepare_input("process-before-auth", version)?,
            )?
            .0,
        )
        .error
        == Some(ErrorCode::AuthenticationRequired);
    let agent = ActorRole::open(&custody.join("agent"), AGENT_KIND, vault_id)?;
    let admin = ActorRole::open(&custody.join("admin"), ADMIN_KIND, vault_id)?;
    connect(p, &agent, &admin)?;
    let id = prepare(
        p,
        if version == 1 {
            "process-install"
        } else {
            "process-rotate"
        },
        version,
    )?;
    approve(p, &admin, id)?;
    let input = invocation(p, &agent, id)?;
    let first = run(p.agent.handle(&input.0))?;
    let duplicate_reused = run(p.agent.handle(&input.0))? == first;
    Ok((first, duplicate_reused, unauthenticated_denied))
}

pub(super) fn process_fixture_revoke(
    p: &SyntheticProtocol,
    custody: &Path,
    vault_id: &str,
) -> Result<(), ErrorCode> {
    let admin = ActorRole::open(&custody.join("admin"), ADMIN_KIND, vault_id)?;
    let c = challenge(p.admin.handle(&frame("revoke_challenge", json!({}))?.0))?;
    if matches!(
        p.admin.handle(&frame("revoke", admin.proof(&c)?)?.0).result,
        Some(ProtocolResult::Revoked)
    ) {
        Ok(())
    } else {
        Err(ErrorCode::BrokerUnavailable)
    }
}

/// Bootstrap NEW dummy custody/state, deliver, cold-start and rotate, then durably
/// revoke. Actor signing is simulated using its own file; this is not a human UI.
/// All deliveries use the existing authenticated protocol and durable core path.
pub fn run_synthetic_custody_drill(
    root: &Path,
    custody: &Path,
    recipient_state: &Path,
) -> Result<CustodyDrillReport, ErrorCode> {
    let bootstrap = bootstrap_synthetic_custody(custody)?;
    let clock = Arc::new(ManualClock::default());
    let p = create_synthetic_protocol(
        root,
        &custody.join("broker"),
        &custody.join("recipient"),
        recipient_state,
        clock.clone(),
    )?;
    // These actors are loaded separately AFTER runtime assembly. Neither is retained
    // by the protocol; no runtime constructor reads these paths or a combined kit.
    let vault_id = &bootstrap.vault_id;
    let agent = ActorRole::open(&custody.join("agent"), AGENT_KIND, vault_id)?;
    let admin = ActorRole::open(&custody.join("admin"), ADMIN_KIND, vault_id)?;
    let a = challenge(p.agent.handle(&frame("connect_challenge", json!({}))?.0))?;
    let h = challenge(p.admin.handle(&frame("connect_challenge", json!({}))?.0))?;
    let wrong_role_signing_denied = agent.proof(&h).is_err() && admin.proof(&a).is_err();
    let unauthenticated_agent_denied = p
        .agent
        .handle(&frame("prepare_operation", prepare_input("before-auth", 1)?)?.0)
        .error
        == Some(ErrorCode::AuthenticationRequired);
    let unauthenticated_admin_denied = p
        .admin
        .handle(&frame("revoke_challenge", json!({}))?.0)
        .error
        == Some(ErrorCode::AuthenticationRequired);
    connect(&p, &agent, &admin)?;
    let id = prepare(&p, "custody-install", 1)?;
    let expected = review(
        p.admin
            .handle(&frame("inspect_review", json!({"prepared_request_id":id}))?.0),
    )?;
    let c = challenge(p.admin.handle(&frame("approval_challenge", &expected)?.0))?;
    let mut changed = expected.clone();
    changed.operation.repository_id += 1;
    let changed_review_denied = admin.reviewed_proof(&c, &changed).is_err()
        && p.admin
            .handle(
                &frame(
                    "approve",
                    json!({"expected":changed,"proof":admin.reviewed_proof(&c,&expected)?}),
                )?
                .0,
            )
            .error
            == Some(ErrorCode::ApprovalRequired);
    approve(&p, &admin, id)?;
    let input = invocation(&p, &agent, id)?;
    let first = p.agent.handle(&input.0);
    let mut transcript = serde_json::to_string(&first).map_err(|_| ErrorCode::BrokerUnavailable)?;
    let first = run(first)?;
    let duplicate_reused = run(p.agent.handle(&input.0))? == first;
    if first.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }
    drop(p);
    drop(agent);
    drop(admin);
    let p = open_synthetic_protocol(
        root,
        &custody.join("broker"),
        &custody.join("recipient"),
        recipient_state,
        2,
        clock.clone(),
    )?;
    let cold_start_required_authentication = p
        .agent
        .handle(&frame("prepare_operation", prepare_input("cold-before-auth", 2)?)?.0)
        .error
        == Some(ErrorCode::AuthenticationRequired)
        && p.admin
            .handle(&frame("revoke_challenge", json!({}))?.0)
            .error
            == Some(ErrorCode::AuthenticationRequired);
    let agent = ActorRole::open(&custody.join("agent"), AGENT_KIND, vault_id)?;
    let admin = ActorRole::open(&custody.join("admin"), ADMIN_KIND, vault_id)?;
    connect(&p, &agent, &admin)?;
    let previous_request_id_denied = p
        .agent
        .handle(&frame("prepare_operation", prepare_input("custody-install", 2)?)?.0)
        .error
        == Some(ErrorCode::RequestIdConflict);
    let id = prepare(&p, "custody-rotate", 2)?;
    approve(&p, &admin, id)?;
    let second = p.agent.handle(&invocation(&p, &agent, id)?.0);
    transcript.push_str(&serde_json::to_string(&second).map_err(|_| ErrorCode::BrokerUnavailable)?);
    if run(second)?.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let c = challenge(p.admin.handle(&frame("revoke_challenge", json!({}))?.0))?;
    if !matches!(
        p.admin.handle(&frame("revoke", admin.proof(&c)?)?.0).result,
        Some(ProtocolResult::Revoked)
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    drop(p);
    drop(agent);
    drop(admin);
    let inspected = inspect_synthetic_custody(root, custody, recipient_state)?;
    let revocation_survived_restart = inspected.revoked
        && matches!(
            open_synthetic_protocol(
                root,
                &custody.join("broker"),
                &custody.join("recipient"),
                recipient_state,
                2,
                clock,
            ),
            Err(ErrorCode::GrantRevoked)
        );
    let delivery_responses_contain_canary =
        transcript.contains(store::CANARY_ONE) || transcript.contains(store::CANARY_TWO);
    if !(wrong_role_signing_denied
        && unauthenticated_agent_denied
        && unauthenticated_admin_denied
        && changed_review_denied
        && duplicate_reused
        && cold_start_required_authentication
        && previous_request_id_denied
        && revocation_survived_restart
        && !delivery_responses_contain_canary
        && inspected.consumed_uses == 2
        && inspected.remaining_uses == 2
        && inspected.recipient_generation == 2
        && inspected.incomplete_deliveries == 0
        && inspected.unknown_deliveries == 0)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(CustodyDrillReport {
        synthetic_only: true,
        separate_role_documents: bootstrap.role_documents,
        all_role_kit_created: bootstrap.all_role_kit_created,
        wrong_role_signing_denied,
        unauthenticated_agent_denied,
        unauthenticated_admin_denied,
        changed_review_denied,
        completed_deliveries: 2,
        duplicate_reused,
        cold_start_required_authentication,
        previous_request_id_denied,
        consumed_uses: inspected.consumed_uses,
        remaining_uses: inspected.remaining_uses,
        recipient_generation: inspected.recipient_generation,
        revocation_survived_restart,
        delivery_responses_contain_canary,
        restored_sessions: 0,
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
