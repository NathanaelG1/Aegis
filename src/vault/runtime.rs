use super::{
    auth::{self, Challenge, Gate, Purpose, Receipt, Review, AGENT},
    crypto::Signed,
    model::*,
    process_recipient::RecipientEndpoint,
    store::{Kit, Recipient, Store},
};
use crate::{
    broker::{AuthorizedDispatch, Clock},
    *,
};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};
struct Work {
    review: Review,
    request_id: RequestId,
    remaining_before: u32,
    reserved_at: u64,
}
/// Private adapter. Agent and admin proof hooks run inside the main core lock.
pub(crate) struct Adapter {
    pub(super) store: Arc<Store>,
    pub(super) recipient: RecipientEndpoint,
    pub(super) gate: Gate,
    profile: DeliveryProfile,
    clock: Arc<dyn Clock>,
    verified: Mutex<BTreeMap<u64, Receipt>>,
    pending: Mutex<BTreeMap<u64, Work>>,
    revoke_proof: Mutex<Option<Receipt>>,
}
impl Adapter {
    fn new(
        instance: [u8; 16],
        profile: DeliveryProfile,
        clock: Arc<dyn Clock>,
        store: Arc<Store>,
        recipient: RecipientEndpoint,
        enrollment: &auth::Enrollment,
    ) -> Result<Self, ErrorCode> {
        store.ready()?;
        recipient.check_store(&store)?;
        Ok(Self {
            gate: Gate::new(instance, profile.clone(), clock.clone(), enrollment)?,
            profile,
            clock,
            store,
            recipient,
            verified: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            revoke_proof: Mutex::new(None),
        })
    }
    pub(crate) fn authenticate_agent(
        &self,
        session: Option<&Arc<auth::AuthenticatedSession>>,
    ) -> Result<(), ErrorCode> {
        self.gate.check_agent(session)?;
        if !self
            .store
            .permits(&PrincipalId::new(AGENT).expect("constant"), &self.profile)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(())
    }
    pub(crate) fn authorize_prepare(&self, input: &OperationPrepareInput) -> Result<(), ErrorCode> {
        self.gate.check_active()?;
        let OperationIntent::Delivery(parameters) = &input.operation else {
            return Err(ErrorCode::ScopeDenied);
        };
        if input.profile_id != self.profile.id || !self.profile.permits(parameters) {
            return Err(ErrorCode::ScopeDenied);
        }
        self.store.ensure_new(&input.request_id)?;
        if self.recipient.generation() != Ok(parameters.expected_generation) {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(())
    }
    pub(crate) fn authorize_approval(&self, view: &OperationApprovalView) -> Result<(), ErrorCode> {
        let review = Review::of(view)?;
        if review.profile != self.profile || !self.store.permits(&review.principal, &self.profile) {
            return Err(ErrorCode::ScopeDenied);
        }
        let proof = self.gate.approval(view)?;
        self.store.approve(review, proof, self.clock.now())
    }
    pub(crate) fn authorize_dispatch(&self, d: &AuthorizedDispatch) -> Result<(), ErrorCode> {
        self.gate.check_active()?;
        let review = Review::of(&d.approval)?;
        if review.profile != self.profile
            || !self.profile.permits(&review.operation)
            || !self.store.permits(&review.principal, &self.profile)
            || d.request_id != view_id(&d.approval)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        self.store.ensure_new(&d.request_id)?;
        if self.recipient.generation() != Ok(review.operation.expected_generation) {
            return Err(ErrorCode::ScopeDenied);
        }
        let receipt = self.gate.dispatch(d)?;
        self.store.begin_reservation(&review, d.remaining_before)?;
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if verified
            .insert(d.approval.prepared_request_id, receipt)
            .is_some()
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        Ok(())
    }
    pub(crate) fn reserve(&self, d: &AuthorizedDispatch) -> Result<(), ErrorCode> {
        let receipt = self
            .verified
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .remove(&d.approval.prepared_request_id)
            .ok_or(ErrorCode::AuthenticationRequired)?;
        if receipt.digest != auth::dispatch_digest(d)? {
            return Err(ErrorCode::AuthenticationRequired);
        }
        let review = Review::of(&d.approval)?;
        self.store
            .reserve(review.clone(), receipt, d.remaining_before, d.reserved_at)?;
        let work = Work {
            review,
            request_id: d.request_id.clone(),
            remaining_before: d.remaining_before,
            reserved_at: d.reserved_at,
        };
        if self
            .pending
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .insert(d.approval.prepared_request_id, work)
            .is_some()
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        Ok(())
    }
    pub(crate) fn execute(&self, d: &AuthorizedDispatch) -> Result<DeliveryProjection, ErrorCode> {
        let work = self
            .pending
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .remove(&d.approval.prepared_request_id)
            .ok_or(ErrorCode::OutcomeUnknown)?;
        if work.review != Review::of(&d.approval)?
            || work.request_id != d.request_id
            || work.remaining_before != d.remaining_before
            || work.reserved_at != d.reserved_at
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        self.recipient
            .deliver(&self.store, &d.request_id, self.clock.now())
    }
    pub(crate) fn authorize_revoke(&self) -> Result<(), ErrorCode> {
        let proof = self.gate.authorize_revoke()?;
        self.store.begin_revocation(&proof)?;
        let mut slot = self
            .revoke_proof
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if slot.is_some() {
            return Err(ErrorCode::AuthenticationRequired);
        }
        *slot = Some(proof);
        Ok(())
    }
    pub(crate) fn revoke(&self) -> Result<(), ErrorCode> {
        let proof = self
            .revoke_proof
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?
            .take()
            .ok_or(ErrorCode::AuthenticationRequired)?;
        let result = self.store.revoke(proof, self.clock.now());
        self.gate.revoke();
        result
    }
    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.store.blocked()
    }
}
fn view_id(v: &OperationApprovalView) -> RequestId {
    v.request_id.clone()
}
/// Test host owns control/signers separately from the agent handle. No public constructor
/// accepts real credentials or an assertion that deployment protection is available.
pub(super) struct AgentSlot {
    initial: AgentClient,
    authenticated: std::sync::OnceLock<AgentClient>,
}
impl std::ops::Deref for AgentSlot {
    type Target = AgentClient;
    fn deref(&self) -> &AgentClient {
        self.authenticated.get().unwrap_or(&self.initial)
    }
}
impl AgentSlot {
    fn bind(&self, session: Arc<auth::AuthenticatedSession>) -> Result<(), ErrorCode> {
        self.authenticated
            .set(self.initial.with_vault_session(session))
            .map_err(|_| ErrorCode::AuthenticationRequired)
    }
}
pub(super) struct Host {
    pub control: Arc<Control>,
    pub agent: AgentSlot,
    pub adapter: Arc<Adapter>,
    pub kit: Arc<Kit>,
    admin: std::sync::OnceLock<Arc<auth::AdminSession>>,
}
impl Host {
    pub fn create(
        root: &Path,
        kit_path: &Path,
        recipient_path: &Path,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let kit = Kit::create(kit_path)?;
        let store = Store::create(root, kit.broker_material())?;
        let recipient = Recipient::create(recipient_path, kit.recipient_material())?;
        Self::compose(kit, store, recipient, 1, clock)
    }
    pub fn open(
        root: &Path,
        kit_path: &Path,
        recipient_path: &Path,
        version: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let kit = Kit::open(kit_path)?;
        let store = Store::open(root, kit.broker_material())?;
        let recipient = Recipient::open(recipient_path, kit.recipient_material())?;
        Self::compose(kit, store, recipient, version, clock)
    }
    pub(super) fn compose(
        kit: Arc<Kit>,
        store: Arc<Store>,
        recipient: Arc<Recipient>,
        version: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ErrorCode> {
        let (control, agent, adapter) =
            assemble_runtime(kit.actors.enrollment(), store, recipient, version, clock)?;
        Ok(Self {
            control,
            agent: AgentSlot {
                initial: agent,
                authenticated: std::sync::OnceLock::new(),
            },
            adapter,
            kit,
            admin: std::sync::OnceLock::new(),
        })
    }
    pub fn connect(&self) -> Result<(), ErrorCode> {
        let c = self.adapter.gate.challenge(
            Purpose::Connect,
            self.adapter.gate.context_digest(Purpose::Connect)?,
        )?;
        let session = self.adapter.gate.connect(self.kit.actors.sign(&c)?)?;
        self.agent.bind(session)?;
        let c = self.adapter.gate.challenge(
            Purpose::AdminConnect,
            self.adapter.gate.context_digest(Purpose::AdminConnect)?,
        )?;
        let session = self.adapter.gate.connect_admin(self.kit.actors.sign(&c)?)?;
        self.admin
            .set(session)
            .map_err(|_| ErrorCode::AuthenticationRequired)
    }
    pub fn prepare(&self, id: &str, version: u64) -> Result<u64, ErrorCode> {
        self.agent
            .prepare_operation(OperationPrepareInput {
                request_id: RequestId::new(id)?,
                profile_id: ProfileId::new("vault-delivery")?,
                operation: OperationIntent::Delivery(DeliveryParameters::fixture(version)),
            })
            .map(|v| v.prepared_request_id)
    }
    pub fn approval_challenge(&self, id: u64) -> Result<Challenge, ErrorCode> {
        let view = self.control.inspect_operation_approval(id)?;
        self.adapter
            .gate
            .challenge(Purpose::Approve, Review::of(&view)?.digest()?)
    }
    pub fn approve(&self, id: u64, proof: Signed) -> Result<(), ErrorCode> {
        let view = self.control.inspect_operation_approval(id)?;
        self.adapter.gate.stage_admin(
            id,
            self.admin
                .get()
                .cloned()
                .ok_or(ErrorCode::AuthenticationRequired)?,
            proof,
        )?;
        let result = self
            .control
            .approve_operation_reviewed(id, &view)
            .map(|_| ());
        self.adapter.gate.discard(id, true);
        result
    }
    pub fn invocation_challenge(&self, id: u64) -> Result<Challenge, ErrorCode> {
        let d = self.control.delivery_context(id)?;
        self.adapter
            .gate
            .challenge(Purpose::Invoke, auth::dispatch_digest(&d)?)
    }
    pub fn invoke(&self, id: u64, proof: Signed) -> Result<OperationRunView, ErrorCode> {
        self.adapter.gate.stage_agent(id, proof)?;
        let result = self.agent.invoke_operation(id);
        self.adapter.gate.discard(id, false);
        result
    }
    pub fn reviewed_invoke(&self, id: u64) -> Result<OperationRunView, ErrorCode> {
        self.agent.request_operation_approval(id)?;
        self.approve(id, self.kit.actors.sign(&self.approval_challenge(id)?)?)?;
        self.invoke(id, self.kit.actors.sign(&self.invocation_challenge(id)?)?)
    }
    pub fn revoke(&self) -> Result<(), ErrorCode> {
        let c = self.adapter.gate.challenge(
            Purpose::Revoke,
            self.adapter.gate.context_digest(Purpose::Revoke)?,
        )?;
        self.adapter.gate.stage_admin(
            0,
            self.admin
                .get()
                .cloned()
                .ok_or(ErrorCode::AuthenticationRequired)?,
            self.kit.actors.sign(&c)?,
        )?;
        let result = self.control.revoke();
        self.adapter.gate.discard(0, true);
        result
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.control.stop();
        self.adapter.gate.revoke();
    }
}

/// Runtime assembly has no actor signing keys or all-role fixture kit.
pub(super) fn assemble_runtime(
    enrollment: auth::Enrollment,
    store: Arc<Store>,
    recipient: impl Into<RecipientEndpoint>,
    version: u64,
    clock: Arc<dyn Clock>,
) -> Result<(Arc<Control>, AgentClient, Arc<Adapter>), ErrorCode> {
    let recipient = recipient.into();
    if !matches!(version, 1 | 2) {
        return Err(ErrorCode::InvalidRequest);
    }
    store.ready()?;
    let profile = DeliveryProfile::fixture(version);
    let setup = OperationSetup {
        principal: PrincipalId::new(AGENT).expect("constant"),
        profile: OperationProfile::Delivery(profile.clone()),
        approval_mode: ApprovalMode::EachRequest,
        uses: store.remaining()?,
        idle_seconds: 600,
        maximum_seconds: 1800,
        request_seconds: 15,
        maximum_requests: 32,
        maximum_concurrent: 1,
    };
    let mut saved = None;
    let adapter_clock = clock.clone();
    let (control, agent) = Control::build_delivery(setup, clock, |instance, _, _| {
        let adapter = Arc::new(Adapter::new(
            instance,
            profile,
            adapter_clock,
            store,
            recipient,
            &enrollment,
        )?);
        saved = Some(adapter.clone());
        Ok(adapter)
    })?;
    Ok((Arc::new(control), agent, saved.expect("built adapter")))
}
