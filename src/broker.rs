//! Single-process serialization of authorization, reservation, and revocation.
use crate::fake::{Dispatch, Executor, ProviderOutcome};
use crate::types::*;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};
use std::time::Instant;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
pub struct MonotonicClock(Instant);
impl Default for MonotonicClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Clock for MonotonicClock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_secs()
    }
}
#[derive(Default)]
pub struct ManualClock(AtomicU64);
impl ManualClock {
    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}
impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Host-selected frozen grant. No caller-provided principal is accepted on the agent wire.
#[derive(Clone, Debug)]
pub struct SyntheticSetup {
    pub principal: PrincipalId,
    pub profile: Profile,
    pub approval_mode: ApprovalMode,
    pub uses: u32,
    pub idle_seconds: u64,
    pub maximum_seconds: u64,
    pub request_seconds: u64,
    pub maximum_requests: usize,
    pub maximum_concurrent: usize,
}
impl Default for SyntheticSetup {
    fn default() -> Self {
        Self {
            principal: PrincipalId::new("synthetic-host").expect("constant"),
            profile: Profile::synthetic(),
            approval_mode: ApprovalMode::EachRequest,
            uses: 20,
            idle_seconds: 600,
            maximum_seconds: 1800,
            request_seconds: 15,
            maximum_requests: 128,
            maximum_concurrent: 4,
        }
    }
}

/// Trusted synthetic V2 setup. GitHub accepts only its fixed profile, reviewed-per-request
/// approval, one flight, and at most 32 retained requests/uses.
#[derive(Clone, Debug)]
pub struct OperationSetup {
    pub principal: PrincipalId,
    pub profile: OperationProfile,
    pub approval_mode: ApprovalMode,
    pub uses: u32,
    pub idle_seconds: u64,
    pub maximum_seconds: u64,
    pub request_seconds: u64,
    pub maximum_requests: usize,
    pub maximum_concurrent: usize,
}
impl From<SyntheticSetup> for OperationSetup {
    fn from(s: SyntheticSetup) -> Self {
        Self {
            principal: s.principal,
            profile: OperationProfile::IssueStatus(s.profile),
            approval_mode: s.approval_mode,
            uses: s.uses,
            idle_seconds: s.idle_seconds,
            maximum_seconds: s.maximum_seconds,
            request_seconds: s.request_seconds,
            maximum_requests: s.maximum_requests,
            maximum_concurrent: s.maximum_concurrent,
        }
    }
}
impl OperationSetup {
    fn limits(&self) -> OperationLimits {
        OperationLimits {
            initial_uses: self.uses,
            idle_seconds: self.idle_seconds,
            maximum_seconds: self.maximum_seconds,
            request_seconds: self.request_seconds,
            maximum_requests: self.maximum_requests,
            maximum_concurrent: self.maximum_concurrent,
        }
    }
    pub fn synthetic_github() -> Self {
        let mut setup: Self = SyntheticSetup::default().into();
        setup.profile = OperationProfile::GithubMetadata(GithubProfile::synthetic());
        setup.maximum_requests = 32;
        setup.maximum_concurrent = 1;
        setup
    }
}
/// Created only after core approval checks. Not Clone, Deserialize, Serialize or public.
pub(crate) struct AuthorizedDispatch {
    pub(crate) approval: OperationApprovalView,
    pub(crate) request_id: RequestId,
    pub(crate) reserved_at: u64,
    pub(crate) remaining_before: u32,
}
enum ExecutorKind {
    Issue(Arc<dyn Executor>),
    #[cfg(unix)]
    Github(Arc<crate::github::BrokerAdapter>),
    #[cfg(all(unix, feature = "vault-spike"))]
    Delivery(Arc<crate::vault::Adapter>),
}
impl ExecutorKind {
    fn authenticate_agent(&self, client: &AgentClient) -> Result<(), ErrorCode> {
        #[cfg(all(unix, feature = "vault-spike"))]
        if let Self::Delivery(adapter) = self {
            return adapter.authenticate_agent(client.vault_session.as_ref());
        }
        let _ = client;
        Ok(())
    }
    fn authorize_prepare(&self, input: &OperationPrepareInput) -> Result<(), ErrorCode> {
        #[cfg(all(unix, feature = "vault-spike"))]
        if let Self::Delivery(adapter) = self {
            return adapter.authorize_prepare(input);
        }
        let _ = input;
        Ok(())
    }
    fn authorize_approval(&self, view: &OperationApprovalView) -> Result<(), ErrorCode> {
        #[cfg(all(unix, feature = "vault-spike"))]
        if let Self::Delivery(adapter) = self {
            return adapter.authorize_approval(view);
        }
        let _ = view;
        Ok(())
    }
    fn authorize_dispatch(&self, dispatch: &AuthorizedDispatch) -> Result<(), ErrorCode> {
        #[cfg(all(unix, feature = "vault-spike"))]
        if let Self::Delivery(adapter) = self {
            return adapter.authorize_dispatch(dispatch);
        }
        let _ = dispatch;
        Ok(())
    }
    fn authorize_revoke(&self) -> Result<(), ErrorCode> {
        #[cfg(all(unix, feature = "vault-spike"))]
        if let Self::Delivery(adapter) = self {
            return adapter.authorize_revoke();
        }
        Ok(())
    }

    fn reserve(&self, dispatch: &AuthorizedDispatch) -> Result<(), ErrorCode> {
        match self {
            Self::Issue(_)
                if matches!(dispatch.approval.profile, OperationProfile::IssueStatus(_)) =>
            {
                Ok(())
            }
            #[cfg(unix)]
            Self::Github(adapter) => adapter.reserve(dispatch),
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(adapter) => adapter.reserve(dispatch),
            _ => Err(ErrorCode::ScopeDenied),
        }
    }
    fn execute(&self, dispatch: &AuthorizedDispatch) -> Result<OperationResult, ErrorCode> {
        match (
            self,
            &dispatch.approval.profile,
            &dispatch.approval.operation,
        ) {
            (
                Self::Issue(executor),
                OperationProfile::IssueStatus(profile),
                OperationIntent::IssueStatus(parameters),
            ) => {
                match executor.execute(&Dispatch {
                    profile: profile.clone(),
                    parameters: parameters.clone(),
                }) {
                    ProviderOutcome::Status(raw)
                        if raw.repository_id == parameters.repository_id
                            && raw.issue_number == parameters.issue_number
                            && matches!(raw.state.as_str(), "open" | "closed") =>
                    {
                        Ok(OperationResult::IssueStatus(StatusProjection {
                            repository_id: raw.repository_id,
                            issue_number: raw.issue_number,
                            state: if raw.state == "open" {
                                IssueState::Open
                            } else {
                                IssueState::Closed
                            },
                        }))
                    }
                    ProviderOutcome::Status(_) => Err(ErrorCode::InvalidProviderResult),
                    ProviderOutcome::Unavailable => Err(ErrorCode::ProviderUnavailable),
                    ProviderOutcome::Unknown => Err(ErrorCode::OutcomeUnknown),
                }
            }
            #[cfg(unix)]
            (
                Self::Github(adapter),
                OperationProfile::GithubMetadata(_),
                OperationIntent::GithubMetadata(_),
            ) => adapter
                .execute(dispatch)
                .map(OperationResult::GithubMetadata),
            #[cfg(all(unix, feature = "vault-spike"))]
            (
                Self::Delivery(adapter),
                OperationProfile::Delivery(_),
                OperationIntent::Delivery(_),
            ) => adapter.execute(dispatch).map(OperationResult::Delivery),
            _ => Err(ErrorCode::ScopeDenied),
        }
    }
    fn requires_reconciliation(&self) -> bool {
        match self {
            Self::Issue(_) => false,
            #[cfg(unix)]
            Self::Github(adapter) => adapter.requires_reconciliation(),
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(adapter) => adapter.requires_reconciliation(),
        }
    }
    fn revoke(&self) -> Result<(), ErrorCode> {
        match self {
            Self::Issue(_) => Ok(()),
            #[cfg(unix)]
            Self::Github(adapter) => adapter.revoke(),
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(adapter) => adapter.revoke(),
        }
    }
}
fn validate_outcome(
    result: Result<OperationResult, ErrorCode>,
    view: &OperationApprovalView,
) -> Result<OperationResult, ErrorCode> {
    match result {
        Ok(OperationResult::IssueStatus(ref result)) if matches!(&view.operation,OperationIntent::IssueStatus(parameters) if parameters.repository_id==result.repository_id && parameters.issue_number==result.issue_number) => {
            Ok(OperationResult::IssueStatus(result.clone()))
        }
        Ok(OperationResult::GithubMetadata(ref result)) if matches!(&view.operation,OperationIntent::GithubMetadata(parameters) if parameters.repository_id==result.repository_id) => {
            Ok(OperationResult::GithubMetadata(result.clone()))
        }
        #[cfg(all(unix, feature = "vault-spike"))]
        Ok(OperationResult::Delivery(ref result)) if matches!(&view.operation,OperationIntent::Delivery(parameters) if result.matches(&view.request_id,parameters)) => {
            Ok(OperationResult::Delivery(result.clone()))
        }
        Ok(_) => Err(ErrorCode::InvalidProviderResult),
        Err(error) => Err(error),
    }
}
fn ensure_issue(state: &State, id: u64) -> Result<(), ErrorCode> {
    match state.requests.get(&id) {
        Some(request) if !matches!(request.profile, OperationProfile::IssueStatus(_)) => {
            Err(ErrorCode::ScopeDenied)
        }
        // Preserve the original session-check-before-missing-handle precedence.
        _ => Ok(()),
    }
}

struct Request {
    input: OperationPrepareInput,
    profile: OperationProfile,
    reviewed: Option<OperationApprovalView>,
    generation: u64,
    expires_at: u64,
    session: u64,
    view: OperationRunView,
}
struct State {
    instance: [u8; 16],
    setup: OperationSetup,
    current_profile: OperationProfile,
    generation: u64,
    grant_generation: u64,
    session: u64,
    started_at: u64,
    last_success: u64,
    last_observed: u64,
    stopped: bool,
    revoked: bool,
    uncertain: bool,
    remaining: u32,
    in_flight: usize,
    next_id: u64,
    requests: BTreeMap<u64, Request>,
    dedup: BTreeMap<RequestId, u64>,
}
struct Shared {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    executor: ExecutorKind,
}

/// Trusted administrative capability. Never serialized or returned through the agent protocol.
pub struct Control {
    shared: Arc<Shared>,
}
/// A connection bound by its trusted host. Clone keeps the same principal/session.
#[derive(Clone)]
pub struct AgentClient {
    shared: Arc<Shared>,
    session: u64,
    #[cfg(all(unix, feature = "vault-spike"))]
    vault_session: Option<Arc<crate::vault::AuthenticatedSession>>,
}

impl Shared {
    fn lock(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        self.state.lock().map_err(|_| ErrorCode::BrokerUnavailable)
    }
    fn check(&self, state: &mut State, session: u64) -> Result<u64, ErrorCode> {
        if session != state.session {
            return Err(ErrorCode::PrincipalMismatch);
        }
        let now = self.clock.now();
        if now < state.last_observed {
            state.stopped = true;
        }
        state.last_observed = now;
        if state.stopped
            || now.saturating_sub(state.started_at) >= state.setup.maximum_seconds
            || now.saturating_sub(state.last_success) >= state.setup.idle_seconds
        {
            state.stopped = true;
            return Err(ErrorCode::SessionExpired);
        }
        Ok(now)
    }
}

impl Control {
    pub fn synthetic(
        setup: SyntheticSetup,
        clock: Arc<dyn Clock>,
        executor: Arc<dyn Executor>,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        Self::build(setup.into(), clock, |_, _, _| {
            Ok(ExecutorKind::Issue(executor))
        })
    }

    /// Fixed synthetic GitHub operation; no caller-provided executor, keys or live transport.
    /// A NEW journal directory is mandatory. Existing directories cannot resume authority.
    pub fn synthetic_github(
        setup: OperationSetup,
        clock: Arc<dyn Clock>,
        journal_directory: &std::path::Path,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        Self::build_synthetic_github(setup, clock, journal_directory, false)
    }

    /// Optional disposable-key composition with the same synthetic provider and approval policy.
    /// It imports no key and exposes neither a signer nor JWT bytes.
    #[cfg(feature = "signing-spike")]
    pub fn synthetic_github_signed(
        setup: OperationSetup,
        clock: Arc<dyn Clock>,
        journal_directory: &std::path::Path,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        Self::build_synthetic_github(setup, clock, journal_directory, true)
    }
    fn build_synthetic_github(
        setup: OperationSetup,
        clock: Arc<dyn Clock>,
        journal_directory: &std::path::Path,
        signed: bool,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        if setup.profile != OperationProfile::GithubMetadata(GithubProfile::synthetic())
            || setup.approval_mode != ApprovalMode::EachRequest
            || setup.maximum_concurrent != 1
            || setup.maximum_requests > 32
            || setup.uses > 32
        {
            return Err(ErrorCode::InvalidRequest);
        }
        #[cfg(unix)]
        {
            let adapter_clock = clock.clone();
            Self::build(setup, clock, |instance, setup, started_at| {
                let adapter = crate::github::BrokerAdapter::new(
                    instance,
                    setup,
                    started_at,
                    adapter_clock.clone(),
                    journal_directory,
                )?;
                #[cfg(feature = "signing-spike")]
                let adapter = if signed {
                    adapter.with_signing(instance, setup, adapter_clock)?
                } else {
                    adapter
                };
                #[cfg(not(feature = "signing-spike"))]
                if signed {
                    return Err(ErrorCode::InvalidRequest);
                }
                Ok(ExecutorKind::Github(Arc::new(adapter)))
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (setup, clock, journal_directory, signed);
            Err(ErrorCode::InteractionRequired)
        }
    }

    #[cfg(all(unix, feature = "vault-spike"))]
    pub(crate) fn build_delivery(
        setup: OperationSetup,
        clock: Arc<dyn Clock>,
        factory: impl FnOnce(
            [u8; 16],
            &OperationSetup,
            u64,
        ) -> Result<Arc<crate::vault::Adapter>, ErrorCode>,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        if !matches!(setup.profile, OperationProfile::Delivery(_))
            || setup.approval_mode != ApprovalMode::EachRequest
            || setup.maximum_concurrent != 1
            || setup.maximum_requests > 32
            || setup.uses > 4
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Self::build(setup, clock, |instance, setup, started| {
            factory(instance, setup, started).map(ExecutorKind::Delivery)
        })
    }
    #[cfg(all(unix, feature = "vault-spike"))]
    pub(crate) fn delivery_context(&self, id: u64) -> Result<AuthorizedDispatch, ErrorCode> {
        let mut state = self.shared.lock()?;
        let session = state.session;
        let now = self.shared.check(&mut state, session)?;
        let request = state.requests.get(&id).ok_or(ErrorCode::NotFound)?;
        if !matches!(request.profile, OperationProfile::Delivery(_)) {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(AuthorizedDispatch {
            approval: request
                .reviewed
                .clone()
                .unwrap_or_else(|| approval_view(&state, request)),
            request_id: request.input.request_id.clone(),
            reserved_at: now,
            remaining_before: state.remaining,
        })
    }

    fn build(
        setup: OperationSetup,
        clock: Arc<dyn Clock>,
        factory: impl FnOnce([u8; 16], &OperationSetup, u64) -> Result<ExecutorKind, ErrorCode>,
    ) -> Result<(Self, AgentClient), ErrorCode> {
        setup.profile.validate()?;
        if setup.uses == 0
            || setup.uses > 1000
            || setup.idle_seconds == 0
            || setup.idle_seconds > 600
            || setup.maximum_seconds == 0
            || setup.maximum_seconds > 1800
            || setup.request_seconds == 0
            || setup.request_seconds > 15
            || setup.maximum_requests == 0
            || setup.maximum_requests > 128
            || setup.maximum_concurrent == 0
            || setup.maximum_concurrent > 4
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let now = clock.now();
        let mut instance = [0u8; 16];
        getrandom::getrandom(&mut instance).map_err(|_| ErrorCode::BrokerUnavailable)?;
        let executor = factory(instance, &setup, now)?;
        let state = State {
            instance,
            current_profile: setup.profile.clone(),
            remaining: setup.uses,
            setup,
            generation: 1,
            grant_generation: 1,
            session: 1,
            started_at: now,
            last_success: now,
            last_observed: now,
            stopped: false,
            revoked: false,
            uncertain: false,
            in_flight: 0,
            next_id: 1,
            requests: BTreeMap::new(),
            dedup: BTreeMap::new(),
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            clock,
            executor,
        });
        Ok((
            Self {
                shared: shared.clone(),
            },
            AgentClient {
                shared,
                session: 1,
                #[cfg(all(unix, feature = "vault-spike"))]
                vault_session: None,
            },
        ))
    }

    /// Canonical resolved fields for private human display, never agent rationale.
    pub fn inspect_operation_approval(&self, id: u64) -> Result<OperationApprovalView, ErrorCode> {
        let mut state = self.shared.lock()?;
        let session = state.session;
        let now = self.shared.check(&mut state, session)?;
        let request = state.requests.get(&id).ok_or(ErrorCode::NotFound)?;
        if now >= request.expires_at {
            return Err(ErrorCode::RequestExpired);
        }
        Ok(approval_view(&state, request))
    }

    /// Embedding host authority only; this is NOT evidence of genuine human presence.
    pub fn approve(&self, id: u64) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        self.approve_inner(id, None)?.into_legacy()
    }

    /// Atomically validate the exact broker-resolved review before granting approval.
    /// This remains host authority, not proof of a human's presence.
    pub fn approve_reviewed(&self, id: u64, expected: &ApprovalView) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        let (request_id, limits) = {
            let mut state = self.shared.lock()?;
            let session = state.session;
            self.shared.check(&mut state, session)?;
            if state.revoked {
                return Err(ErrorCode::GrantRevoked);
            }
            (
                state
                    .requests
                    .get(&id)
                    .ok_or(ErrorCode::NotFound)?
                    .input
                    .request_id
                    .clone(),
                state.setup.limits(),
            )
        };
        self.approve_inner(
            id,
            Some(&OperationApprovalView::from_legacy(
                expected, request_id, limits,
            )),
        )?
        .into_legacy()
    }
    pub fn approve_operation_reviewed(
        &self,
        id: u64,
        expected: &OperationApprovalView,
    ) -> Result<OperationRunView, ErrorCode> {
        self.approve_inner(id, Some(expected))
    }
    pub fn inspect_approval(&self, id: u64) -> Result<ApprovalView, ErrorCode> {
        self.inspect_operation_approval(id)?.into_legacy()
    }
    fn ensure_issue(&self, id: u64) -> Result<(), ErrorCode> {
        ensure_issue(&*self.shared.lock()?, id)
    }

    fn approve_inner(
        &self,
        id: u64,
        expected: Option<&OperationApprovalView>,
    ) -> Result<OperationRunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        let session = state.session;
        let now = self.shared.check(&mut state, session)?;
        if state.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if state.uncertain {
            return Err(ErrorCode::ReconciliationRequired);
        }
        let request = state.requests.get(&id).ok_or(ErrorCode::NotFound)?;
        match request.view.state {
            Lifecycle::AwaitingApproval | Lifecycle::Approved => {}
            Lifecycle::Canceled => return Err(ErrorCode::RequestCanceled),
            Lifecycle::Expired => return Err(ErrorCode::RequestExpired),
            _ => return Err(ErrorCode::InvalidRequest),
        }
        if now >= request.expires_at {
            expire_if_pending(
                state
                    .requests
                    .get_mut(&id)
                    .ok_or(ErrorCode::BrokerUnavailable)?,
                now,
            );
            return Err(ErrorCode::RequestExpired);
        }
        if request.generation != state.generation
            || state.generation != state.grant_generation
            || request.profile != state.current_profile
        {
            return Err(ErrorCode::PolicyChanged);
        }
        if expected.is_some_and(|view| view != &approval_view(&state, request)) {
            return Err(ErrorCode::ApprovalRequired);
        }
        let exact = expected
            .cloned()
            .unwrap_or_else(|| approval_view(&state, request));
        self.shared.executor.authorize_approval(&exact)?;
        let request = state
            .requests
            .get_mut(&id)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        request.view.state = Lifecycle::Approved;
        request.reviewed = expected.cloned();
        Ok(request.view.clone())
    }
    /// The same lock used by dispatch defines the revocation serialization point.
    pub fn revoke(&self) -> Result<(), ErrorCode> {
        let mut state = self.shared.lock()?;
        self.shared.executor.authorize_revoke()?;
        state.revoked = true;
        self.shared.executor.revoke()
    }
    /// Explicit trusted-control mock provider revocation, separate from future-use denial.
    /// Never exposed through the agent protocol.
    pub fn revoke_provider_tokens(&self) -> Result<crate::github::RevocationStatus, ErrorCode> {
        match &self.shared.executor {
            ExecutorKind::Issue(_) => Err(ErrorCode::ScopeDenied),
            #[cfg(all(unix, feature = "vault-spike"))]
            ExecutorKind::Delivery(_) => Err(ErrorCode::ScopeDenied),
            #[cfg(unix)]
            ExecutorKind::Github(adapter) => {
                self.revoke()?;
                adapter.revoke_provider()
            }
        }
    }
    pub fn stop(&self) -> Result<(), ErrorCode> {
        self.shared.lock()?.stopped = true;
        Ok(())
    }
    /// Revisions never silently broaden an existing frozen grant.
    pub fn replace_profile(&self, profile: Profile) -> Result<(), ErrorCode> {
        if !matches!(
            self.shared.lock()?.current_profile,
            OperationProfile::IssueStatus(_)
        ) {
            return Err(ErrorCode::ScopeDenied);
        }
        self.replace_operation_profile(OperationProfile::IssueStatus(profile))
    }
    pub fn replace_operation_profile(&self, profile: OperationProfile) -> Result<(), ErrorCode> {
        profile.validate()?;
        let mut state = self.shared.lock()?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        state.current_profile = profile;
        Ok(())
    }
    pub fn remaining_uses(&self) -> Result<u32, ErrorCode> {
        Ok(self.shared.lock()?.remaining)
    }
    pub fn is_active(&self) -> Result<(), ErrorCode> {
        let mut state = self.shared.lock()?;
        let session = state.session;
        self.shared.check(&mut state, session).map(|_| ())
    }
}

fn approval_view(state: &State, request: &Request) -> OperationApprovalView {
    OperationApprovalView {
        broker_instance: state.instance,
        request_id: request.input.request_id.clone(),
        limits: state.setup.limits(),
        prepared_request_id: request.view.prepared_request_id,
        principal: state.setup.principal.clone(),
        session: state.session,
        profile: request.profile.clone(),
        operation: request.input.operation.clone(),
        policy_generation: request.generation,
        expires_at: request.expires_at,
        remaining_uses: state.remaining,
    }
}
fn pending(state: Lifecycle) -> bool {
    matches!(
        state,
        Lifecycle::Prepared | Lifecycle::AwaitingApproval | Lifecycle::Approved
    )
}
fn expire_if_pending(request: &mut Request, now: u64) -> bool {
    if pending(request.view.state) && now >= request.expires_at {
        request.view.state = Lifecycle::Expired;
        request.view.error = Some(ErrorCode::RequestExpired);
        true
    } else {
        false
    }
}
// A retained GitHub uncertainty receipt is closed static status, not result data or
// renewed authority. Keep it accessible to its existing bound client after expiry.
fn retained_durable_unknown(state: &State, session: u64, id: u64) -> Option<OperationRunView> {
    if session != state.session {
        return None;
    }
    let request = state.requests.get(&id)?;
    (request.session == session
        && request.profile.durable()
        && request.view.state == Lifecycle::OutcomeUnknown
        && request.view.result.is_none()
        && request.view.error == Some(ErrorCode::OutcomeUnknown))
    .then(|| request.view.clone())
}
fn terminal(state: Lifecycle) -> bool {
    matches!(
        state,
        Lifecycle::Succeeded
            | Lifecycle::Failed
            | Lifecycle::OutcomeUnknown
            | Lifecycle::Canceled
            | Lifecycle::Expired
    )
}

impl AgentClient {
    #[cfg(all(unix, feature = "vault-spike"))]
    pub(crate) fn with_vault_session(
        &self,
        session: Arc<crate::vault::AuthenticatedSession>,
    ) -> Self {
        let mut client = self.clone();
        client.vault_session = Some(session);
        client
    }

    /// This public catalog is deliberately unverified and never selects authoritative policy.
    pub fn discover_operations(&self) -> Discovery {
        Discovery {
            verified: false,
            profile_id: ProfileId::new("issue-status").expect("constant"),
            operation: "synthetic.issue-status.v1".into(),
            input_contract: "repository-id-issue-number.v1".into(),
        }
    }

    pub fn prepare(&self, input: PrepareInput) -> Result<RunView, ErrorCode> {
        self.prepare_operation(input.into())?.into_legacy()
    }
    fn ensure_issue(&self, id: u64) -> Result<(), ErrorCode> {
        let state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        ensure_issue(&state, id)
    }
    pub fn request_approval(&self, id: u64) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        self.request_operation_approval(id)?.into_legacy()
    }
    pub fn cancel(&self, id: u64) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        self.cancel_operation(id)?.into_legacy()
    }
    pub fn status(&self, id: u64) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        self.operation_status(id)?.into_legacy()
    }
    pub fn invoke(&self, id: u64) -> Result<RunView, ErrorCode> {
        self.ensure_issue(id)?;
        self.invoke_operation(id)?.into_legacy()
    }
    pub fn discover_versioned_operations(&self) -> Result<OperationDiscovery, ErrorCode> {
        let state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        Ok(OperationDiscovery {
            verified: false,
            profile_id: state.current_profile.id().clone(),
            operation: match state.current_profile {
                OperationProfile::IssueStatus(_) => "synthetic.issue-status.v1",
                OperationProfile::GithubMetadata(_) => "synthetic.github.repository-metadata.v1",
                #[cfg(all(unix, feature = "vault-spike"))]
                OperationProfile::Delivery(_) => "synthetic.vault.deliver.v1",
            }
            .into(),
            protocol_version: 2,
        })
    }

    pub fn prepare_operation(
        &self,
        input: OperationPrepareInput,
    ) -> Result<OperationRunView, ErrorCode> {
        input.operation.validate()?;
        let mut state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        let now = self.shared.check(&mut state, self.session)?;
        if let Some(id) = state.dedup.get(&input.request_id).copied() {
            let request = state
                .requests
                .get_mut(&id)
                .ok_or(ErrorCode::BrokerUnavailable)?;
            if request.input != input {
                return Err(ErrorCode::RequestIdConflict);
            }
            expire_if_pending(request, now);
            return Ok(request.view.clone());
        }
        if state.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if state.uncertain {
            return Err(ErrorCode::ReconciliationRequired);
        }
        if state.current_profile != state.setup.profile
            || state.generation != state.grant_generation
        {
            return Err(ErrorCode::PolicyChanged);
        }
        if input.profile_id != *state.current_profile.id()
            || !state.current_profile.permits(&input.operation)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        self.shared.executor.authorize_prepare(&input)?;
        if state.remaining == 0 {
            return Err(ErrorCode::BudgetExhausted);
        }
        if state.requests.len() >= state.setup.maximum_requests {
            return Err(ErrorCode::CapacityExceeded);
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        let view = OperationRunView {
            prepared_request_id: id,
            state: if state.setup.approval_mode == ApprovalMode::BoundedSession {
                Lifecycle::Approved
            } else {
                Lifecycle::Prepared
            },
            result: None,
            error: None,
        };
        let request = Request {
            input: input.clone(),
            reviewed: None,
            profile: state.current_profile.clone(),
            generation: state.generation,
            expires_at: now.saturating_add(state.setup.request_seconds),
            session: self.session,
            view: view.clone(),
        };
        state.requests.insert(id, request);
        state.dedup.insert(input.request_id, id);
        Ok(view)
    }

    pub fn request_operation_approval(&self, id: u64) -> Result<OperationRunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        let now = self.shared.check(&mut state, self.session)?;
        let request = state.requests.get_mut(&id).ok_or(ErrorCode::NotFound)?;
        if request.session != self.session {
            return Err(ErrorCode::PrincipalMismatch);
        }
        if !pending(request.view.state) {
            return Ok(request.view.clone());
        }
        if expire_if_pending(request, now) {
            return Err(ErrorCode::RequestExpired);
        }
        if request.view.state == Lifecycle::Prepared {
            request.view.state = Lifecycle::AwaitingApproval;
        }
        Ok(request.view.clone())
    }

    pub fn cancel_operation(&self, id: u64) -> Result<OperationRunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        self.shared.check(&mut state, self.session)?;
        let request = state.requests.get_mut(&id).ok_or(ErrorCode::NotFound)?;
        if request.session != self.session {
            return Err(ErrorCode::PrincipalMismatch);
        }
        if matches!(
            request.view.state,
            Lifecycle::Prepared | Lifecycle::AwaitingApproval | Lifecycle::Approved
        ) {
            request.view.state = Lifecycle::Canceled;
            request.view.error = Some(ErrorCode::RequestCanceled);
        }
        // Once dispatched, cancellation cannot imply retraction of an external effect.
        Ok(request.view.clone())
    }

    pub fn operation_status(&self, id: u64) -> Result<OperationRunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        self.shared.executor.authenticate_agent(self)?;
        if let Some(receipt) = retained_durable_unknown(&state, self.session, id) {
            return Ok(receipt);
        }
        let now = self.shared.check(&mut state, self.session)?;
        let request = state.requests.get_mut(&id).ok_or(ErrorCode::NotFound)?;
        if request.session != self.session {
            return Err(ErrorCode::PrincipalMismatch);
        }
        expire_if_pending(request, now);
        Ok(request.view.clone())
    }

    pub fn invoke_operation(&self, id: u64) -> Result<OperationRunView, ErrorCode> {
        let dispatch = {
            let mut state = self.shared.lock()?;
            self.shared.executor.authenticate_agent(self)?;
            if let Some(receipt) = retained_durable_unknown(&state, self.session, id) {
                return Ok(receipt);
            }
            let now = self.shared.check(&mut state, self.session)?;
            let request = state.requests.get(&id).ok_or(ErrorCode::NotFound)?;
            if request.session != self.session {
                return Err(ErrorCode::PrincipalMismatch);
            }
            if terminal(request.view.state)
                || matches!(
                    request.view.state,
                    Lifecycle::Reserved | Lifecycle::Dispatched
                )
            {
                return Ok(request.view.clone());
            }
            if state.revoked {
                return Err(ErrorCode::GrantRevoked);
            }
            if state.uncertain {
                return Err(ErrorCode::ReconciliationRequired);
            }
            if now >= request.expires_at {
                expire_if_pending(
                    state
                        .requests
                        .get_mut(&id)
                        .ok_or(ErrorCode::BrokerUnavailable)?,
                    now,
                );
                return Err(ErrorCode::RequestExpired);
            }
            if request.profile != state.current_profile
                || request.generation != state.generation
                || state.generation != state.grant_generation
                || state.current_profile != state.setup.profile
            {
                return Err(ErrorCode::PolicyChanged);
            }
            if request.view.state != Lifecycle::Approved {
                return Err(ErrorCode::ApprovalRequired);
            }
            if state.remaining == 0 {
                return Err(ErrorCode::BudgetExhausted);
            }
            if state.in_flight >= state.setup.maximum_concurrent {
                return Err(ErrorCode::CapacityExceeded);
            }
            if request.profile.durable() && request.reviewed.is_none() {
                return Err(ErrorCode::ApprovalRequired);
            }
            let dispatch = AuthorizedDispatch {
                approval: request
                    .reviewed
                    .clone()
                    .unwrap_or_else(|| approval_view(&state, request)),
                request_id: request.input.request_id.clone(),
                reserved_at: now,
                remaining_before: state.remaining,
            };
            // Authentication/ACL/proof failure must precede budget consumption.
            self.shared.executor.authorize_dispatch(&dispatch)?;
            // Core authority/budget and durable adapter reservation share this lock with revoke.
            state.remaining -= 1;
            state.in_flight += 1;
            state
                .requests
                .get_mut(&id)
                .ok_or(ErrorCode::BrokerUnavailable)?
                .view
                .state = Lifecycle::Reserved;
            let reservation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.shared.executor.reserve(&dispatch)
            }))
            .unwrap_or(Err(ErrorCode::OutcomeUnknown));
            if reservation.is_err() {
                state.in_flight -= 1;
                state.uncertain |= dispatch.approval.profile.durable();
                let request = state
                    .requests
                    .get_mut(&id)
                    .ok_or(ErrorCode::BrokerUnavailable)?;
                request.view.state = Lifecycle::OutcomeUnknown;
                request.view.error = Some(ErrorCode::OutcomeUnknown);
                return Ok(request.view.clone());
            }
            state
                .requests
                .get_mut(&id)
                .ok_or(ErrorCode::BrokerUnavailable)?
                .view
                .state = Lifecycle::Dispatched;
            dispatch
        };

        // Provider may block. Never hold policy lock across provider work.
        // No automatic retry/refund: an accepted operation may have an unknown outcome.
        // Unwind does not prove the provider rejected an effect. Abort/process loss still
        // invalidates the entire session. Hosts own panic hooks (see SECURITY.md).
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.shared.executor.execute(&dispatch)
        }))
        .unwrap_or(Err(ErrorCode::OutcomeUnknown));
        let outcome = validate_outcome(outcome, &dispatch.approval);
        // Already reserved work must retain its result even if authentication expires
        // or is revoked while the trusted recipient is processing it.
        let mut state = self.shared.lock()?;
        state.in_flight = state.in_flight.saturating_sub(1);
        let active_now = self.shared.check(&mut state, self.session).ok();
        if outcome.is_ok() {
            if let Some(now) = active_now {
                state.last_success = now;
            }
        }
        if outcome == Err(ErrorCode::OutcomeUnknown) && dispatch.approval.profile.durable() {
            state.uncertain = true;
        }
        state.uncertain |= self.shared.executor.requires_reconciliation();
        let request = state
            .requests
            .get_mut(&id)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        match outcome {
            Ok(result) => {
                request.view.state = Lifecycle::Succeeded;
                request.view.result = Some(result);
            }
            Err(ErrorCode::OutcomeUnknown) => {
                request.view.state = Lifecycle::OutcomeUnknown;
                request.view.error = Some(ErrorCode::OutcomeUnknown);
            }
            Err(error) => {
                request.view.state = Lifecycle::Failed;
                request.view.error = Some(error);
            }
        }
        Ok(request.view.clone())
    }
}

#[cfg(all(unix, test))]
#[path = "broker_github_tests.rs"]
mod github_tests;
