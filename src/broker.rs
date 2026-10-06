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

struct Request {
    input: PrepareInput,
    profile: Profile,
    generation: u64,
    expires_at: u64,
    session: u64,
    view: RunView,
}
struct State {
    instance: [u8; 16],
    setup: SyntheticSetup,
    current_profile: Profile,
    generation: u64,
    grant_generation: u64,
    session: u64,
    started_at: u64,
    last_success: u64,
    last_observed: u64,
    stopped: bool,
    revoked: bool,
    remaining: u32,
    in_flight: usize,
    next_id: u64,
    requests: BTreeMap<u64, Request>,
    dedup: BTreeMap<RequestId, u64>,
}
struct Shared {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    executor: Arc<dyn Executor>,
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
            AgentClient { shared, session: 1 },
        ))
    }

    /// Canonical resolved fields for private human display, never agent rationale.
    pub fn inspect_approval(&self, id: u64) -> Result<ApprovalView, ErrorCode> {
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
        self.approve_inner(id, None)
    }

    /// Atomically validate the exact broker-resolved review before granting approval.
    /// This remains host authority, not proof of a human's presence.
    pub fn approve_reviewed(&self, id: u64, expected: &ApprovalView) -> Result<RunView, ErrorCode> {
        self.approve_inner(id, Some(expected))
    }

    fn approve_inner(
        &self,
        id: u64,
        expected: Option<&ApprovalView>,
    ) -> Result<RunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        let session = state.session;
        let now = self.shared.check(&mut state, session)?;
        if state.revoked {
            return Err(ErrorCode::GrantRevoked);
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
        let request = state
            .requests
            .get_mut(&id)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        request.view.state = Lifecycle::Approved;
        Ok(request.view.clone())
    }
    /// The same lock used by dispatch defines the revocation serialization point.
    pub fn revoke(&self) -> Result<(), ErrorCode> {
        self.shared.lock()?.revoked = true;
        Ok(())
    }
    pub fn stop(&self) -> Result<(), ErrorCode> {
        self.shared.lock()?.stopped = true;
        Ok(())
    }
    /// Revisions never silently broaden an existing frozen grant.
    pub fn replace_profile(&self, profile: Profile) -> Result<(), ErrorCode> {
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

fn approval_view(state: &State, request: &Request) -> ApprovalView {
    ApprovalView {
        broker_instance: state.instance,
        prepared_request_id: request.view.prepared_request_id,
        principal: state.setup.principal.clone(),
        session: state.session,
        profile: request.profile.clone(),
        parameters: request.input.parameters.clone(),
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
        input.parameters.validate()?;
        let mut state = self.shared.lock()?;
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
        if state.current_profile != state.setup.profile
            || state.generation != state.grant_generation
        {
            return Err(ErrorCode::PolicyChanged);
        }
        if input.profile_id != state.current_profile.id
            || input.parameters.repository_id != state.current_profile.repository_id
        {
            return Err(ErrorCode::ScopeDenied);
        }
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
        let view = RunView {
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

    pub fn request_approval(&self, id: u64) -> Result<RunView, ErrorCode> {
        let mut state = self.shared.lock()?;
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

    pub fn cancel(&self, id: u64) -> Result<RunView, ErrorCode> {
        let mut state = self.shared.lock()?;
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

    pub fn status(&self, id: u64) -> Result<RunView, ErrorCode> {
        let mut state = self.shared.lock()?;
        let now = self.shared.check(&mut state, self.session)?;
        let request = state.requests.get_mut(&id).ok_or(ErrorCode::NotFound)?;
        if request.session != self.session {
            return Err(ErrorCode::PrincipalMismatch);
        }
        expire_if_pending(request, now);
        Ok(request.view.clone())
    }

    pub fn invoke(&self, id: u64) -> Result<RunView, ErrorCode> {
        let dispatch = {
            let mut state = self.shared.lock()?;
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
            let dispatch = Dispatch {
                profile: request.profile.clone(),
                parameters: request.input.parameters.clone(),
            };
            // Reservation and transition to dispatch are one critical section: no control interleaves.
            state.remaining -= 1;
            state.in_flight += 1;
            let request = state
                .requests
                .get_mut(&id)
                .ok_or(ErrorCode::BrokerUnavailable)?;
            request.view.state = Lifecycle::Reserved;
            request.view.state = Lifecycle::Dispatched;
            dispatch
        };

        // Provider may block. Never hold policy lock across provider work.
        // No automatic retry/refund: an accepted operation may have an unknown outcome.
        // Unwind does not prove the provider rejected an effect. Abort/process loss still
        // invalidates the entire session. Hosts own panic hooks (see SECURITY.md).
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.shared.executor.execute(&dispatch)
        }))
        .unwrap_or(ProviderOutcome::Unknown);
        let mut state = self.shared.lock()?;
        state.in_flight = state.in_flight.saturating_sub(1);
        let active_now = self.shared.check(&mut state, self.session).ok();
        let valid_success = matches!(&outcome, ProviderOutcome::Status(raw) if raw.repository_id == dispatch.parameters.repository_id && raw.issue_number == dispatch.parameters.issue_number && matches!(raw.state.as_str(), "open" | "closed"));
        if valid_success {
            if let Some(now) = active_now {
                state.last_success = now;
            }
        }
        let request = state
            .requests
            .get_mut(&id)
            .ok_or(ErrorCode::BrokerUnavailable)?;
        match outcome {
            ProviderOutcome::Status(raw) if valid_success => {
                request.view.state = Lifecycle::Succeeded;
                request.view.result = Some(StatusProjection {
                    repository_id: raw.repository_id,
                    issue_number: raw.issue_number,
                    state: if raw.state == "open" {
                        IssueState::Open
                    } else {
                        IssueState::Closed
                    },
                });
            }
            ProviderOutcome::Status(_) => {
                request.view.state = Lifecycle::Failed;
                request.view.error = Some(ErrorCode::InvalidProviderResult);
            }
            ProviderOutcome::Unavailable => {
                request.view.state = Lifecycle::Failed;
                request.view.error = Some(ErrorCode::ProviderUnavailable);
            }
            ProviderOutcome::Unknown => {
                request.view.state = Lifecycle::OutcomeUnknown;
                request.view.error = Some(ErrorCode::OutcomeUnknown);
            }
        }
        Ok(request.view.clone())
    }
}
