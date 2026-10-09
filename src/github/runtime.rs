#[cfg(unix)]
use super::journal::{BrokerContext, BrokerReview, Event, Journal, Terminal};
use super::model::*;
use super::{GithubError, RepositoryProjection, RevocationStatus, SyntheticReport};
use crate::types::RequestId;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, MutexGuard,
};

const ORIGIN: &str = "https://api.github.com";
const API_VERSION: &str = "2026-03-10";
const ACCEPT: &str = "application/vnd.github+json";

/// Request policy exercised by the mock, not an implementation of TLS or confinement.
struct RequestPolicy {
    origin: &'static str,
    api_version: &'static str,
    accept: &'static str,
    follow_redirects: bool,
    use_environment_proxy: bool,
    max_response_bytes: usize,
    timeout_seconds: u64,
}
impl RequestPolicy {
    fn fixed() -> Self {
        Self {
            origin: ORIGIN,
            api_version: API_VERSION,
            accept: ACCEPT,
            follow_redirects: false,
            use_environment_proxy: false,
            max_response_bytes: MAX_BODY,
            timeout_seconds: 10,
        }
    }
    fn is_fixed(&self) -> bool {
        self.origin == ORIGIN
            && self.api_version == API_VERSION
            && self.accept == ACCEPT
            && !self.follow_redirects
            && !self.use_environment_proxy
            && self.max_response_bytes == MAX_BODY
            && self.timeout_seconds == 10
    }
}
/// No Debug, serialization, arbitrary headers, URL, redirects or process handoff.
struct ExchangeRequest {
    policy: RequestPolicy,
    path: String,
    scope: TokenScope,
    jwt: SignedJwt,
    #[cfg(all(unix, feature = "signing-spike"))]
    signing_authorization: Option<crate::signing::SigningAuthorization>,
    #[cfg(all(unix, feature = "signing-spike"))]
    verification_at: Moment,
}
struct MetadataRequest<'a> {
    policy: RequestPolicy,
    path: String,
    token: &'a Token,
}
struct RevokeRequest<'a> {
    policy: RequestPolicy,
    path: &'static str,
    token: &'a Token,
}

trait Signer: Send + Sync {
    fn sign(
        &self,
        signer_id: &str,
        signer_version: u64,
        claims: &JwtClaims,
    ) -> Result<SignedJwt, GithubError>;
}
enum ExchangeOutcome {
    Issued(TokenEnvelope),
    Rejected,
    #[cfg_attr(not(test), allow(dead_code))] // Failure injection; the fixed mock succeeds.
    Unknown,
}
enum ReadOutcome {
    Body(Vec<u8>),
    Rejected,
    #[cfg_attr(not(test), allow(dead_code))] // Failure injection; the fixed mock succeeds.
    Unknown,
}
enum RevokeOutcome {
    Confirmed,
    Unknown,
}
trait Provider: Send + Sync {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome;
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome;
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome;
}
trait TimeSource: Send + Sync {
    fn now(&self) -> Moment;
}
struct ManualTime {
    unix: AtomicU64,
    elapsed: AtomicU64,
}
impl ManualTime {
    fn new() -> Self {
        Self {
            unix: AtomicU64::new(1_800_000_000),
            elapsed: AtomicU64::new(0),
        }
    }
    fn advance(&self, seconds: u64) {
        self.unix.fetch_add(seconds, Ordering::SeqCst);
        self.elapsed.fetch_add(seconds, Ordering::SeqCst);
    }
}
impl TimeSource for ManualTime {
    fn now(&self) -> Moment {
        Moment {
            unix: self.unix.load(Ordering::SeqCst),
            elapsed: self.elapsed.load(Ordering::SeqCst),
        }
    }
}

/// Test-only approval evidence: not genuine human authentication or a broker grant.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovedRead {
    instance: [u8; 16],
    request_id: RequestId,
    binding: Binding,
    repository_id: u64,
    expires_elapsed: u64,
    #[cfg(unix)]
    broker_review: Option<BrokerReview>,
}
#[derive(Clone)]
struct Record {
    approval: ApprovedRead,
    result: Option<Result<RepositoryProjection, GithubError>>,
}
struct State {
    binding: Binding,
    broker_owned: bool,
    instance: [u8; 16],
    target: Repository,
    last: Moment,
    started: Moment,
    revoked: bool,
    revoke_persistence_failed: bool,
    blocked: bool,
    unresolved_exchange: bool,
    in_flight: bool,
    cached: Option<Lease>,
    retired: Vec<Lease>,
    quarantine: Option<TokenEnvelope>,
    records: BTreeMap<RequestId, Record>,
    revocation: Option<RevocationStatus>,
}
/// One-shot owned work. No Clone or public constructor; reserve never calls a provider.
#[cfg(all(unix, feature = "signing-spike"))]
struct SignedWork {
    authorization: crate::signing::SigningAuthorization,
    permit: Option<crate::signing::BoundPermit>,
}
struct ReservedRead {
    approval: ApprovedRead,
    binding: Binding,
    repo: Repository,
    now: Moment,
    cached: Option<Lease>,
    #[cfg(all(unix, feature = "signing-spike"))]
    signed: Option<SignedWork>,
}
enum ReservationOutcome {
    New(Box<ReservedRead>),
    Replay(Result<RepositoryProjection, GithubError>),
}
struct Fixture {
    #[cfg(all(unix, test, feature = "signing-spike"))]
    exchange_pause: Mutex<Option<Arc<BrokerPause>>>,
    #[cfg(unix)]
    journal: Option<Arc<Journal>>,
    state: Mutex<State>,
    clock: Arc<dyn TimeSource>,
    signer: Arc<dyn Signer>,
    provider: Arc<dyn Provider>,
}
impl Fixture {
    fn new(
        binding: Binding,
        target_id: u64,
        clock: Arc<dyn TimeSource>,
        signer: Arc<dyn Signer>,
        provider: Arc<dyn Provider>,
    ) -> Result<Self, GithubError> {
        binding.validate()?;
        let target = binding
            .repositories
            .iter()
            .find(|repo| repo.id == target_id)
            .cloned()
            .ok_or(GithubError::ScopeDenied)?;
        let started = clock.now();
        started.validate_after(started)?;
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|_| GithubError::Unavailable)?;
        Ok(Self {
            #[cfg(all(unix, test, feature = "signing-spike"))]
            exchange_pause: Mutex::new(None),
            #[cfg(unix)]
            journal: None,
            state: Mutex::new(State {
                binding,
                broker_owned: false,
                instance,
                target,
                last: started,
                started,
                revoked: false,
                revoke_persistence_failed: false,
                blocked: false,
                unresolved_exchange: false,
                in_flight: false,
                cached: None,
                retired: Vec::new(),
                quarantine: None,
                records: BTreeMap::new(),
                revocation: None,
            }),
            clock,
            signer,
            provider,
        })
    }
    #[cfg(unix)]
    fn attach_new_journal(mut self, path: &std::path::Path) -> Result<Self, super::JournalError> {
        let instance = self
            .state
            .get_mut()
            .map_err(|_| super::JournalError::Unavailable)?
            .instance;
        self.journal = Some(Arc::new(Journal::create(path, instance)?));
        Ok(self)
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, GithubError> {
        self.state.lock().map_err(|_| GithubError::Unavailable)
    }
    fn time(&self, state: &mut State) -> Result<Moment, GithubError> {
        let now = self.clock.now();
        if now.validate_after(state.last).is_err()
            || now.elapsed.saturating_sub(state.started.elapsed) >= 7200
        {
            state.blocked = true;
            return Err(GithubError::ClockInvalid);
        }
        state.last = now;
        Ok(now)
    }
    fn simulate_approval(&self, id: &str, repository_id: u64) -> Result<ApprovedRead, GithubError> {
        let request_id = RequestId::new(id).map_err(|_| GithubError::ScopeDenied)?;
        let mut state = self.lock()?;
        if state.broker_owned {
            return Err(GithubError::ScopeDenied);
        }
        let now = self.time(&mut state)?;
        if state.revoked {
            return Err(GithubError::Revoked);
        }
        if state.blocked {
            return Err(GithubError::ReconciliationRequired);
        }
        if repository_id != state.target.id {
            return Err(GithubError::ScopeDenied);
        }
        if let Some(record) = state.records.get(&request_id) {
            return Ok(record.approval.clone());
        }
        Ok(ApprovedRead {
            instance: state.instance,
            request_id,
            binding: state.binding.clone(),
            repository_id,
            expires_elapsed: now
                .elapsed
                .checked_add(30)
                .ok_or(GithubError::ClockInvalid)?,
            #[cfg(unix)]
            broker_review: None,
        })
    }
    fn invoke(&self, approval: &ApprovedRead) -> Result<RepositoryProjection, GithubError> {
        match self.reserve(approval)? {
            ReservationOutcome::New(reservation) => self.execute_reserved(*reservation),
            ReservationOutcome::Replay(result) => result,
        }
    }
    fn reserve(&self, approval: &ApprovedRead) -> Result<ReservationOutcome, GithubError> {
        let (binding, repo, now, cached) = {
            let mut state = self.lock()?;
            #[cfg(unix)]
            if state.broker_owned != approval.broker_review.is_some() {
                return Err(GithubError::ScopeDenied);
            }
            // A static uncertainty receipt must survive expiry/clock failure. Check the
            // exact authority/intent first; this releases neither data nor a new effect.
            if approval.instance == state.instance && approval.binding == state.binding {
                if let Some(record) = state.records.get(&approval.request_id) {
                    if record.approval != *approval {
                        return Err(GithubError::RequestConflict);
                    }
                    if record.result == Some(Err(GithubError::OutcomeUnknown)) {
                        return Err(GithubError::OutcomeUnknown);
                    }
                }
            }
            let now = self.time(&mut state)?;
            if state.revoked {
                return Err(GithubError::Revoked);
            }
            if approval.instance != state.instance || approval.binding != state.binding {
                return Err(GithubError::BindingChanged);
            }
            if approval.repository_id != state.target.id {
                return Err(GithubError::ScopeDenied);
            }
            if let Some(record) = state.records.get(&approval.request_id) {
                if record.approval != *approval {
                    return Err(GithubError::RequestConflict);
                }
                return Ok(ReservationOutcome::Replay(
                    record
                        .result
                        .clone()
                        .unwrap_or(Err(GithubError::InProgress)),
                ));
            }
            if state.blocked {
                return Err(GithubError::ReconciliationRequired);
            }
            if now.elapsed >= approval.expires_elapsed {
                return Err(GithubError::ApprovalExpired);
            }
            if state.in_flight {
                return Err(GithubError::InProgress);
            }
            if state.records.len() >= MAX_RECORDS {
                return Err(GithubError::CapacityExceeded);
            }
            state.retired.retain(|lease| !lease.expired(now));
            if state
                .cached
                .as_ref()
                .is_some_and(|lease| !lease.usable(now))
            {
                let old = state.cached.take().expect("present");
                if !old.expired(now) {
                    state.retired.push(old);
                }
            }
            // Reserve before signer/exchange/read. Revoke shares this serialization point.
            state.in_flight = true;
            state.records.insert(
                approval.request_id.clone(),
                Record {
                    approval: approval.clone(),
                    result: None,
                },
            );
            #[cfg(unix)]
            if let Some(journal) = &self.journal {
                if journal
                    .reserve(
                        approval.request_id.clone(),
                        state.instance,
                        &state.binding,
                        &state.target,
                        (now, approval.expires_elapsed),
                        approval.broker_review.clone(),
                    )
                    .is_err()
                {
                    state.in_flight = false;
                    state.blocked = true;
                    state
                        .records
                        .get_mut(&approval.request_id)
                        .expect("reserved")
                        .result = Some(Err(GithubError::PersistenceUnavailable));
                    return Err(GithubError::PersistenceUnavailable);
                }
            }
            (
                state.binding.clone(),
                state.target.clone(),
                now,
                state.cached.take(),
            )
        };
        Ok(ReservationOutcome::New(Box::new(ReservedRead {
            approval: approval.clone(),
            binding,
            repo,
            now,
            cached,
            #[cfg(all(unix, feature = "signing-spike"))]
            signed: None,
        })))
    }
    fn execute_reserved(
        &self,
        reserved: ReservedRead,
    ) -> Result<RepositoryProjection, GithubError> {
        let ReservedRead {
            approval,
            binding,
            repo,
            now,
            cached,
            #[cfg(all(unix, feature = "signing-spike"))]
            signed,
        } = reserved;
        let mut retained = cached;
        let mut quarantine = None;
        let uncertain_exchange = std::cell::Cell::new(false);
        let mut provider_effect_started = false;
        let mut last_observed = now;
        // Panics never cause another automatic exchange or read. This does not sanitize panic hooks.
        let execution = catch_unwind(AssertUnwindSafe(|| {
            if retained.is_none() {
                let claims = JwtClaims::new(&binding, now)?;
                #[cfg(all(unix, feature = "signing-spike"))]
                let (jwt, signing_authorization, jwt_issued_at) = if let Some(work) = signed {
                    let jwt = work
                        .permit
                        .ok_or(GithubError::SignerUnavailable)?
                        .sign(&work.authorization)
                        .map_err(|_| GithubError::SignerUnavailable)?;
                    let (unix, elapsed) = jwt.issued_at();
                    (
                        SignedJwt::Bound(Box::new(jwt)),
                        Some(work.authorization),
                        Moment { unix, elapsed },
                    )
                } else {
                    (
                        self.signer
                            .sign(&binding.signer_id, binding.signer_version, &claims)?,
                        None,
                        now,
                    )
                };
                #[cfg(not(all(unix, feature = "signing-spike")))]
                let jwt = self
                    .signer
                    .sign(&binding.signer_id, binding.signer_version, &claims)?;
                #[cfg(not(all(unix, feature = "signing-spike")))]
                let jwt_issued_at = now;
                jwt_issued_at.validate_after(last_observed)?;
                last_observed = jwt_issued_at;
                let scope = TokenScope::metadata(&repo);
                #[allow(unused_mut)]
                let mut request = ExchangeRequest {
                    policy: RequestPolicy::fixed(),
                    path: format!(
                        "/app/installations/{}/access_tokens",
                        binding.installation_id
                    ),
                    scope: scope.clone(),
                    jwt,
                    #[cfg(all(unix, feature = "signing-spike"))]
                    signing_authorization,
                    #[cfg(all(unix, feature = "signing-spike"))]
                    verification_at: now,
                };
                #[cfg(unix)]
                if let Some(journal) = &self.journal {
                    journal.append(Event::MintIntent {
                        request_id: approval.request_id.clone(),
                    })?;
                }
                #[cfg(all(unix, test, feature = "signing-spike"))]
                if let Some(pause) = self.exchange_pause.lock().unwrap().clone() {
                    pause.wait();
                }
                #[cfg(all(unix, feature = "signing-spike"))]
                if request.signing_authorization.is_some() {
                    // Sample after durable intent sync: issuance time is not verification now.
                    // Preserve the legacy synthetic token-expiry anchor and schema-2 policy.
                    let observed = self.clock.now();
                    observed.validate_after(last_observed)?;
                    last_observed = observed;
                    request.verification_at = observed;
                }
                // Until a receipt is validated, a token may have been minted.
                uncertain_exchange.set(true);
                provider_effect_started = true;
                // The fixed mock keeps its existing reservation-anchored token deadline;
                // signed JWT verification uses the separate current observation above.
                match self.provider.exchange(request, now) {
                    ExchangeOutcome::Issued(mut envelope) => {
                        envelope.mint_request = Some(approval.request_id.clone());
                        // Retain the receipt before invoking even a trusted clock: a
                        // panic must not drop the only token and claim no known token.
                        quarantine = Some(envelope);
                        uncertain_exchange.set(false);
                        #[cfg(unix)]
                        if let Some(journal) = &self.journal {
                            journal.append(Event::TokenReceived {
                                request_id: approval.request_id.clone(),
                                reported_expires_at: quarantine
                                    .as_ref()
                                    .expect("retained")
                                    .expires_at,
                            })?;
                        }
                        let current = self.clock.now();
                        if now.unix.checked_add(TOKEN_SECONDS).is_none_or(|limit| {
                            quarantine.as_ref().expect("retained receipt").expires_at > limit
                        }) {
                            return Err(GithubError::InvalidProviderResult);
                        }
                        if current.validate_after(last_observed).is_err() {
                            return Err(GithubError::ClockInvalid);
                        }
                        last_observed = current;
                        // If validation panics while owning the receipt, retain uncertainty.
                        uncertain_exchange.set(true);
                        let envelope = quarantine.take().expect("retained receipt");
                        // Expiry is checked at response completion, never just before the exchange.
                        match Lease::validate(envelope, &scope, now, current) {
                            Ok(lease) => {
                                retained = Some(lease);
                                uncertain_exchange.set(false);
                                #[cfg(unix)]
                                if let Some(journal) = &self.journal {
                                    journal.append(Event::TokenValidated {
                                        request_id: approval.request_id.clone(),
                                    })?;
                                }
                            }
                            Err((error, envelope)) => {
                                quarantine = Some(envelope);
                                uncertain_exchange.set(false);
                                return Err(error);
                            }
                        }
                    }
                    ExchangeOutcome::Rejected => {
                        uncertain_exchange.set(false);
                        return Err(GithubError::ProviderRejected);
                    }
                    ExchangeOutcome::Unknown => return Err(GithubError::OutcomeUnknown),
                }
            }
            let current = self.clock.now();
            current.validate_after(last_observed)?;
            last_observed = current;
            let lease = retained.as_ref().expect("validated lease");
            if !lease.usable(current) {
                return Err(GithubError::InvalidProviderResult);
            }
            let request = MetadataRequest {
                policy: RequestPolicy::fixed(),
                path: format!("/repos/{}/{}", binding.login, repo.name),
                token: &lease.envelope.token,
            };
            #[cfg(unix)]
            if let Some(journal) = &self.journal {
                journal.append(Event::ReadIntent {
                    request_id: approval.request_id.clone(),
                    mint_request_id: lease
                        .envelope
                        .mint_request
                        .clone()
                        .ok_or(GithubError::PersistenceUnavailable)?,
                })?;
            }
            provider_effect_started = true;
            match self.provider.metadata(request) {
                ReadOutcome::Body(body) => project(&body, &binding, &repo),
                ReadOutcome::Rejected => Err(GithubError::ProviderRejected),
                ReadOutcome::Unknown => Err(GithubError::OutcomeUnknown),
            }
        }));
        let mut result = execution.unwrap_or(Err(GithubError::OutcomeUnknown));
        if result == Err(GithubError::PersistenceUnavailable) && provider_effect_started {
            result = Err(GithubError::OutcomeUnknown);
        }
        let mut state = self.lock()?;
        state.in_flight = false;
        state.cached = retained;
        state.blocked |= quarantine.is_some()
            || matches!(
                result,
                Err(GithubError::OutcomeUnknown
                    | GithubError::ClockInvalid
                    | GithubError::PersistenceUnavailable)
            );
        state.quarantine = quarantine;
        // Lost or invalid mint receipt prevents every subsequent new request from minting again.
        state.blocked |= uncertain_exchange.get();
        state.unresolved_exchange |= uncertain_exchange.get();
        state.last = Moment {
            unix: state.last.unix.max(last_observed.unix),
            elapsed: state.last.elapsed.max(last_observed.elapsed),
        };
        let result = match self.time(&mut state) {
            Ok(_) => result,
            Err(_) if result == Err(GithubError::OutcomeUnknown) => result,
            Err(error) => Err(error),
        };
        #[cfg(unix)]
        let result = if let Some(journal) = &self.journal {
            let outcome = match &result {
                Ok(_) => Terminal::Succeeded,
                Err(GithubError::OutcomeUnknown) => Terminal::Unknown,
                Err(_) => Terminal::Failed,
            };
            if journal
                .append(Event::Complete {
                    request_id: approval.request_id.clone(),
                    outcome,
                    blocks_new_requests: state.blocked,
                })
                .is_err()
            {
                state.blocked = true;
                if provider_effect_started || result == Err(GithubError::OutcomeUnknown) {
                    Err(GithubError::OutcomeUnknown)
                } else {
                    Err(GithubError::PersistenceUnavailable)
                }
            } else {
                result
            }
        } else {
            result
        };
        state
            .records
            .get_mut(&approval.request_id)
            .expect("reservation retained")
            .result = Some(result.clone());
        result
    }
    fn revoke_future(&self) -> Result<(), GithubError> {
        let mut state = self.lock()?;
        if state.revoked {
            return if state.revoke_persistence_failed {
                Err(GithubError::PersistenceUnavailable)
            } else {
                Ok(())
            };
        }
        state.revoked = true;
        #[cfg(unix)]
        if let Some(journal) = &self.journal {
            if journal.append(Event::RevokeAuthority {}).is_err() {
                state.blocked = true;
                state.revoke_persistence_failed = true;
                return Err(GithubError::PersistenceUnavailable);
            }
        }
        Ok(())
    }
    /// Separate mock provider action, never implicit in local future-use revocation.
    fn revoke_provider(&self) -> Result<RevocationStatus, GithubError> {
        self.revoke_future()?;
        let (tokens, unresolved) = {
            let mut state = self.lock()?;
            state.revoked = true;
            if state.in_flight {
                return Ok(RevocationStatus::InProgress);
            }
            if let Some(status) = state.revocation {
                return Ok(status);
            }
            let mut tokens: Vec<TokenEnvelope> = state
                .retired
                .drain(..)
                .map(|lease| lease.envelope)
                .collect();
            if let Some(lease) = state.cached.take() {
                tokens.push(lease.envelope);
            }
            if let Some(token) = state.quarantine.take() {
                tokens.push(token);
            }
            let unresolved = state.unresolved_exchange;
            if tokens.is_empty() {
                let status = if unresolved {
                    RevocationStatus::UnresolvedExchange
                } else {
                    RevocationStatus::NoKnownToken
                };
                state.revocation = Some(status);
                return Ok(status);
            }
            state.revocation = Some(RevocationStatus::InProgress);
            (tokens, unresolved)
        };
        let mut unknown = unresolved;
        for envelope in tokens {
            #[cfg(unix)]
            if let Some(journal) = &self.journal {
                let Some(mint_request_id) = envelope.mint_request.clone() else {
                    unknown = true;
                    break;
                };
                if journal
                    .append(Event::RevokeIntent { mint_request_id })
                    .is_err()
                {
                    unknown = true;
                    break;
                }
            }
            // Revoke each known token once. Unknown acknowledgements are never silently retried.
            let result = catch_unwind(AssertUnwindSafe(|| {
                self.provider.revoke(RevokeRequest {
                    policy: RequestPolicy::fixed(),
                    path: "/installation/token",
                    token: &envelope.token,
                })
            }));
            let confirmed = matches!(result, Ok(RevokeOutcome::Confirmed));
            if !confirmed {
                unknown = true;
            }
            #[cfg(unix)]
            if let Some(journal) = &self.journal {
                let Some(mint_request_id) = envelope.mint_request.clone() else {
                    unknown = true;
                    break;
                };
                if journal
                    .append(Event::RevokeComplete {
                        mint_request_id,
                        confirmed,
                    })
                    .is_err()
                {
                    unknown = true;
                    break;
                }
            }
        }
        let status = if unresolved {
            RevocationStatus::UnresolvedExchange
        } else if unknown {
            RevocationStatus::OutcomeUnknown
        } else {
            RevocationStatus::ProviderConfirmed
        };
        self.lock()?.revocation = Some(status);
        Ok(status)
    }
}

#[cfg(unix)]
struct BrokerTime(Arc<dyn crate::broker::Clock>);
#[cfg(unix)]
impl TimeSource for BrokerTime {
    fn now(&self) -> Moment {
        let elapsed = self.0.now();
        Moment {
            unix: 1_800_000_000u64.checked_add(elapsed).unwrap_or(0),
            elapsed,
        }
    }
}
#[cfg(unix)]
pub(crate) struct BrokerAdapter {
    #[cfg(test)]
    provider: Arc<MockProvider>,
    #[cfg(test)]
    pause: Mutex<Option<Arc<BrokerPause>>>,
    fixture: Fixture,
    #[cfg(feature = "signing-spike")]
    source: Option<crate::signing::BoundSource>,
    pending: Mutex<BTreeMap<u64, Box<ReservedRead>>>,
}
#[cfg(unix)]
impl BrokerAdapter {
    pub(crate) fn new(
        instance: [u8; 16],
        setup: &crate::broker::OperationSetup,
        started_at: u64,
        clock: Arc<dyn crate::broker::Clock>,
        path: &std::path::Path,
    ) -> Result<Self, crate::ErrorCode> {
        use crate::types::*;
        if setup.profile != OperationProfile::GithubMetadata(GithubProfile::synthetic()) {
            return Err(ErrorCode::InvalidRequest);
        }
        let provider = Arc::new(MockProvider::default());
        let mut fixture = Fixture::new(
            Binding::fixture(),
            4242,
            Arc::new(BrokerTime(clock)),
            Arc::new(MockSigner::default()),
            provider.clone(),
        )
        .map_err(map_broker_error)?;
        let state = fixture
            .state
            .get_mut()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        state.instance = instance;
        state.broker_owned = true;
        fixture.journal = Some(Arc::new(
            Journal::create_broker(
                path,
                instance,
                BrokerContext {
                    principal: setup.principal.clone(),
                    session: 1,
                    profile_id: ProfileId::new("github-metadata").expect("constant"),
                    policy_generation: 1,
                    initial_uses: setup.uses,
                    session_started_at: started_at,
                    maximum_requests: setup.maximum_requests,
                    maximum_concurrent: setup.maximum_concurrent,
                    idle_seconds: setup.idle_seconds,
                    maximum_seconds: setup.maximum_seconds,
                    request_seconds: setup.request_seconds,
                    approval_mode: "each_request_reviewed".into(),
                },
            )
            .map_err(|_| ErrorCode::PersistenceUnavailable)?,
        ));
        Ok(Self {
            #[cfg(test)]
            provider,
            #[cfg(test)]
            pause: Mutex::new(None),
            fixture,
            #[cfg(feature = "signing-spike")]
            source: None,
            pending: Mutex::new(BTreeMap::new()),
        })
    }
    #[cfg(feature = "signing-spike")]
    pub(crate) fn with_signing(
        mut self,
        instance: [u8; 16],
        setup: &crate::broker::OperationSetup,
        clock: Arc<dyn crate::broker::Clock>,
    ) -> Result<Self, crate::ErrorCode> {
        self.source = Some(
            crate::signing::BoundSource::new(instance, setup, clock)
                .map_err(|_| crate::ErrorCode::ProviderUnavailable)?,
        );
        Ok(self)
    }
    pub(crate) fn reserve(
        &self,
        dispatch: &crate::broker::AuthorizedDispatch,
    ) -> Result<(), crate::ErrorCode> {
        use crate::types::*;
        let view = &dispatch.approval;
        if dispatch.request_id != view.request_id
            || view.profile != OperationProfile::GithubMetadata(GithubProfile::synthetic())
            || view.operation
                != OperationIntent::GithubMetadata(GithubMetadataParameters {
                    repository_id: 4242,
                })
        {
            return Err(ErrorCode::ScopeDenied);
        }
        let approval = ApprovedRead {
            instance: view.broker_instance,
            request_id: dispatch.request_id.clone(),
            binding: Binding::fixture(),
            repository_id: 4242,
            expires_elapsed: view.expires_at,
            broker_review: Some(BrokerReview {
                reviewed_request_id: view.request_id.clone(),
                principal: view.principal.clone(),
                session: view.session,
                profile_id: ProfileId::new("github-metadata").expect("constant"),
                prepared_request_id: view.prepared_request_id,
                profile_revision: 1,
                policy_generation: view.policy_generation,
                credential_version: 1,
                adapter_contract: 1,
                output_contract: 1,
                reviewed_remaining_uses: view.remaining_uses,
                remaining_before: dispatch.remaining_before,
                remaining_after: dispatch
                    .remaining_before
                    .checked_sub(1)
                    .ok_or(ErrorCode::BudgetExhausted)?,
                reviewed_expires_elapsed: view.expires_at,
            }),
        };
        // The core checked this clock instant under its lock; the adapter uses the same origin.
        if dispatch.reserved_at >= view.expires_at {
            return Err(ErrorCode::RequestExpired);
        }
        #[allow(unused_mut)]
        let mut reserved = match self.fixture.reserve(&approval).map_err(map_broker_error)? {
            ReservationOutcome::New(reserved) => reserved,
            ReservationOutcome::Replay(_) => return Err(ErrorCode::OutcomeUnknown),
        };
        #[cfg(feature = "signing-spike")]
        if let Some(source) = &self.source {
            // Journal reservation has acknowledged sync before resolving a lease.
            let authorization = crate::signing::SigningAuthorization::from_dispatch(dispatch)
                .map_err(|_| ErrorCode::ScopeDenied)?;
            // Existing token authority is independent of future key signing. A cached
            // read remains core-reviewed but needs no fresh key lease/signature.
            let permit = if reserved.cached.is_none() {
                Some(
                    source
                        .reserve(&authorization)
                        .map_err(|_| ErrorCode::ProviderUnavailable)?,
                )
            } else {
                None
            };
            reserved.signed = Some(SignedWork {
                authorization,
                permit,
            });
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if pending.insert(view.prepared_request_id, reserved).is_some() {
            return Err(ErrorCode::OutcomeUnknown);
        }
        Ok(())
    }
    pub(crate) fn execute(
        &self,
        dispatch: &crate::broker::AuthorizedDispatch,
    ) -> Result<RepositoryProjection, crate::ErrorCode> {
        let reserved = self
            .pending
            .lock()
            .map_err(|_| crate::ErrorCode::BrokerUnavailable)?
            .remove(&dispatch.approval.prepared_request_id)
            .ok_or(crate::ErrorCode::OutcomeUnknown)?;
        #[cfg(feature = "signing-spike")]
        if let Some(work) = &reserved.signed {
            let actual = crate::signing::SigningAuthorization::from_dispatch(dispatch)
                .map_err(|_| crate::ErrorCode::ScopeDenied)?;
            if actual != work.authorization {
                return Err(crate::ErrorCode::OutcomeUnknown);
            }
        }
        #[cfg(test)]
        if let Some(pause) = self
            .pause
            .lock()
            .map_err(|_| crate::ErrorCode::BrokerUnavailable)?
            .clone()
        {
            pause.wait();
        }
        self.fixture
            .execute_reserved(*reserved)
            .map_err(map_broker_error)
    }
    #[cfg(all(test, feature = "signing-spike"))]
    pub(crate) fn test_exchange_pause(&self) -> (std::sync::mpsc::Receiver<()>, Arc<BrokerPause>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let pause = Arc::new(BrokerPause {
            sender: Mutex::new(sender),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
        });
        *self.fixture.exchange_pause.lock().unwrap() = Some(pause.clone());
        (receiver, pause)
    }
    #[cfg(all(test, feature = "signing-spike"))]
    pub(crate) fn test_signing_fault(&self, at: usize) {
        self.source.as_ref().unwrap().fault(at);
    }
    #[cfg(all(test, feature = "signing-spike"))]
    pub(crate) fn test_signatures(&self) -> u32 {
        self.source.as_ref().map_or(0, |source| source.signatures())
    }
    #[cfg(all(test, feature = "signing-spike"))]
    pub(crate) fn test_lock_signer(&self) {
        self.source.as_ref().unwrap().lock();
    }
    #[cfg(test)]
    pub(crate) fn test_fault(&self, sequence: usize, fault: super::journal::Fault) {
        self.fixture
            .journal
            .as_ref()
            .unwrap()
            .fault(sequence, fault);
    }
    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize, usize) {
        (
            self.provider.exchanges.load(Ordering::SeqCst),
            self.provider.reads.load(Ordering::SeqCst),
            self.provider.revocations.load(Ordering::SeqCst),
        )
    }
    #[cfg(test)]
    pub(crate) fn test_pause(&self) -> (std::sync::mpsc::Receiver<()>, Arc<BrokerPause>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let pause = Arc::new(BrokerPause {
            sender: Mutex::new(sender),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
        });
        *self.pause.lock().unwrap() = Some(pause.clone());
        (receiver, pause)
    }
    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.fixture
            .lock()
            .map(|state| state.blocked)
            .unwrap_or(true)
    }
    pub(crate) fn revoke(&self) -> Result<(), crate::ErrorCode> {
        self.fixture.revoke_future().map_err(map_broker_error)
    }
    pub(crate) fn revoke_provider(&self) -> Result<RevocationStatus, crate::ErrorCode> {
        self.fixture.revoke_provider().map_err(map_broker_error)
    }
}
#[cfg(all(unix, test))]
pub(crate) struct BrokerPause {
    sender: Mutex<std::sync::mpsc::Sender<()>>,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(all(unix, test))]
impl BrokerPause {
    fn wait(&self) {
        self.sender.lock().unwrap().send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
#[cfg(unix)]
fn map_broker_error(error: GithubError) -> crate::ErrorCode {
    use crate::ErrorCode;
    match error {
        GithubError::OutcomeUnknown => ErrorCode::OutcomeUnknown,
        GithubError::PersistenceUnavailable => ErrorCode::PersistenceUnavailable,
        GithubError::ReconciliationRequired => ErrorCode::ReconciliationRequired,
        GithubError::InvalidProviderResult => ErrorCode::InvalidProviderResult,
        GithubError::ProviderRejected | GithubError::SignerUnavailable => {
            ErrorCode::ProviderUnavailable
        }
        GithubError::ScopeDenied | GithubError::InvalidBinding => ErrorCode::ScopeDenied,
        GithubError::ApprovalExpired => ErrorCode::RequestExpired,
        GithubError::BindingChanged => ErrorCode::PolicyChanged,
        GithubError::RequestConflict => ErrorCode::RequestIdConflict,
        GithubError::CapacityExceeded | GithubError::InProgress => ErrorCode::CapacityExceeded,
        GithubError::Revoked => ErrorCode::GrantRevoked,
        GithubError::ClockInvalid => ErrorCode::SessionExpired,
        GithubError::Unavailable => ErrorCode::BrokerUnavailable,
    }
}

#[derive(Default)]
struct MockSigner {
    calls: AtomicUsize,
}
impl Signer for MockSigner {
    fn sign(&self, id: &str, version: u64, claims: &JwtClaims) -> Result<SignedJwt, GithubError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if id != "synthetic-github-key"
            || version != 1
            || claims.iss != "Iv1_SYNTHETIC_ONLY"
            || claims.exp.checked_sub(claims.iat) != Some(600)
        {
            return Err(GithubError::SignerUnavailable);
        }
        // Deliberately NOT cryptography or a valid JWT. A maintained RS256 library is a live gate.
        Ok(SignedJwt::Mock(SYNTHETIC_JWT.into()))
    }
}
#[derive(Default)]
struct MockProvider {
    exchanges: AtomicUsize,
    reads: AtomicUsize,
    revocations: AtomicUsize,
}
impl Provider for MockProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        let valid_jwt = match &request.jwt {
            SignedJwt::Mock(value) => value == SYNTHETIC_JWT,
            #[cfg(all(unix, feature = "signing-spike"))]
            SignedJwt::Bound(jwt) => {
                request
                    .signing_authorization
                    .as_ref()
                    .is_some_and(|authorization| {
                        jwt.verify(
                            authorization,
                            request.verification_at.unix,
                            request.verification_at.elapsed,
                        )
                    })
            }
        };
        if !request.policy.is_fixed()
            || request.path != "/app/installations/202/access_tokens"
            || !valid_jwt
            || request.scope != TokenScope::metadata(&Binding::fixture().repositories[0])
        {
            return ExchangeOutcome::Rejected;
        }
        ExchangeOutcome::Issued(TokenEnvelope {
            mint_request: None,
            token: Token(SYNTHETIC_TOKEN.into()),
            expires_at: at.unix + TOKEN_SECONDS,
            scope: request.scope,
        })
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if !request.policy.is_fixed()
            || request.path != "/repos/NathanaelG1/Aegis"
            || request.token.0 != SYNTHETIC_TOKEN
        {
            return ReadOutcome::Rejected;
        }
        ReadOutcome::Body(br#"{"id":4242,"owner":{"id":303,"login":"NathanaelG1","type":"User"},"name":"Aegis","private":false,"archived":false,"description":"untrusted content is omitted"}"#.to_vec())
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.revocations.fetch_add(1, Ordering::SeqCst);
        if request.policy.is_fixed()
            && request.path == "/installation/token"
            && request.token.valid_shape()
        {
            RevokeOutcome::Confirmed
        } else {
            RevokeOutcome::Unknown
        }
    }
}
pub(super) fn demo() -> Result<SyntheticReport, GithubError> {
    let clock = Arc::new(ManualTime::new());
    let provider = Arc::new(MockProvider::default());
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        clock.clone(),
        Arc::new(MockSigner::default()),
        provider.clone(),
    )?;
    let approved = fixture.simulate_approval("first", 4242)?;
    let metadata = fixture.invoke(&approved)?;
    let duplicate_reused = fixture.invoke(&approved)? == metadata;
    clock.advance(3540); // Refresh margin, with the previous token retained for explicit revocation.
    fixture.invoke(&fixture.simulate_approval("refresh", 4242)?)?;
    fixture.revoke_future()?;
    let provider_revocation = fixture.revoke_provider()?;
    Ok(SyntheticReport {
        synthetic_only: true,
        metadata,
        duplicate_reused,
        exchanges: provider.exchanges.load(Ordering::SeqCst),
        metadata_requests: provider.reads.load(Ordering::SeqCst),
        provider_revocation,
        later_request_denied: fixture.invoke(&approved) == Err(GithubError::Revoked),
        live_available: super::live_readiness().available,
    })
}

#[cfg(unix)]
pub(super) fn journal_demo(path: &std::path::Path) -> Result<(), super::JournalError> {
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        Arc::new(ManualTime::new()),
        Arc::new(MockSigner::default()),
        Arc::new(MockProvider::default()),
    )
    .map_err(|_| super::JournalError::Unavailable)?
    .attach_new_journal(path)?;
    finish_journal_demo(fixture)
}

#[cfg(unix)]
fn finish_journal_demo(fixture: Fixture) -> Result<(), super::JournalError> {
    let approval = fixture
        .simulate_approval("durable-fixture", 4242)
        .map_err(|_| super::JournalError::Unavailable)?;
    fixture
        .invoke(&approval)
        .map_err(|_| super::JournalError::Incomplete)?;
    let status = fixture
        .revoke_provider()
        .map_err(|_| super::JournalError::Incomplete)?;
    if status != RevocationStatus::ProviderConfirmed {
        return Err(super::JournalError::Incomplete);
    }
    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

#[cfg(all(unix, test))]
#[path = "runtime_journal_tests.rs"]
mod journal_tests;
