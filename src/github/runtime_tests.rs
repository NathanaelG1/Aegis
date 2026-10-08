use super::*;
use std::sync::{Barrier, Condvar};

fn harness() -> (Fixture, Arc<ManualTime>, Arc<MockSigner>, Arc<MockProvider>) {
    let clock = Arc::new(ManualTime::new());
    let signer = Arc::new(MockSigner::default());
    let provider = Arc::new(MockProvider::default());
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        clock.clone(),
        signer.clone(),
        provider.clone(),
    )
    .unwrap();
    (fixture, clock, signer, provider)
}
fn run(fixture: &Fixture, id: &str) -> Result<RepositoryProjection, GithubError> {
    fixture.invoke(&fixture.simulate_approval(id, 4242)?)
}
fn envelope() -> TokenEnvelope {
    TokenEnvelope {
        mint_request: None,
        token: Token(SYNTHETIC_TOKEN.into()),
        expires_at: 1_800_003_600,
        scope: TokenScope::metadata(&Binding::fixture().repositories[0]),
    }
}

#[test]
fn fixture_and_public_report_are_synthetic_only() {
    let report = demo().unwrap();
    assert!(report.synthetic_only && report.duplicate_reused && report.later_request_denied);
    assert_eq!(report.exchanges, 2);
    assert_eq!(report.metadata_requests, 2);
    assert_eq!(
        report.provider_revocation,
        RevocationStatus::ProviderConfirmed
    );
    assert!(!report.live_available);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(SYNTHETIC_TOKEN));
    assert!(!serialized.contains(SYNTHETIC_JWT));
    assert_eq!(super::super::live_readiness().missing.len(), 6);
}
#[test]
fn binding_rejects_organization_other_owner_all_and_empty_repos() {
    for mutation in [
        |b: &mut Binding| b.account_kind = AccountKind::Organization,
        |b: &mut Binding| b.login = "someone-else".into(),
        |b: &mut Binding| b.selection = Selection::All,
        |b: &mut Binding| b.repositories.clear(),
        |b: &mut Binding| b.account_id = 0,
        |b: &mut Binding| b.app_id = 0,
        |b: &mut Binding| b.installation_id = 0,
        |b: &mut Binding| b.signer_version = 0,
        |b: &mut Binding| b.revision = 0,
        |b: &mut Binding| b.repositories[0].owner_id = 404,
    ] {
        let mut binding = Binding::fixture();
        mutation(&mut binding);
        assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    }
}
#[test]
fn binding_rejects_duplicates_oversize_and_route_injection() {
    let mut binding = Binding::fixture();
    binding.repositories.push(binding.repositories[0].clone());
    assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    for name in [
        "..",
        ".",
        "",
        "a/b",
        "a?token=secret",
        "a#frag",
        "a%2fb",
        "a\\b",
        "a\n",
        "é",
    ] {
        let mut binding = Binding::fixture();
        binding.repositories[0].name = name.into();
        assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    }
    let mut binding = Binding::fixture();
    binding.repositories = (1..=501)
        .map(|id| Repository {
            id,
            owner_id: 303,
            name: format!("r{id}"),
        })
        .collect();
    assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    binding.repositories.pop();
    assert_eq!(binding.validate(), Ok(()));
    binding.repositories[1].name = "R1".into();
    assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
}
#[test]
fn binding_rejects_workflows_admin_user_permissions_and_bad_key_reference() {
    for key in ["workflows", "administration", "members", "emails", "issues"] {
        let mut binding = Binding::fixture();
        binding.permissions.insert(key.into(), Permission::Read);
        assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    }
    let mut binding = Binding::fixture();
    binding
        .permissions
        .insert("metadata".into(), Permission::Write);
    assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    binding = Binding::fixture();
    binding.permissions.remove("metadata");
    assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    for id in ["/tmp/key", "latest/key", "key\n", ""] {
        binding = Binding::fixture();
        binding.signer_id = id.into();
        assert_eq!(binding.validate(), Err(GithubError::InvalidBinding));
    }
}
#[test]
fn metadata_scope_narrows_write_ceiling_and_serializes_explicit_repositories() {
    let binding = Binding::fixture();
    assert_eq!(
        binding.permissions.get("contents"),
        Some(&Permission::Write)
    );
    assert_eq!(
        serde_json::to_string(&TokenScope::metadata(&binding.repositories[0])).unwrap(),
        r#"{"repository_ids":[4242],"permissions":{"metadata":"read"}}"#
    );
}
#[test]
fn claims_use_client_id_bounded_time_and_checked_arithmetic() {
    let binding = Binding::fixture();
    let claims = JwtClaims::new(
        &binding,
        Moment {
            unix: 1000,
            elapsed: 0,
        },
    )
    .unwrap();
    assert_eq!(
        claims,
        JwtClaims {
            iss: binding.client_id.clone(),
            iat: 940,
            exp: 1540
        }
    );
    for unix in [0, 59, u64::MAX] {
        assert_eq!(
            JwtClaims::new(&binding, Moment { unix, elapsed: 0 }),
            Err(GithubError::ClockInvalid)
        );
    }
}
#[test]
fn preflight_denial_never_signs_exchanges_or_reads() {
    let (fixture, _, signer, provider) = harness();
    assert_eq!(
        fixture.simulate_approval("wrong", 7),
        Err(GithubError::ScopeDenied)
    );
    let mut approval = fixture.simulate_approval("good", 4242).unwrap();
    approval.repository_id = 7;
    assert_eq!(fixture.invoke(&approval), Err(GithubError::ScopeDenied));
    approval.repository_id = 4242;
    approval.binding.signer_version += 1;
    assert_eq!(fixture.invoke(&approval), Err(GithubError::BindingChanged));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 0);
    assert_eq!(provider.reads.load(Ordering::SeqCst), 0);
}
#[test]
fn approved_snapshot_binds_every_administrative_field_and_instance() {
    let (fixture, _, signer, _) = harness();
    let approval = fixture.simulate_approval("bound", 4242).unwrap();
    for mutation in [
        |b: &mut Binding| b.app_id += 1,
        |b: &mut Binding| b.client_id.push('x'),
        |b: &mut Binding| b.installation_id += 1,
        |b: &mut Binding| b.account_id += 1,
        |b: &mut Binding| b.signer_id.push('x'),
        |b: &mut Binding| b.signer_version += 1,
        |b: &mut Binding| b.revision += 1,
        |b: &mut Binding| {
            b.permissions.remove("contents");
        },
        |b: &mut Binding| b.repositories[0].name.push('x'),
    ] {
        let mut changed = approval.clone();
        mutation(&mut changed.binding);
        assert_eq!(fixture.invoke(&changed), Err(GithubError::BindingChanged));
    }
    let (other, _, _, _) = harness();
    assert_eq!(other.invoke(&approval), Err(GithubError::BindingChanged));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn duplicate_replays_and_changed_canonical_approval_conflicts() {
    let (fixture, _, _, provider) = harness();
    let mut approval = fixture.simulate_approval("one", 4242).unwrap();
    assert_eq!(fixture.invoke(&approval), fixture.invoke(&approval));
    approval.expires_elapsed += 1;
    assert_eq!(fixture.invoke(&approval), Err(GithubError::RequestConflict));
    assert_eq!(provider.reads.load(Ordering::SeqCst), 1);
}
#[test]
fn expired_approval_does_not_mint() {
    let (fixture, clock, _, provider) = harness();
    let approval = fixture.simulate_approval("expired", 4242).unwrap();
    clock.advance(30);
    assert_eq!(fixture.invoke(&approval), Err(GithubError::ApprovalExpired));
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 0);
}
#[test]
fn cache_reuse_and_refresh_keep_overlap_for_explicit_revoke() {
    let (fixture, clock, _, provider) = harness();
    run(&fixture, "one").unwrap();
    run(&fixture, "two").unwrap();
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
    clock.advance(3540);
    run(&fixture, "refresh").unwrap();
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.lock().unwrap().retired.len(), 1);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
    assert_eq!(provider.revocations.load(Ordering::SeqCst), 2);
}
#[test]
fn expiry_removes_only_expired_leases_and_refresh_requires_new_approval() {
    let (fixture, clock, _, provider) = harness();
    let approved = fixture.simulate_approval("one", 4242).unwrap();
    fixture.invoke(&approved).unwrap();
    clock.advance(3601);
    fixture.invoke(&approved).unwrap(); // Dedup does not refresh a token.
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
    run(&fixture, "new").unwrap();
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 2);
    assert!(fixture.lock().unwrap().retired.is_empty());
}
#[test]
fn utc_or_elapsed_regression_blocks_every_new_effect() {
    for wall in [true, false] {
        let (fixture, clock, _, provider) = harness();
        clock.advance(10);
        run(&fixture, "first").unwrap();
        if wall {
            clock.unix.fetch_sub(1, Ordering::SeqCst);
        } else {
            clock.elapsed.fetch_sub(1, Ordering::SeqCst);
        }
        assert_eq!(run(&fixture, "second"), Err(GithubError::ClockInvalid));
        clock.advance(2);
        assert_eq!(
            run(&fixture, "third"),
            Err(GithubError::ReconciliationRequired)
        );
        assert_eq!(provider.reads.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn bounded_session_and_record_capacity_do_not_evict_dedup() {
    let (fixture, clock, _, provider) = harness();
    for n in 0..MAX_RECORDS {
        run(&fixture, &format!("r{n}")).unwrap();
    }
    assert_eq!(
        run(&fixture, "overflow"),
        Err(GithubError::CapacityExceeded)
    );
    run(&fixture, "r0").unwrap();
    assert_eq!(provider.reads.load(Ordering::SeqCst), MAX_RECORDS);
    clock.advance(7200);
    assert_eq!(run(&fixture, "old"), Err(GithubError::ClockInvalid));
}
#[test]
fn token_shape_has_bounds_without_fixed_40_character_assumption() {
    assert!(Token("t".repeat(4096)).valid_shape());
    for value in [
        "".into(),
        "t".repeat(4097),
        "token\r\nAuthorization:bad".into(),
        "two words".into(),
        "токен".into(),
    ] {
        assert!(!Token(value).valid_shape());
    }
}
#[test]
fn token_receipt_rejects_scope_surplus_missing_scope_and_bad_expiry() {
    let scope = envelope().scope;
    let now = Moment {
        unix: 1_800_000_000,
        elapsed: 0,
    };
    for mutate in [
        |e: &mut TokenEnvelope| e.scope.repository_ids.push(7),
        |e: &mut TokenEnvelope| e.scope.repository_ids.clear(),
        |e: &mut TokenEnvelope| {
            e.scope
                .permissions
                .insert("contents".into(), Permission::Write);
        },
        |e: &mut TokenEnvelope| e.scope.permissions.clear(),
        |e: &mut TokenEnvelope| e.expires_at = 1_800_000_000,
        |e: &mut TokenEnvelope| e.expires_at = 1_800_000_060,
        |e: &mut TokenEnvelope| e.expires_at = 1_800_003_601,
        |e: &mut TokenEnvelope| e.token.0.clear(),
    ] {
        let mut reply = envelope();
        mutate(&mut reply);
        assert!(matches!(
            Lease::validate(reply, &scope, now, now),
            Err((GithubError::InvalidProviderResult, _))
        ));
    }
    assert!(matches!(
        Lease::validate(
            envelope(),
            &scope,
            Moment {
                elapsed: u64::MAX,
                ..now
            },
            Moment {
                elapsed: u64::MAX,
                ..now
            }
        ),
        Err((GithubError::ClockInvalid, _))
    ));
}
#[test]
fn metadata_projection_omits_hostile_strings_and_validates_identity() {
    let binding = Binding::fixture();
    let repo = &binding.repositories[0];
    let good = serde_json::json!({"id":4242,"owner":{"id":303,"login":"NathanaelG1","type":"User"},"name":"Aegis","private":true,"archived":false,"description":SYNTHETIC_TOKEN,"token":SYNTHETIC_JWT});
    let projected = project(&serde_json::to_vec(&good).unwrap(), &binding, repo).unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap(),
        serde_json::json!({"repository_id":4242,"private":true,"archived":false})
    );
    for (pointer, bad) in [
        ("/id", serde_json::json!(7)),
        ("/owner/id", serde_json::json!(404)),
        ("/owner/login", serde_json::json!("different")),
        ("/owner/type", serde_json::json!("Organization")),
        ("/name", serde_json::json!("moved")),
        ("/private", serde_json::json!(SYNTHETIC_TOKEN)),
    ] {
        let mut value = good.clone();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert_eq!(
            project(&serde_json::to_vec(&value).unwrap(), &binding, repo),
            Err(GithubError::InvalidProviderResult)
        );
    }
}
#[test]
fn metadata_parser_rejects_oversize_malformed_duplicate_and_nested_payloads() {
    let binding = Binding::fixture();
    let repo = &binding.repositories[0];
    for body in [
        vec![b' '; MAX_BODY + 1],
        b"not json".to_vec(),
        br#"{"id":4242,"id":7}"#.to_vec(),
        format!("{}{}", "[".repeat(200), "]".repeat(200)).into_bytes(),
    ] {
        assert_eq!(
            project(&body, &binding, repo),
            Err(GithubError::InvalidProviderResult)
        );
    }
}

#[derive(Clone, Copy)]
enum ExchangeFault {
    None,
    Unknown,
    Reject,
    Panic,
    WrongScope,
    Expired,
}
struct FaultProvider {
    base: MockProvider,
    exchange_fault: ExchangeFault,
    read_unknown: bool,
    revoke_unknown: bool,
    advance_on_exchange: Option<Arc<ManualTime>>,
}
impl FaultProvider {
    fn new(exchange_fault: ExchangeFault) -> Self {
        Self {
            base: MockProvider::default(),
            exchange_fault,
            read_unknown: false,
            revoke_unknown: false,
            advance_on_exchange: None,
        }
    }
}
impl Provider for FaultProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        let normal = self.base.exchange(request, at);
        match self.exchange_fault {
            ExchangeFault::Unknown => ExchangeOutcome::Unknown,
            ExchangeFault::Reject => ExchangeOutcome::Rejected,
            ExchangeFault::Panic => panic!("synthetic exchange interruption"),
            ExchangeFault::WrongScope => {
                let mut e = envelope();
                e.scope.repository_ids.push(7);
                ExchangeOutcome::Issued(e)
            }
            ExchangeFault::Expired => {
                let mut e = envelope();
                e.expires_at = at.unix;
                ExchangeOutcome::Issued(e)
            }
            ExchangeFault::None => {
                if let Some(clock) = &self.advance_on_exchange {
                    clock.advance(3600);
                }
                normal
            }
        }
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        let normal = self.base.metadata(request);
        if self.read_unknown {
            ReadOutcome::Unknown
        } else {
            normal
        }
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        let normal = self.base.revoke(request);
        if self.revoke_unknown {
            RevokeOutcome::Unknown
        } else {
            normal
        }
    }
}
fn faulty(provider: Arc<FaultProvider>, clock: Arc<ManualTime>) -> Fixture {
    Fixture::new(
        Binding::fixture(),
        4242,
        clock,
        Arc::new(MockSigner::default()),
        provider,
    )
    .unwrap()
}
#[test]
fn unknown_or_panicking_exchange_is_retained_and_blocks_new_ids() {
    for fault in [ExchangeFault::Unknown, ExchangeFault::Panic] {
        let provider = Arc::new(FaultProvider::new(fault));
        let fixture = faulty(provider.clone(), Arc::new(ManualTime::new()));
        let approval = fixture.simulate_approval("once", 4242).unwrap();
        assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
        assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
        assert_eq!(
            run(&fixture, "again"),
            Err(GithubError::ReconciliationRequired)
        );
        assert_eq!(provider.base.exchanges.load(Ordering::SeqCst), 1);
        assert_eq!(provider.base.reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.revoke_provider().unwrap(),
            RevocationStatus::UnresolvedExchange
        );
    }
}
#[test]
fn known_rejection_is_retained_without_automatic_retry() {
    let provider = Arc::new(FaultProvider::new(ExchangeFault::Reject));
    let fixture = faulty(provider.clone(), Arc::new(ManualTime::new()));
    let approval = fixture.simulate_approval("once", 4242).unwrap();
    assert_eq!(
        fixture.invoke(&approval),
        Err(GithubError::ProviderRejected)
    );
    assert_eq!(
        fixture.invoke(&approval),
        Err(GithubError::ProviderRejected)
    );
    assert_eq!(provider.base.exchanges.load(Ordering::SeqCst), 1);
}
#[test]
fn invalid_receipt_is_quarantined_and_never_used() {
    for fault in [ExchangeFault::WrongScope, ExchangeFault::Expired] {
        let provider = Arc::new(FaultProvider::new(fault));
        let fixture = faulty(provider.clone(), Arc::new(ManualTime::new()));
        assert_eq!(
            run(&fixture, "bad"),
            Err(GithubError::InvalidProviderResult)
        );
        assert_eq!(
            run(&fixture, "new"),
            Err(GithubError::ReconciliationRequired)
        );
        assert_eq!(provider.base.reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.revoke_provider().unwrap(),
            RevocationStatus::ProviderConfirmed
        );
        assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn token_expiring_during_exchange_cannot_reach_metadata_dispatch() {
    let clock = Arc::new(ManualTime::new());
    let mut provider = FaultProvider::new(ExchangeFault::None);
    provider.advance_on_exchange = Some(clock.clone());
    let provider = Arc::new(provider);
    let fixture = faulty(provider.clone(), clock);
    assert_eq!(
        run(&fixture, "late"),
        Err(GithubError::InvalidProviderResult)
    );
    assert_eq!(provider.base.reads.load(Ordering::SeqCst), 0);
}
#[test]
fn unknown_read_is_retained_and_blocks_fresh_request_ids() {
    let mut provider = FaultProvider::new(ExchangeFault::None);
    provider.read_unknown = true;
    let provider = Arc::new(provider);
    let fixture = faulty(provider.clone(), Arc::new(ManualTime::new()));
    let approval = fixture.simulate_approval("once", 4242).unwrap();
    assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
    assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
    assert_eq!(
        run(&fixture, "again"),
        Err(GithubError::ReconciliationRequired)
    );
    assert_eq!(provider.base.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
}
#[test]
fn local_revoke_is_not_provider_revocation_and_prevents_first_exchange() {
    let (fixture, _, _, provider) = harness();
    let approval = fixture.simulate_approval("stop", 4242).unwrap();
    fixture.revoke_future().unwrap();
    assert_eq!(fixture.invoke(&approval), Err(GithubError::Revoked));
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 0);
    assert_eq!(provider.revocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::NoKnownToken
    );
}
#[test]
fn unknown_provider_revoke_is_retained_without_repeat() {
    let mut provider = FaultProvider::new(ExchangeFault::None);
    provider.revoke_unknown = true;
    let provider = Arc::new(provider);
    let fixture = faulty(provider.clone(), Arc::new(ManualTime::new()));
    run(&fixture, "first").unwrap();
    fixture.revoke_future().unwrap();
    assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::OutcomeUnknown
    );
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::OutcomeUnknown
    );
    assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 1);
    assert_eq!(run(&fixture, "new"), Err(GithubError::Revoked));
}

struct BlockingProvider {
    base: MockProvider,
    entered: Barrier,
    released: (Mutex<bool>, Condvar),
}
impl BlockingProvider {
    fn new() -> Self {
        Self {
            base: MockProvider::default(),
            entered: Barrier::new(2),
            released: (Mutex::new(false), Condvar::new()),
        }
    }
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}
impl Provider for BlockingProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        self.entered.wait();
        let (lock, cond) = &self.released;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = cond.wait(released).unwrap();
        }
        self.base.exchange(request, at)
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.base.metadata(request)
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.base.revoke(request)
    }
}
#[test]
fn concurrent_duplicate_and_distinct_calls_are_single_flight_with_revoke_race() {
    let provider = Arc::new(BlockingProvider::new());
    let fixture = Arc::new(
        Fixture::new(
            Binding::fixture(),
            4242,
            Arc::new(ManualTime::new()),
            Arc::new(MockSigner::default()),
            provider.clone(),
        )
        .unwrap(),
    );
    let approval = fixture.simulate_approval("first", 4242).unwrap();
    let second = fixture.simulate_approval("second", 4242).unwrap();
    let thread_fixture = fixture.clone();
    let thread_approval = approval.clone();
    let worker = std::thread::spawn(move || thread_fixture.invoke(&thread_approval));
    provider.entered.wait();
    assert_eq!(fixture.invoke(&approval), Err(GithubError::InProgress));
    assert_eq!(fixture.invoke(&second), Err(GithubError::InProgress));
    fixture.revoke_future().unwrap();
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::InProgress
    );
    assert_eq!(fixture.invoke(&second), Err(GithubError::Revoked));
    provider.release();
    worker.join().unwrap().unwrap(); // Previously reserved request may complete.
    assert_eq!(provider.base.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(provider.base.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
    assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 1);
}

struct ClockFaultProvider {
    base: MockProvider,
    clock: Arc<ManualTime>,
    unknown_mint: bool,
    expire_session: bool,
}
impl ClockFaultProvider {
    fn disturb(&self) {
        if self.expire_session {
            self.clock.advance(7200);
        } else {
            self.clock.unix.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
impl Provider for ClockFaultProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        let normal = self.base.exchange(request, at);
        if self.unknown_mint {
            self.disturb();
            ExchangeOutcome::Unknown
        } else {
            normal
        }
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.base.metadata(request);
        self.disturb();
        ReadOutcome::Unknown
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.base.revoke(request)
    }
}
#[test]
fn unknown_receipt_survives_clock_regression_and_session_expiry() {
    for unknown_mint in [true, false] {
        for expire_session in [true, false] {
            let clock = Arc::new(ManualTime::new());
            let provider = Arc::new(ClockFaultProvider {
                base: MockProvider::default(),
                clock: clock.clone(),
                unknown_mint,
                expire_session,
            });
            let fixture = Fixture::new(
                Binding::fixture(),
                4242,
                clock,
                Arc::new(MockSigner::default()),
                provider.clone(),
            )
            .unwrap();
            let approved = fixture.simulate_approval("uncertain", 4242).unwrap();
            assert_eq!(fixture.invoke(&approved), Err(GithubError::OutcomeUnknown));
            assert_eq!(fixture.invoke(&approved), Err(GithubError::OutcomeUnknown));
            assert!(run(&fixture, "new").is_err());
            assert_eq!(provider.base.exchanges.load(Ordering::SeqCst), 1);
            assert_eq!(
                provider.base.reads.load(Ordering::SeqCst),
                usize::from(!unknown_mint)
            );
            let mut changed = approved.clone();
            changed.expires_elapsed += 1;
            assert_eq!(fixture.invoke(&changed), Err(GithubError::RequestConflict));
        }
    }
}
struct UnknownRefreshProvider {
    base: MockProvider,
}
impl Provider for UnknownRefreshProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        let normal = self.base.exchange(request, at);
        if self.base.exchanges.load(Ordering::SeqCst) > 1 {
            ExchangeOutcome::Unknown
        } else {
            normal
        }
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.base.metadata(request)
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.base.revoke(request)
    }
}
#[test]
fn revoking_older_known_token_does_not_resolve_an_unknown_refresh() {
    let clock = Arc::new(ManualTime::new());
    let provider = Arc::new(UnknownRefreshProvider {
        base: MockProvider::default(),
    });
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        clock.clone(),
        Arc::new(MockSigner::default()),
        provider.clone(),
    )
    .unwrap();
    run(&fixture, "first").unwrap();
    clock.advance(3540);
    assert_eq!(run(&fixture, "refresh"), Err(GithubError::OutcomeUnknown));
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::UnresolvedExchange
    );
    assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::UnresolvedExchange
    );
    assert_eq!(provider.base.revocations.load(Ordering::SeqCst), 1);
}

struct ScriptedClock {
    samples: Mutex<std::collections::VecDeque<Moment>>,
    last: Moment,
}
impl TimeSource for ScriptedClock {
    fn now(&self) -> Moment {
        self.samples
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(self.last)
    }
}
#[test]
fn clock_regression_between_exchange_receipt_and_read_is_sticky() {
    let start = Moment {
        unix: 1_800_000_000,
        elapsed: 0,
    };
    let complete = Moment {
        unix: start.unix + 100,
        elapsed: 100,
    };
    let regressed = Moment {
        unix: start.unix + 50,
        elapsed: 50,
    };
    let recovered = Moment {
        unix: start.unix + 101,
        elapsed: 101,
    };
    let clock = Arc::new(ScriptedClock {
        samples: Mutex::new([start, start, start, complete, regressed, recovered].into()),
        last: recovered,
    });
    let provider = Arc::new(MockProvider::default());
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        clock,
        Arc::new(MockSigner::default()),
        provider.clone(),
    )
    .unwrap();
    assert_eq!(run(&fixture, "first"), Err(GithubError::ClockInvalid));
    assert_eq!(
        run(&fixture, "second"),
        Err(GithubError::ReconciliationRequired)
    );
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(provider.reads.load(Ordering::SeqCst), 0);
}
#[test]
fn stalled_wall_clock_cannot_extend_token_lifetime_during_exchange() {
    let start = Moment {
        unix: 1_800_000_000,
        elapsed: 0,
    };
    let late = Moment {
        elapsed: 3600,
        ..start
    };
    let clock = Arc::new(ScriptedClock {
        samples: Mutex::new([start, start, start, late].into()),
        last: late,
    });
    let provider = Arc::new(MockProvider::default());
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        clock,
        Arc::new(MockSigner::default()),
        provider.clone(),
    )
    .unwrap();
    assert_eq!(
        run(&fixture, "first"),
        Err(GithubError::InvalidProviderResult)
    );
    assert_eq!(
        run(&fixture, "second"),
        Err(GithubError::ReconciliationRequired)
    );
    assert_eq!(provider.reads.load(Ordering::SeqCst), 0);
}

struct OneShotPanicClock {
    calls: AtomicUsize,
}
impl TimeSource for OneShotPanicClock {
    fn now(&self) -> Moment {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 3 {
            panic!("synthetic clock interruption after mint");
        }
        Moment {
            unix: 1_800_000_000,
            elapsed: 0,
        }
    }
}
#[test]
fn clock_panic_after_mint_keeps_the_receipt_for_explicit_revocation() {
    let provider = Arc::new(MockProvider::default());
    let fixture = Fixture::new(
        Binding::fixture(),
        4242,
        Arc::new(OneShotPanicClock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(MockSigner::default()),
        provider.clone(),
    )
    .unwrap();
    let approval = fixture.simulate_approval("mint", 4242).unwrap();
    assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
    assert_eq!(fixture.invoke(&approval), Err(GithubError::OutcomeUnknown));
    assert_eq!(
        run(&fixture, "another"),
        Err(GithubError::ReconciliationRequired)
    );
    assert_eq!(provider.reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.revoke_provider().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
    assert_eq!(provider.revocations.load(Ordering::SeqCst), 1);
}
