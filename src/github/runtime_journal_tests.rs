use super::super::journal::Fault;
use super::super::{inspect_synthetic_intents, JournalError};
use super::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Barrier;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aegis-durable-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(path: &Path, provider: Arc<dyn Provider>, clock: Arc<dyn TimeSource>) -> Fixture {
    Fixture::new(
        Binding::fixture(),
        4242,
        clock,
        Arc::new(MockSigner::default()),
        provider,
    )
    .unwrap()
    .attach_new_journal(path)
    .unwrap()
}
fn run(fixture: &Fixture, id: &str) -> Result<RepositoryProjection, GithubError> {
    fixture.invoke(&fixture.simulate_approval(id, 4242)?)
}
#[test]
fn durable_success_and_revocation_have_no_restored_authority_or_secret_bytes() {
    let directory = Directory::new();
    let path = directory.journal();
    super::journal_demo(&path).unwrap();
    let report = inspect_synthetic_intents(&path).unwrap();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.unresolved_tokens, 0);
    assert!(!report.reconciliation_required);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
    assert!(!report.automatic_retry_allowed);
    let bytes = fs::read(path.join("intents.jsonl")).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains(SYNTHETIC_TOKEN));
    assert!(!text.contains(SYNTHETIC_JWT));
    assert!(!text.contains("Bearer"));
    assert!(text.contains("synthetic-github-key")); // Reference only, never material.
    assert_eq!(
        super::journal_demo(&path),
        Err(JournalError::DestinationExists)
    );
}
#[test]
fn every_write_sync_fault_blocks_effects_and_retains_consumed_state() {
    for sequence in 2..=10 {
        for fault in [
            Fault::BeforeWrite,
            Fault::PartialWrite,
            Fault::AfterWrite,
            Fault::AfterSync,
        ] {
            let directory = Directory::new();
            let path = directory.journal();
            let provider = Arc::new(MockProvider::default());
            let fixture = fixture(&path, provider.clone(), Arc::new(ManualTime::new()));
            fixture.journal.as_ref().unwrap().fault(sequence, fault);
            let approved = fixture.simulate_approval("once", 4242).unwrap();
            let result = fixture.invoke(&approved);
            if sequence <= 7 {
                assert!(result.is_err(), "sequence {sequence}");
                assert_eq!(fixture.invoke(&approved), result);
                assert!(fixture.simulate_approval("fresh-id", 4242).is_err());
            } else {
                result.unwrap();
                assert!(matches!(
                    fixture.revoke_provider(),
                    Err(GithubError::PersistenceUnavailable) | Ok(RevocationStatus::OutcomeUnknown)
                ));
                assert!(fixture.simulate_approval("fresh-id", 4242).is_err());
            }
            let exchanges = provider.exchanges.load(Ordering::SeqCst);
            let reads = provider.reads.load(Ordering::SeqCst);
            let revocations = provider.revocations.load(Ordering::SeqCst);
            assert_eq!(
                exchanges,
                usize::from(sequence >= 4),
                "exchange sequence {sequence}"
            );
            assert_eq!(
                reads,
                usize::from(sequence >= 7),
                "read sequence {sequence}"
            );
            assert_eq!(
                revocations,
                usize::from(sequence >= 10),
                "revoke sequence {sequence}"
            );
            drop(fixture);
            let recovered = inspect_synthetic_intents(&path);
            if matches!(fault, Fault::PartialWrite) {
                assert_eq!(recovered, Err(JournalError::InvalidJournal));
            } else {
                let report = recovered.unwrap();
                assert_eq!(report.restored_grants, 0);
                assert!(!report.automatic_retry_allowed);
                assert_eq!(
                    report.reservations_consumed,
                    usize::from(sequence > 2 || !matches!(fault, Fault::BeforeWrite))
                );
            }
        }
    }
}
#[test]
fn identical_and_conflicting_requests_do_not_duplicate_durable_reservations() {
    let directory = Directory::new();
    let path = directory.journal();
    let provider = Arc::new(MockProvider::default());
    let fixture = fixture(&path, provider.clone(), Arc::new(ManualTime::new()));
    let approved = fixture.simulate_approval("same", 4242).unwrap();
    fixture.invoke(&approved).unwrap();
    fixture.invoke(&approved).unwrap();
    let mut changed = approved.clone();
    changed.expires_elapsed += 1;
    assert_eq!(fixture.invoke(&changed), Err(GithubError::RequestConflict));
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(provider.reads.load(Ordering::SeqCst), 1);
    drop(fixture);
    assert_eq!(
        inspect_synthetic_intents(&path)
            .unwrap()
            .reservations_consumed,
        1
    );
}
#[test]
fn cached_reads_reference_the_original_issuance_and_refresh_keeps_both() {
    let directory = Directory::new();
    let path = directory.journal();
    let provider = Arc::new(MockProvider::default());
    let clock = Arc::new(ManualTime::new());
    let fixture = fixture(&path, provider.clone(), clock.clone());
    run(&fixture, "first").unwrap();
    run(&fixture, "cache").unwrap();
    clock.advance(3540);
    run(&fixture, "refresh").unwrap();
    fixture.revoke_provider().unwrap();
    assert_eq!(provider.exchanges.load(Ordering::SeqCst), 2);
    assert_eq!(provider.revocations.load(Ordering::SeqCst), 2);
    drop(fixture);
    let report = inspect_synthetic_intents(&path).unwrap();
    assert_eq!(report.reservations_consumed, 3);
    assert_eq!(report.unresolved_tokens, 0);
    assert!(!report.reconciliation_required);
}
struct PausingProvider {
    base: MockProvider,
    entered: Barrier,
    release: Barrier,
}
impl Provider for PausingProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        self.entered.wait();
        self.release.wait();
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
fn concurrent_final_reservation_and_revoke_share_the_durable_order() {
    let directory = Directory::new();
    let path = directory.journal();
    let provider = Arc::new(PausingProvider {
        base: MockProvider::default(),
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let fixture = Arc::new(fixture(
        &path,
        provider.clone(),
        Arc::new(ManualTime::new()),
    ));
    let first = fixture.simulate_approval("first", 4242).unwrap();
    let second = fixture.simulate_approval("second", 4242).unwrap();
    let worker_fixture = fixture.clone();
    let worker_first = first.clone();
    let worker = std::thread::spawn(move || worker_fixture.invoke(&worker_first));
    provider.entered.wait();
    assert_eq!(fixture.invoke(&first), Err(GithubError::InProgress));
    assert_eq!(fixture.invoke(&second), Err(GithubError::InProgress));
    fixture.revoke_future().unwrap();
    assert_eq!(fixture.invoke(&second), Err(GithubError::Revoked));
    assert_eq!(inspect_synthetic_intents(&path), Err(JournalError::Busy));
    provider.release.wait();
    worker.join().unwrap().unwrap();
    fixture.revoke_provider().unwrap();
    drop(fixture);
    let report = inspect_synthetic_intents(&path).unwrap();
    assert_eq!(report.reservations_consumed, 1);
    assert!(report.local_authority_revoked);
    assert_eq!(report.unresolved_tokens, 0);
}
struct UnknownWithClock {
    base: MockProvider,
    clock: Arc<ManualTime>,
}
impl Provider for UnknownWithClock {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        self.base.exchange(request, at);
        self.clock.unix.fetch_sub(1, Ordering::SeqCst);
        ExchangeOutcome::Unknown
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.base.metadata(request)
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.base.revoke(request)
    }
}
#[test]
fn clock_regression_never_erases_persisted_unknown_or_restores_a_session() {
    let directory = Directory::new();
    let path = directory.journal();
    let clock = Arc::new(ManualTime::new());
    let provider = Arc::new(UnknownWithClock {
        base: MockProvider::default(),
        clock: clock.clone(),
    });
    let fixture = fixture(&path, provider.clone(), clock);
    let approved = fixture.simulate_approval("unknown", 4242).unwrap();
    assert_eq!(fixture.invoke(&approved), Err(GithubError::OutcomeUnknown));
    assert_eq!(fixture.invoke(&approved), Err(GithubError::OutcomeUnknown));
    drop(fixture);
    let report = inspect_synthetic_intents(&path).unwrap();
    assert_eq!(report.uncertain_mints, 1);
    assert_eq!(report.unknown_operations, 1);
    assert!(report.reconciliation_required);
    assert_eq!(report.restored_sessions, 0);
}

struct CrashingProvider {
    base: MockProvider,
    mode: String,
    effects: PathBuf,
}
impl CrashingProvider {
    fn effect(&self, name: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.effects)
            .unwrap();
        writeln!(file, "{name}").unwrap();
        file.sync_all().unwrap();
    }
    fn crash(&self, mode: &str) {
        if self.mode == mode {
            std::process::exit(86);
        }
    }
}
impl Provider for CrashingProvider {
    fn exchange(&self, request: ExchangeRequest, at: Moment) -> ExchangeOutcome {
        self.crash("before_issuance");
        let result = self.base.exchange(request, at);
        self.effect("exchange");
        self.crash("after_issuance");
        result
    }
    fn metadata(&self, request: MetadataRequest<'_>) -> ReadOutcome {
        self.crash("before_read");
        let result = self.base.metadata(request);
        self.effect("read");
        self.crash("after_read");
        result
    }
    fn revoke(&self, request: RevokeRequest<'_>) -> RevokeOutcome {
        self.crash("before_revocation");
        let result = self.base.revoke(request);
        self.effect("revoke");
        self.crash("after_revocation");
        result
    }
}
#[test]
fn crash_worker() {
    let Some(mode) = std::env::var_os("AEGIS_SYNTHETIC_INTENT_CRASH_TEST") else {
        return;
    };
    let mode = mode.into_string().unwrap();
    let path = PathBuf::from(std::env::var_os("AEGIS_SYNTHETIC_INTENT_PATH").unwrap());
    let provider = Arc::new(CrashingProvider {
        base: MockProvider::default(),
        mode: mode.clone(),
        effects: path.join("mock-effects.txt"),
    });
    let fixture = fixture(&path, provider, Arc::new(ManualTime::new()));
    if mode == "before_mint_intent" {
        fixture
            .journal
            .as_ref()
            .unwrap()
            .fault(3, Fault::BeforeWrite);
    }
    let result = run(&fixture, "crash-fixture");
    if mode == "before_mint_intent" {
        assert_eq!(result, Err(GithubError::PersistenceUnavailable));
        std::process::exit(86);
    }
    result.unwrap();
    if mode == "after_terminal" {
        std::process::exit(86);
    }
    fixture.revoke_provider().unwrap();
    if mode == "after_revoke_terminal" {
        std::process::exit(86);
    }
    panic!("unknown synthetic crash scenario");
}
#[test]
fn fresh_process_crashes_before_after_issuance_read_and_revoke_reconcile_without_replay() {
    for mode in [
        "before_mint_intent",
        "before_issuance",
        "after_issuance",
        "before_read",
        "after_read",
        "after_terminal",
        "before_revocation",
        "after_revocation",
        "after_revoke_terminal",
    ] {
        let directory = Directory::new();
        let path = directory.journal();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "github::runtime::journal_tests::crash_worker",
                "--nocapture",
            ])
            .env("AEGIS_SYNTHETIC_INTENT_CRASH_TEST", mode)
            .env("AEGIS_SYNTHETIC_INTENT_PATH", &path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let before = fs::read(path.join("intents.jsonl")).unwrap();
        let report = inspect_synthetic_intents(&path).unwrap();
        assert_eq!(report.reservations_consumed, 1);
        assert_eq!(report.restored_grants, 0);
        assert_eq!(report.restored_sessions, 0);
        assert!(!report.automatic_retry_allowed);
        assert_eq!(
            report.uncertain_mints,
            usize::from(matches!(mode, "before_issuance" | "after_issuance"))
        );
        assert_eq!(
            report.uncertain_revocations,
            usize::from(matches!(mode, "before_revocation" | "after_revocation"))
        );
        assert_eq!(
            report.reconciliation_required,
            mode != "after_revoke_terminal"
        );
        let effects = fs::read_to_string(path.join("mock-effects.txt")).unwrap_or_default();
        let expected = match mode {
            "before_mint_intent" | "before_issuance" => "",
            "after_issuance" | "before_read" => "exchange\n",
            "after_read" | "after_terminal" | "before_revocation" => "exchange\nread\n",
            _ => "exchange\nread\nrevoke\n",
        };
        assert_eq!(effects, expected);
        assert_eq!(fs::read(path.join("intents.jsonl")).unwrap(), before);
        assert_eq!(
            super::journal_demo(&path),
            Err(JournalError::DestinationExists)
        );
        assert_eq!(
            fs::read_to_string(path.join("mock-effects.txt")).unwrap_or_default(),
            effects
        );
    }
}

#[test]
fn failed_durable_local_revoke_never_turns_into_success_on_replay() {
    let directory = Directory::new();
    let path = directory.journal();
    let provider = Arc::new(MockProvider::default());
    let fixture = fixture(&path, provider.clone(), Arc::new(ManualTime::new()));
    run(&fixture, "first").unwrap();
    fixture
        .journal
        .as_ref()
        .unwrap()
        .fault(8, Fault::BeforeWrite);
    assert_eq!(
        fixture.revoke_future(),
        Err(GithubError::PersistenceUnavailable)
    );
    assert_eq!(
        fixture.revoke_future(),
        Err(GithubError::PersistenceUnavailable)
    );
    assert_eq!(
        fixture.revoke_provider(),
        Err(GithubError::PersistenceUnavailable)
    );
    assert_eq!(provider.revocations.load(Ordering::SeqCst), 0);
    drop(fixture);
    let report = inspect_synthetic_intents(&path).unwrap();
    assert!(!report.local_authority_revoked);
    assert_eq!(report.unresolved_tokens, 1);
}
#[test]
fn fixed_public_drill_path_cannot_report_success_for_uncertain_revocation() {
    for sequence in [9, 10] {
        let directory = Directory::new();
        let fixture = fixture(
            &directory.journal(),
            Arc::new(MockProvider::default()),
            Arc::new(ManualTime::new()),
        );
        fixture
            .journal
            .as_ref()
            .unwrap()
            .fault(sequence, Fault::BeforeWrite);
        assert_eq!(
            super::finish_journal_demo(fixture),
            Err(JournalError::Incomplete)
        );
    }
}
