use super::*;
use crate::github::{inspect_synthetic_intents, JournalFault, RevocationStatus};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "aegis-broker-v2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
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
struct Harness {
    directory: Directory,
    control: Control,
    client: AgentClient,
    clock: Arc<ManualClock>,
}
impl Harness {
    fn new(uses: u32) -> Self {
        let directory = Directory::new();
        let clock = Arc::new(ManualClock::default());
        let setup = OperationSetup {
            uses,
            ..OperationSetup::synthetic_github()
        };
        let (control, client) =
            Control::synthetic_github(setup, clock.clone(), &directory.journal()).unwrap();
        Self {
            directory,
            control,
            client,
            clock,
        }
    }
    fn adapter(&self) -> &Arc<crate::github::BrokerAdapter> {
        match &self.control.shared.executor {
            ExecutorKind::Github(adapter) => adapter,
            _ => panic!("Github fixture"),
        }
    }
    fn approved(&self, id: &str) -> u64 {
        let id = self
            .client
            .prepare_operation(input(id))
            .unwrap()
            .prepared_request_id;
        self.client.request_operation_approval(id).unwrap();
        let review = self.control.inspect_operation_approval(id).unwrap();
        self.control
            .approve_operation_reviewed(id, &review)
            .unwrap();
        id
    }
    fn close(self) -> (Directory, crate::github::JournalRecovery) {
        let Self {
            directory,
            control,
            client,
            clock,
        } = self;
        drop(control);
        drop(client);
        drop(clock);
        let report = inspect_synthetic_intents(&directory.journal()).unwrap();
        (directory, report)
    }
}
fn input(id: &str) -> OperationPrepareInput {
    OperationPrepareInput {
        request_id: RequestId::new(id).unwrap(),
        profile_id: ProfileId::new("github-metadata").unwrap(),
        operation: OperationIntent::GithubMetadata(GithubMetadataParameters {
            repository_id: 4242,
        }),
    }
}
#[test]
fn main_engine_reviews_reserves_projects_replays_and_revokes_metadata() {
    let h = Harness::new(2);
    let first = h.client.prepare_operation(input("first")).unwrap();
    let id = first.prepared_request_id;
    assert_eq!(first.state, Lifecycle::Prepared);
    assert_eq!(
        h.client.invoke_operation(id),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    h.client.request_operation_approval(id).unwrap();
    let review = h.control.inspect_operation_approval(id).unwrap();
    assert_eq!(review.request_id, RequestId::new("first").unwrap());
    assert_eq!(review.remaining_uses, 2);
    assert_eq!(
        review.profile,
        OperationProfile::GithubMetadata(GithubProfile::synthetic())
    );
    h.control.approve_operation_reviewed(id, &review).unwrap();
    let done = h.client.invoke_operation(id).unwrap();
    assert_eq!(done.state, Lifecycle::Succeeded);
    assert!(matches!(
        done.result,
        Some(OperationResult::GithubMetadata(
            crate::github::RepositoryProjection {
                repository_id: 4242,
                private: false,
                archived: false
            }
        ))
    ));
    assert_eq!(h.client.invoke_operation(id).unwrap(), done);
    assert_eq!(h.control.remaining_uses().unwrap(), 1);
    assert_eq!(h.adapter().test_counts(), (1, 1, 0));
    h.control.revoke().unwrap();
    assert_eq!(h.adapter().test_counts(), (1, 1, 0));
    assert_eq!(
        h.control.revoke_provider_tokens().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
    assert_eq!(h.adapter().test_counts(), (1, 1, 1));
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
    assert!(!report.reconciliation_required);
}
#[test]
fn every_legacy_handle_wrapper_rejects_github_before_mutation() {
    let h = Harness::new(2);
    let id = h
        .client
        .prepare_operation(input("legacy-denied"))
        .unwrap()
        .prepared_request_id;
    assert_eq!(h.client.request_approval(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(h.client.cancel(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(h.client.invoke(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(h.client.status(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(h.control.approve(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(h.control.inspect_approval(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(
        h.client.operation_status(id).unwrap().state,
        Lifecycle::Prepared
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 2);
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    h.client.request_operation_approval(id).unwrap();
    let reviewed = h.control.inspect_operation_approval(id).unwrap();
    h.control.approve_operation_reviewed(id, &reviewed).unwrap();
    assert_eq!(h.client.invoke(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(
        h.client.operation_status(id).unwrap().state,
        Lifecycle::Approved
    );
}
#[test]
fn nonfixture_or_bounded_github_setup_is_rejected_without_journal_creation() {
    for mutation in [
        |s: &mut OperationSetup| s.approval_mode = ApprovalMode::BoundedSession,
        |s: &mut OperationSetup| s.maximum_concurrent = 2,
        |s: &mut OperationSetup| s.maximum_requests = 33,
        |s: &mut OperationSetup| s.uses = 33,
        |s: &mut OperationSetup| s.uses = 0,
        |s: &mut OperationSetup| s.profile = OperationProfile::IssueStatus(Profile::synthetic()),
        |s: &mut OperationSetup| {
            if let OperationProfile::GithubMetadata(p) = &mut s.profile {
                p.account_id = 999;
            }
        },
        |s: &mut OperationSetup| {
            if let OperationProfile::GithubMetadata(p) = &mut s.profile {
                p.output_contract = 2;
            }
        },
        |s: &mut OperationSetup| {
            if let OperationProfile::GithubMetadata(p) = &mut s.profile {
                p.credential.secret_id = "real-key".into();
            }
        },
    ] {
        let dir = Directory::new();
        let mut setup = OperationSetup::synthetic_github();
        mutation(&mut setup);
        assert!(matches!(
            Control::synthetic_github(setup, Arc::new(ManualClock::default()), &dir.journal()),
            Err(ErrorCode::InvalidRequest)
        ));
        assert!(!dir.journal().exists());
    }
}
#[test]
fn exact_review_cannot_substitute_any_core_authority_or_operation_binding() {
    let h = Harness::new(2);
    let id = h
        .client
        .prepare_operation(input("review"))
        .unwrap()
        .prepared_request_id;
    h.client.request_operation_approval(id).unwrap();
    let review = h.control.inspect_operation_approval(id).unwrap();
    for mutation in [
        |r: &mut OperationApprovalView| r.request_id = RequestId::new("other").unwrap(),
        |r: &mut OperationApprovalView| r.prepared_request_id += 1,
        |r: &mut OperationApprovalView| r.principal = PrincipalId::new("other").unwrap(),
        |r: &mut OperationApprovalView| r.session += 1,
        |r: &mut OperationApprovalView| r.policy_generation += 1,
        |r: &mut OperationApprovalView| r.expires_at += 1,
        |r: &mut OperationApprovalView| r.remaining_uses += 1,
        |r: &mut OperationApprovalView| r.limits.maximum_seconds += 1,
        |r: &mut OperationApprovalView| {
            r.operation = OperationIntent::IssueStatus(Parameters {
                repository_id: 4242,
                issue_number: 7,
            })
        },
        |r: &mut OperationApprovalView| {
            if let OperationProfile::GithubMetadata(p) = &mut r.profile {
                p.installation_id += 1;
            }
        },
        |r: &mut OperationApprovalView| {
            if let OperationProfile::GithubMetadata(p) = &mut r.profile {
                p.credential.version += 1;
            }
        },
        |r: &mut OperationApprovalView| {
            if let OperationProfile::GithubMetadata(p) = &mut r.profile {
                p.requested_metadata = GithubPermission::Write;
            }
        },
    ] {
        let mut changed = review.clone();
        mutation(&mut changed);
        assert_eq!(
            h.control.approve_operation_reviewed(id, &changed),
            Err(ErrorCode::ApprovalRequired)
        );
    }
    let other = Harness::new(2);
    let other_id = other
        .client
        .prepare_operation(input("review"))
        .unwrap()
        .prepared_request_id;
    other.client.request_operation_approval(other_id).unwrap();
    assert_eq!(
        other.control.approve_operation_reviewed(other_id, &review),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
}
#[test]
fn changed_operation_with_same_request_id_conflicts_before_effects() {
    let h = Harness::new(2);
    h.client.prepare_operation(input("same")).unwrap();
    let mut changed = input("same");
    changed.operation = OperationIntent::IssueStatus(Parameters {
        repository_id: 4242,
        issue_number: 7,
    });
    assert_eq!(
        h.client.prepare_operation(changed),
        Err(ErrorCode::RequestIdConflict)
    );
    let mut outside = input("outside");
    outside.operation =
        OperationIntent::GithubMetadata(GithubMetadataParameters { repository_id: 999 });
    assert_eq!(
        h.client.prepare_operation(outside),
        Err(ErrorCode::ScopeDenied)
    );
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 2);
}
#[test]
fn stale_profile_key_version_and_generation_never_dispatch() {
    for restore in [false, true] {
        let h = Harness::new(2);
        let id = h.approved("stale");
        let mut revised = GithubProfile::synthetic();
        revised.revision += 1;
        revised.credential.version += 1;
        h.control
            .replace_operation_profile(OperationProfile::GithubMetadata(revised))
            .unwrap();
        if restore {
            h.control
                .replace_operation_profile(OperationProfile::GithubMetadata(
                    GithubProfile::synthetic(),
                ))
                .unwrap();
        }
        assert_eq!(h.client.invoke_operation(id), Err(ErrorCode::PolicyChanged));
        assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    }
}
#[test]
fn approval_expiry_cancel_and_revoke_prevent_durable_reservation() {
    for mode in 0..3 {
        let h = Harness::new(2);
        let id = h.approved("prevent");
        let expected = match mode {
            0 => {
                h.clock.set(15);
                ErrorCode::RequestExpired
            }
            1 => {
                h.client.cancel_operation(id).unwrap();
                let result = h.client.invoke_operation(id).unwrap();
                assert_eq!(result.state, Lifecycle::Canceled);
                assert_eq!(h.adapter().test_counts(), (0, 0, 0));
                continue;
            }
            _ => {
                h.control.revoke().unwrap();
                ErrorCode::GrantRevoked
            }
        };
        assert_eq!(h.client.invoke_operation(id), Err(expected));
        assert_eq!(h.control.remaining_uses().unwrap(), 2);
        assert_eq!(h.adapter().test_counts(), (0, 0, 0));
        let (_, report) = h.close();
        assert_eq!(report.reservations_consumed, 0);
    }
}
#[test]
fn journal_records_reviewed_and_consumed_budget_separately() {
    let h = Harness::new(2);
    let first = h.approved("first");
    let second = h.approved("second");
    h.client.invoke_operation(first).unwrap();
    h.client.invoke_operation(second).unwrap();
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    let records: Vec<serde_json::Value> =
        fs::read_to_string(h.directory.journal().join("intents.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let reservations: Vec<_> = records
        .iter()
        .filter(|r| r["event"]["type"] == "broker_reserve")
        .collect();
    assert_eq!(reservations.len(), 2);
    assert_eq!(
        reservations[1]["event"]["review"]["reviewed_remaining_uses"],
        2
    );
    assert_eq!(reservations[1]["event"]["review"]["remaining_before"], 1);
    assert_eq!(reservations[1]["event"]["review"]["remaining_after"], 0);
    assert_eq!(
        reservations[1]["event"]["review"]["reviewed_request_id"],
        "second"
    );
    assert!(records.iter().all(|r| r["schema_version"] == 2));
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 2);
}
#[test]
fn reservation_and_terminal_io_faults_consume_once_and_block_fresh_ids() {
    for sequence in [2, 3, 4, 5, 6, 7] {
        for fault in [
            JournalFault::BeforeWrite,
            JournalFault::AfterWrite,
            JournalFault::AfterSync,
        ] {
            let h = Harness::new(2);
            h.adapter().test_fault(sequence, fault);
            let id = h.approved("fault");
            let failed = h.client.invoke_operation(id).unwrap();
            if sequence == 3 {
                assert_eq!(failed.state, Lifecycle::Failed);
                assert_eq!(failed.error, Some(ErrorCode::PersistenceUnavailable));
            } else {
                assert_eq!(failed.state, Lifecycle::OutcomeUnknown);
                assert_eq!(failed.error, Some(ErrorCode::OutcomeUnknown));
            }
            assert_eq!(h.client.invoke_operation(id).unwrap(), failed);
            assert_eq!(h.control.remaining_uses().unwrap(), 1);
            assert_eq!(
                h.client.prepare_operation(input("fresh")),
                Err(ErrorCode::ReconciliationRequired)
            );
            let (exchanges, reads, _) = h.adapter().test_counts();
            assert_eq!(exchanges, usize::from(sequence >= 4));
            assert_eq!(reads, usize::from(sequence >= 7));
        }
    }
}
struct Release(Arc<crate::github::BrokerPause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
#[test]
fn core_last_use_concurrency_and_after_reserve_revocation_preserve_one_effect() {
    let h = Harness::new(1);
    let first = h.approved("first");
    let second = h.approved("second");
    let (receiver, pause) = h.adapter().test_pause();
    let _release = Release(pause.clone());
    let client = h.client.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(first).unwrap());
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    assert_eq!(
        h.client.invoke_operation(first).unwrap().state,
        Lifecycle::Dispatched
    );
    assert_eq!(
        h.client.invoke_operation(second),
        Err(ErrorCode::BudgetExhausted)
    );
    h.control.revoke().unwrap();
    assert_eq!(
        h.client.invoke_operation(second),
        Err(ErrorCode::GrantRevoked)
    );
    pause.release();
    assert_eq!(worker.join().unwrap().state, Lifecycle::Succeeded);
    assert_eq!(h.adapter().test_counts(), (1, 1, 0));
    h.control.revoke_provider_tokens().unwrap();
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 1);
}
#[test]
fn cannot_reuse_reserved_work_or_recreate_an_existing_journal() {
    let h = Harness::new(1);
    let id = h.approved("one-shot");
    h.client.invoke_operation(id).unwrap();
    let path = h.directory.journal();
    let (directory, report) = h.close();
    assert_eq!(report.reservations_consumed, 1);
    assert!(matches!(
        Control::synthetic_github(
            OperationSetup::synthetic_github(),
            Arc::new(ManualClock::default()),
            &path
        ),
        Err(ErrorCode::PersistenceUnavailable)
    ));
    assert_eq!(
        inspect_synthetic_intents(&path)
            .unwrap()
            .reservations_consumed,
        1
    );
    drop(directory);
}
#[test]
fn result_kind_substitution_is_rejected_by_core_projection() {
    let h = Harness::new(1);
    let id = h
        .client
        .prepare_operation(input("shape"))
        .unwrap()
        .prepared_request_id;
    let review = h.control.inspect_operation_approval(id).unwrap();
    let wrong = Ok(OperationResult::IssueStatus(StatusProjection {
        repository_id: 4242,
        issue_number: 7,
        state: IssueState::Open,
    }));
    assert_eq!(
        validate_outcome(wrong, &review),
        Err(ErrorCode::InvalidProviderResult)
    );
}

#[test]
fn static_github_uncertainty_survives_session_expiry_rollback_and_stop_without_authority() {
    for mode in 0..3 {
        let h = Harness::new(2);
        h.clock.set(5);
        h.adapter().test_fault(2, JournalFault::AfterSync);
        let id = h.approved("retained");
        let unknown = h.client.invoke_operation(id).unwrap();
        assert_eq!(unknown.state, Lifecycle::OutcomeUnknown);
        match mode {
            0 => h.clock.set(1805),
            1 => h.clock.set(4),
            _ => h.control.stop().unwrap(),
        };
        assert_eq!(h.client.invoke_operation(id).unwrap(), unknown);
        assert_eq!(h.client.operation_status(id).unwrap(), unknown);
        assert!(h.client.prepare_operation(input("new")).is_err());
        assert!(h.client.request_operation_approval(id).is_err());
        assert_eq!(h.adapter().test_counts(), (0, 0, 0));
        assert_eq!(h.control.remaining_uses().unwrap(), 1);
    }
}
#[test]
fn static_unknown_shortcut_does_not_cross_core_instance_or_legacy_operation() {
    let h = Harness::new(1);
    h.adapter().test_fault(2, JournalFault::AfterSync);
    let id = h.approved("unknown");
    h.client.invoke_operation(id).unwrap();
    let other = Harness::new(1);
    assert_eq!(other.client.operation_status(id), Err(ErrorCode::NotFound));
    struct Unknown;
    impl Executor for Unknown {
        fn execute(&self, _: &Dispatch) -> ProviderOutcome {
            ProviderOutcome::Unknown
        }
    }
    let clock = Arc::new(ManualClock::default());
    let (c, a) = Control::synthetic(
        SyntheticSetup {
            approval_mode: ApprovalMode::BoundedSession,
            ..SyntheticSetup::default()
        },
        clock.clone(),
        Arc::new(Unknown),
    )
    .unwrap();
    let legacy = a
        .prepare(PrepareInput {
            request_id: RequestId::new("legacy").unwrap(),
            profile_id: ProfileId::new("issue-status").unwrap(),
            parameters: Parameters {
                repository_id: 4242,
                issue_number: 7,
            },
        })
        .unwrap()
        .prepared_request_id;
    a.invoke(legacy).unwrap();
    clock.set(1800);
    assert_eq!(a.status(legacy), Err(ErrorCode::SessionExpired));
    drop(c);
}

#[test]
fn legacy_missing_handle_error_precedence_is_preserved() {
    let clock = Arc::new(ManualClock::default());
    let (c, a) = Control::synthetic(
        SyntheticSetup::default(),
        clock.clone(),
        Arc::new(crate::fake::FakeProvider::default()),
    )
    .unwrap();
    let id = a
        .prepare(PrepareInput {
            request_id: RequestId::new("existing").unwrap(),
            profile_id: ProfileId::new("issue-status").unwrap(),
            parameters: Parameters {
                repository_id: 4242,
                issue_number: 7,
            },
        })
        .unwrap()
        .prepared_request_id;
    a.request_approval(id).unwrap();
    let review = c.inspect_approval(id).unwrap();
    clock.set(1800);
    assert_eq!(a.status(999), Err(ErrorCode::SessionExpired));
    assert_eq!(a.invoke(999), Err(ErrorCode::SessionExpired));
    assert_eq!(a.cancel(999), Err(ErrorCode::SessionExpired));
    assert_eq!(a.request_approval(999), Err(ErrorCode::SessionExpired));
    assert_eq!(c.approve(999), Err(ErrorCode::SessionExpired));
    assert_eq!(
        c.approve_reviewed(999, &review),
        Err(ErrorCode::SessionExpired)
    );
    let (c, a) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(crate::fake::FakeProvider::default()),
    )
    .unwrap();
    let id = a
        .prepare(PrepareInput {
            request_id: RequestId::new("revoked").unwrap(),
            profile_id: ProfileId::new("issue-status").unwrap(),
            parameters: Parameters {
                repository_id: 4242,
                issue_number: 7,
            },
        })
        .unwrap()
        .prepared_request_id;
    a.request_approval(id).unwrap();
    let review = c.inspect_approval(id).unwrap();
    c.revoke().unwrap();
    assert_eq!(c.approve(999), Err(ErrorCode::GrantRevoked));
    assert_eq!(
        c.approve_reviewed(999, &review),
        Err(ErrorCode::GrantRevoked)
    );
}

#[cfg(feature = "signing-spike")]
#[path = "broker_signing_tests.rs"]
mod signing_tests;
