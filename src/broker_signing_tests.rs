use super::*;

impl Harness {
    fn signed(uses: u32) -> Self {
        let directory = Directory::new();
        let clock = Arc::new(ManualClock::default());
        let (control, client) = Control::synthetic_github_signed(
            OperationSetup {
                uses,
                ..OperationSetup::synthetic_github()
            },
            clock.clone(),
            &directory.journal(),
        )
        .unwrap();
        Self {
            directory,
            control,
            client,
            clock,
        }
    }
}
#[test]
fn reviewed_signed_operation_replays_and_reuses_token_without_resigning() {
    let h = Harness::signed(2);
    let first = h.approved("signed-first");
    let second = h.approved("signed-second");
    let result = h.client.invoke_operation(first).unwrap();
    assert_eq!(result.state, Lifecycle::Succeeded);
    assert_eq!(h.client.invoke_operation(first).unwrap(), result);
    assert_eq!(
        h.client.invoke_operation(second).unwrap().state,
        Lifecycle::Succeeded
    );
    assert_eq!(h.adapter().test_signatures(), 1);
    assert_eq!(h.adapter().test_counts(), (1, 2, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    let output = serde_json::to_string(&result).unwrap();
    let journal = fs::read_to_string(h.directory.journal().join("intents.jsonl")).unwrap();
    for bytes in [output.as_str(), journal.as_str()] {
        assert!(!bytes.contains("PRIVATE KEY"));
        assert!(!bytes.contains("eyJ"));
        assert!(!bytes.contains("AEGIS_SYNTHETIC_GITHUB_INSTALLATION_TOKEN"));
    }
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 2);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
    assert!(!report.automatic_retry_allowed);
}
#[test]
fn unapproved_stale_and_expired_reviews_never_sign() {
    for mode in 0..4 {
        let h = Harness::signed(2);
        let id = h
            .client
            .prepare_operation(input("denied"))
            .unwrap()
            .prepared_request_id;
        assert_eq!(
            h.client.invoke_operation(id),
            Err(ErrorCode::ApprovalRequired)
        );
        h.client.request_operation_approval(id).unwrap();
        let review = h.control.inspect_operation_approval(id).unwrap();
        h.control.approve_operation_reviewed(id, &review).unwrap();
        match mode {
            0 => h.control.revoke().unwrap(),
            1 => h.clock.set(15),
            2 => {
                let mut p = GithubProfile::synthetic();
                p.credential.version = 2;
                h.control
                    .replace_operation_profile(OperationProfile::GithubMetadata(p))
                    .unwrap();
            }
            _ => {
                let mut p = GithubProfile::synthetic();
                p.revision = 2;
                h.control
                    .replace_operation_profile(OperationProfile::GithubMetadata(p))
                    .unwrap();
            }
        }
        assert!(h.client.invoke_operation(id).is_err());
        assert_eq!(h.adapter().test_signatures(), 0);
        assert_eq!(h.adapter().test_counts(), (0, 0, 0));
        assert_eq!(h.control.remaining_uses().unwrap(), 2);
    }
}
#[test]
fn durable_sync_faults_bound_signing_and_preserve_unknown_without_retry() {
    for sequence in [2, 3, 4, 5, 6, 7] {
        for fault in [
            JournalFault::BeforeWrite,
            JournalFault::AfterWrite,
            JournalFault::AfterSync,
        ] {
            let h = Harness::signed(2);
            h.adapter().test_fault(sequence, fault);
            let id = h.approved("signed-fault");
            let result = h.client.invoke_operation(id).unwrap();
            assert_eq!(
                result.state,
                if sequence == 3 {
                    Lifecycle::Failed
                } else {
                    Lifecycle::OutcomeUnknown
                }
            );
            assert_eq!(h.client.invoke_operation(id).unwrap(), result);
            assert_eq!(h.adapter().test_signatures(), u32::from(sequence >= 3));
            assert_eq!(
                h.adapter().test_counts(),
                (usize::from(sequence >= 4), usize::from(sequence >= 7), 0)
            );
            assert_eq!(h.control.remaining_uses().unwrap(), 1);
            assert_eq!(
                h.client.prepare_operation(input("never-retry")),
                Err(ErrorCode::ReconciliationRequired)
            );
        }
    }
}
#[test]
fn signed_unknown_receipt_survives_clock_failure_and_stop() {
    for mode in 0..3 {
        let h = Harness::signed(2);
        h.clock.set(5);
        h.adapter().test_fault(4, JournalFault::AfterSync);
        let id = h.approved("signed-unknown");
        let result = h.client.invoke_operation(id).unwrap();
        assert_eq!(result.state, Lifecycle::OutcomeUnknown);
        match mode {
            0 => h.clock.set(1805),
            1 => h.clock.set(4),
            _ => h.control.stop().unwrap(),
        }
        assert_eq!(h.client.invoke_operation(id).unwrap(), result);
        assert_eq!(h.adapter().test_signatures(), 1);
        assert_eq!(h.adapter().test_counts(), (1, 0, 0));
        assert_eq!(h.control.remaining_uses().unwrap(), 1);
    }
}
#[test]
fn duplicate_and_revoke_after_reservation_preserve_one_signed_dispatch() {
    let h = Harness::signed(1);
    let id = h.approved("race");
    let (entered, pause) = h.adapter().test_pause();
    let release = Release(pause.clone());
    let client = h.client.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        h.client.invoke_operation(id).unwrap().state,
        Lifecycle::Dispatched
    );
    h.control.revoke().unwrap();
    pause.release();
    drop(release);
    assert_eq!(worker.join().unwrap().state, Lifecycle::Succeeded);
    assert_eq!(h.adapter().test_signatures(), 1);
    assert_eq!(h.adapter().test_counts(), (1, 1, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    assert_eq!(
        h.control.revoke_provider_tokens().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
    assert_eq!(h.adapter().test_counts(), (1, 1, 1));
}
#[test]
fn locked_source_after_durable_reservation_cannot_refund_or_sign() {
    let h = Harness::signed(2);
    h.adapter().test_lock_signer();
    let id = h.approved("locked-source");
    let result = h.client.invoke_operation(id).unwrap();
    assert_eq!(result.state, Lifecycle::OutcomeUnknown);
    assert_eq!(h.client.invoke_operation(id).unwrap(), result);
    assert_eq!(h.control.remaining_uses().unwrap(), 1);
    assert_eq!(h.adapter().test_signatures(), 0);
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.incomplete_operations, 1);
    assert!(!report.automatic_retry_allowed);
}
#[test]
fn delayed_reserved_work_uses_shared_clock_and_bounded_signing_lease() {
    for elapsed in [5, 30, 600] {
        let h = Harness::signed(2);
        let id = h.approved("delay");
        let (entered, pause) = h.adapter().test_pause();
        let release = Release(pause.clone());
        let client = h.client.clone();
        let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        h.clock.set(elapsed);
        pause.release();
        drop(release);
        let result = worker.join().unwrap();
        assert_eq!(
            result.state,
            if elapsed == 5 {
                Lifecycle::Succeeded
            } else {
                Lifecycle::Failed
            }
        );
        assert_eq!(h.adapter().test_signatures(), u32::from(elapsed == 5));
        assert_eq!(
            h.adapter().test_counts(),
            if elapsed == 5 { (1, 1, 0) } else { (0, 0, 0) }
        );
        assert_eq!(h.control.remaining_uses().unwrap(), 1);
    }
}
#[test]
fn lock_after_permit_is_known_failure_without_exchange_or_repeat() {
    let h = Harness::signed(2);
    let id = h.approved("late-lock");
    let (entered, pause) = h.adapter().test_pause();
    let release = Release(pause.clone());
    let client = h.client.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    h.adapter().test_lock_signer();
    pause.release();
    drop(release);
    let result = worker.join().unwrap();
    assert_eq!(result.state, Lifecycle::Failed);
    assert_eq!(result.error, Some(ErrorCode::ProviderUnavailable));
    assert_eq!(h.client.invoke_operation(id).unwrap(), result);
    assert_eq!(h.adapter().test_signatures(), 0);
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 1);
    let (_, report) = h.close();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.incomplete_operations, 0);
}
#[test]
fn pre_and_post_sign_panics_retain_uncertainty_without_reminting() {
    for at in [1, 2] {
        let h = Harness::signed(2);
        h.adapter().test_signing_fault(at);
        let id = h.approved("sign-panic");
        let result = h.client.invoke_operation(id).unwrap();
        assert_eq!(result.state, Lifecycle::OutcomeUnknown);
        assert_eq!(h.client.invoke_operation(id).unwrap(), result);
        assert_eq!(h.adapter().test_signatures(), u32::from(at == 2));
        assert_eq!(h.adapter().test_counts(), (0, 0, 0));
        assert_eq!(h.control.remaining_uses().unwrap(), 1);
        let (_, report) = h.close();
        assert_eq!(report.unknown_operations, 1);
        assert!(!report.automatic_retry_allowed);
    }
}
#[test]
fn signing_crash_worker() {
    let Ok(at) = std::env::var("AEGIS_SYNTHETIC_SIGNING_CRASH") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("AEGIS_SYNTHETIC_SIGNING_JOURNAL").unwrap());
    let clock = Arc::new(ManualClock::default());
    let (control, client) =
        Control::synthetic_github_signed(OperationSetup::synthetic_github(), clock, &path).unwrap();
    let ExecutorKind::Github(adapter) = &control.shared.executor else {
        panic!("fixed fixture")
    };
    adapter.test_signing_fault(at.parse().unwrap());
    let id = client
        .prepare_operation(input("crash-signing"))
        .unwrap()
        .prepared_request_id;
    client.request_operation_approval(id).unwrap();
    let review = control.inspect_operation_approval(id).unwrap();
    control.approve_operation_reviewed(id, &review).unwrap();
    client.invoke_operation(id).unwrap();
    panic!("expected synthetic crash");
}
#[test]
fn process_exit_before_and_after_signature_restores_no_authority_or_retry() {
    for at in [3, 4] {
        let directory = Directory::new();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "broker::github_tests::signing_tests::signing_crash_worker",
                "--nocapture",
            ])
            .env("AEGIS_SYNTHETIC_SIGNING_CRASH", at.to_string())
            .env("AEGIS_SYNTHETIC_SIGNING_JOURNAL", directory.journal())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(93));
        let recovery = inspect_synthetic_intents(&directory.journal()).unwrap();
        assert_eq!(recovery.reservations_consumed, 1);
        assert_eq!(recovery.incomplete_operations, 1);
        assert_eq!(recovery.uncertain_mints, 0);
        assert_eq!(recovery.restored_grants, 0);
        assert_eq!(recovery.restored_sessions, 0);
        assert!(!recovery.automatic_retry_allowed);
        let bytes = fs::read_to_string(directory.journal().join("intents.jsonl")).unwrap();
        assert!(!bytes.contains("eyJ"));
        assert!(!bytes.contains("PRIVATE KEY"));
        assert!(Control::synthetic_github_signed(
            OperationSetup::synthetic_github(),
            Arc::new(ManualClock::default()),
            &directory.journal()
        )
        .is_err());
    }
}
#[test]
fn cached_token_use_needs_core_approval_but_no_unlocked_or_live_signing_source() {
    let h = Harness::signed(3);
    let first = h.approved("mint-before-lock");
    assert_eq!(
        h.client.invoke_operation(first).unwrap().state,
        Lifecycle::Succeeded
    );
    h.adapter().test_lock_signer();
    h.clock.set(599);
    let second = h.approved("cached-locked");
    assert_eq!(
        h.client.invoke_operation(second).unwrap().state,
        Lifecycle::Succeeded
    );
    h.clock.set(601);
    let third = h.approved("cached-source-expired");
    assert_eq!(
        h.client.invoke_operation(third).unwrap().state,
        Lifecycle::Succeeded
    );
    assert_eq!(h.adapter().test_signatures(), 1);
    assert_eq!(h.adapter().test_counts(), (1, 3, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    assert_eq!(
        h.control.revoke_provider_tokens().unwrap(),
        RevocationStatus::ProviderConfirmed
    );
}
#[test]
fn preinitialized_provider_constructor_worker() {
    let Some(path) = std::env::var_os("AEGIS_SYNTHETIC_PREINITIALIZED_CONSTRUCTOR") else {
        return;
    };
    assert!(jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .is_ok());
    let path = PathBuf::from(path);
    assert!(matches!(
        Control::synthetic_github_signed(
            OperationSetup::synthetic_github(),
            Arc::new(ManualClock::default()),
            &path
        ),
        Err(ErrorCode::ProviderUnavailable)
    ));
    let report = inspect_synthetic_intents(&path).unwrap();
    assert_eq!(report.reservations_consumed, 0);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
    assert!(matches!(
        Control::synthetic_github_signed(
            OperationSetup::synthetic_github(),
            Arc::new(ManualClock::default()),
            &path
        ),
        Err(ErrorCode::PersistenceUnavailable)
    ));
}
#[test]
fn crypto_initialization_failure_leaves_only_nonresumable_header() {
    let directory = Directory::new();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "broker::github_tests::signing_tests::preinitialized_provider_constructor_worker",
        ])
        .env(
            "AEGIS_SYNTHETIC_PREINITIALIZED_CONSTRUCTOR",
            directory.journal(),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = inspect_synthetic_intents(&directory.journal()).unwrap();
    assert_eq!(report.reservations_consumed, 0);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
}
#[test]
fn exchange_verifies_current_time_after_mint_intent_sync_not_issuance_time() {
    let h = Harness::signed(2);
    let id = h.approved("slow-mint-sync");
    let (entered, pause) = h.adapter().test_exchange_pause();
    let release = Release(pause.clone());
    let client = h.client.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(h.adapter().test_signatures(), 1);
    h.clock.set(540);
    pause.release();
    drop(release);
    let result = worker.join().unwrap();
    assert_eq!(result.state, Lifecycle::Failed);
    assert_eq!(result.error, Some(ErrorCode::ProviderUnavailable));
    assert_eq!(h.adapter().test_counts(), (1, 0, 0));
    assert_eq!(h.control.remaining_uses().unwrap(), 1);
    assert_eq!(h.client.invoke_operation(id).unwrap(), result);
}
#[test]
fn rollback_between_signature_and_exchange_is_retained_before_provider_call() {
    let h = Harness::signed(2);
    h.clock.set(5);
    let id = h.approved("exchange-rollback");
    let (entered, pause) = h.adapter().test_exchange_pause();
    let release = Release(pause.clone());
    let client = h.client.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    h.clock.set(4);
    pause.release();
    drop(release);
    let result = worker.join().unwrap();
    assert_eq!(result.state, Lifecycle::Failed);
    assert_eq!(result.error, Some(ErrorCode::SessionExpired));
    assert_eq!(h.adapter().test_signatures(), 1);
    assert_eq!(h.adapter().test_counts(), (0, 0, 0));
    h.clock.set(5);
    assert!(h.client.prepare_operation(input("never-restored")).is_err());
    assert_eq!(h.control.remaining_uses().unwrap(), 1);
    let (_, report) = h.close();
    assert_eq!(report.uncertain_mints, 0);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(report.restored_sessions, 0);
    assert!(!report.reconciliation_required); // Known denial before provider dispatch.
    assert!(!report.automatic_retry_allowed);
}
