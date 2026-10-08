use super::*;
use super::{
    auth::Purpose,
    crypto::Signed,
    runtime::Host,
    store::{Fault, RecipientFault},
};
use crate::{protocol, ErrorCode, OperationIntent, OperationPrepareInput, ProfileId, RequestId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Paths(PathBuf);
impl Paths {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "aegis-vault-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault")
    }
    fn kit(&self) -> PathBuf {
        self.0.join("kit")
    }
    fn recipient(&self) -> PathBuf {
        self.0.join("recipient")
    }
}
impl Drop for Paths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn setup() -> (Paths, Arc<ManualClock>, Host) {
    let p = Paths::new();
    let c = Arc::new(ManualClock::default());
    let h = Host::create(&p.vault(), &p.kit(), &p.recipient(), c.clone()).unwrap();
    (p, c, h)
}
fn prepared(h: &Host, id: &str) -> u64 {
    h.connect().unwrap();
    let p = h.prepare(id, 1).unwrap();
    h.agent.request_operation_approval(p).unwrap();
    p
}
fn approved(h: &Host, id: &str) -> u64 {
    let p = prepared(h, id);
    h.approve(
        p,
        h.kit
            .actors
            .sign(&h.approval_challenge(p).unwrap())
            .unwrap(),
    )
    .unwrap();
    p
}
fn assert_no_canary(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    assert!(!text.contains(store::CANARY_ONE));
    assert!(!text.contains(store::CANARY_TWO));
}

#[test]
fn full_delivery_rotation_cold_start_and_revoke_reports_only_safe_evidence() {
    let p = Paths::new();
    let report = run_synthetic_vault_drill(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert_eq!(report.completed_deliveries, 2);
    assert_eq!(report.remaining_uses, 2);
    assert!(report.revocation_survived_restart);
    assert!(!report.ready_for_real_keys);
    assert!(!report.protected_deployment_verified);
    assert!(!report.independent_human_presence_verified);
    assert_no_canary(&serde_json::to_vec(&report).unwrap());
    for dir in [p.vault(), p.kit(), p.recipient()] {
        for entry in fs::read_dir(dir).unwrap() {
            assert_no_canary(&fs::read(entry.unwrap().path()).unwrap());
        }
    }
    assert_eq!(
        require_live_deployment(),
        Err(ErrorCode::UnsupportedDeployment)
    );
}
#[test]
fn every_versioned_agent_action_requires_authenticated_principal() {
    let (_p, _c, h) = setup();
    assert_eq!(
        h.agent.discover_versioned_operations(),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        h.prepare("before-auth", 1),
        Err(ErrorCode::AuthenticationRequired)
    );
    for result in [
        h.agent.request_operation_approval(1),
        h.agent.cancel_operation(1),
        h.agent.operation_status(1),
        h.agent.invoke_operation(1),
    ] {
        assert_eq!(result, Err(ErrorCode::AuthenticationRequired));
    }
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
}
#[test]
fn bare_review_and_terminal_style_control_cannot_approve_delivery() {
    let (_p, _c, h) = setup();
    let id = prepared(&h, "no-bypass");
    let review = h.control.inspect_operation_approval(id).unwrap();
    assert_eq!(
        h.control.approve_operation_reviewed(id, &review),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(h.control.approve(id), Err(ErrorCode::ScopeDenied));
    assert_eq!(
        h.control.approve_reviewed(
            id,
            &crate::ApprovalView {
                broker_instance: [0; 16],
                prepared_request_id: id,
                principal: crate::PrincipalId::new("fake").unwrap(),
                session: 1,
                profile: crate::Profile::synthetic(),
                parameters: crate::Parameters {
                    repository_id: 4242,
                    issue_number: 7
                },
                policy_generation: 1,
                expires_at: 15,
                remaining_uses: 4
            }
        ),
        Err(ErrorCode::ScopeDenied)
    );
    assert_eq!(
        h.agent.invoke_operation(id),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(h.control.revoke(), Err(ErrorCode::AuthenticationRequired));
    assert_eq!(h.adapter.store.history_counts().unwrap().0, 0);
    h.approve(
        id,
        h.kit
            .actors
            .sign(&h.approval_challenge(id).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        h.agent.invoke_operation(id),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
}
#[test]
fn agent_and_human_proofs_are_distinct_and_one_use() {
    let (_p, _c, h) = setup();
    let id = prepared(&h, "proofs");
    let approval = h.approval_challenge(id).unwrap();
    let valid = h.kit.actors.sign(&approval).unwrap();
    let replay = Signed::parse(valid.bytes()).unwrap();
    let agent = h.invocation_challenge(id).unwrap();
    let wrong = h.kit.actors.sign(&agent).unwrap();
    assert_eq!(h.approve(id, wrong), Err(ErrorCode::AuthenticationRequired));
    h.approve(id, valid).unwrap();
    assert_eq!(
        h.approve(id, replay),
        Err(ErrorCode::AuthenticationRequired)
    );
    let proof = h
        .kit
        .actors
        .sign(&h.invocation_challenge(id).unwrap())
        .unwrap();
    let replay = Signed::parse(proof.bytes()).unwrap();
    let done = h.invoke(id, proof).unwrap();
    assert_eq!(done.state, Lifecycle::Succeeded);
    assert_eq!(h.invoke(id, replay).unwrap(), done); // Terminal replay creates no signature/recipient effect.
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 1);
    assert!(h.adapter.recipient.contains_canary(1));
}
#[test]
fn proof_for_another_request_or_broker_cannot_authorize() {
    let (_p, _c, h) = setup();
    h.connect().unwrap();
    let first = h.prepare("first", 1).unwrap();
    let second = h.prepare("second", 1).unwrap();
    h.agent.request_operation_approval(first).unwrap();
    h.agent.request_operation_approval(second).unwrap();
    let proof = h
        .kit
        .actors
        .sign(&h.approval_challenge(first).unwrap())
        .unwrap();
    assert_eq!(
        h.approve(second, proof),
        Err(ErrorCode::AuthenticationRequired)
    );
    let (_other, _clock, other) = setup();
    let other_id = prepared(&other, "second");
    let proof = other
        .kit
        .actors
        .sign(&other.approval_challenge(other_id).unwrap())
        .unwrap();
    assert_eq!(
        h.approve(second, proof),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
}
#[test]
fn changed_secret_recipient_slot_resource_and_generation_are_denied() {
    let (_p, _c, h) = setup();
    h.connect().unwrap();
    for change in [
        |p: &mut DeliveryParameters| p.secret.id = "other".into(),
        |p: &mut DeliveryParameters| p.secret.version = 2,
        |p: &mut DeliveryParameters| p.recipient.id = "attacker".into(),
        |p: &mut DeliveryParameters| p.recipient.revision = 2,
        |p: &mut DeliveryParameters| p.recipient.configuration_revision = 2,
        |p: &mut DeliveryParameters| p.recipient.slot = "stdout".into(),
        |p: &mut DeliveryParameters| p.repository_id = 999,
        |p: &mut DeliveryParameters| p.expected_generation = 1,
    ] {
        let mut params = DeliveryParameters::fixture(1);
        change(&mut params);
        assert!(h
            .agent
            .prepare_operation(OperationPrepareInput {
                request_id: RequestId::new("deny").unwrap(),
                profile_id: ProfileId::new("vault-delivery").unwrap(),
                operation: OperationIntent::Delivery(params)
            })
            .is_err());
    }
    assert_eq!(h.adapter.store.history_counts().unwrap().0, 0);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
}
#[test]
fn typed_wire_cannot_supply_authentication_or_human_approval() {
    let (_p, _c, h) = setup();
    h.connect().unwrap();
    let params = serde_json::to_value(DeliveryParameters::fixture(1)).unwrap();
    let base = serde_json::json!({"version":2,"action":{"method":"prepare_operation","params":{"request_id":"wire","profile_id":"vault-delivery","operation":{"kind":"synthetic.vault.deliver.v1","parameters":params}}}});
    for field in [
        "authenticated",
        "approved",
        "principal",
        "acl_allowed",
        "secret",
        "token",
        "destination",
    ] {
        let mut v = base.clone();
        v["action"]["params"][field] = serde_json::json!(true);
        let result = protocol::handle(&h.agent, &serde_json::to_vec(&v).unwrap());
        assert_eq!(result.error, Some(ErrorCode::InvalidRequest));
        assert_no_canary(&serde_json::to_vec(&result).unwrap());
    }
    let r = protocol::handle(&h.agent, &serde_json::to_vec(&base).unwrap());
    assert!(r.error.is_none());
    assert_eq!(
        h.agent.invoke_operation(1),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
}
#[test]
fn approval_and_dispatch_expiry_fail_before_budget_consumption() {
    for at in [15, 30, 600] {
        let (_p, c, h) = setup();
        let id = approved(&h, "expiry");
        let proof = h
            .kit
            .actors
            .sign(&h.invocation_challenge(id).unwrap())
            .unwrap();
        c.set(at);
        assert!(h.invoke(id, proof).is_err());
        assert_eq!(h.control.remaining_uses().unwrap(), 4);
        assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
    }
}
#[test]
fn clock_regression_is_sticky_and_cannot_revive_authentication() {
    let (_p, c, h) = setup();
    h.connect().unwrap();
    c.set(5);
    h.agent.discover_versioned_operations().unwrap();
    c.set(4);
    assert_eq!(
        h.agent.discover_versioned_operations(),
        Err(ErrorCode::SessionExpired)
    );
    c.set(5);
    assert_eq!(h.prepare("regression", 1), Err(ErrorCode::SessionExpired));
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
}
#[test]
fn proof_generation_is_bounded() {
    let (_p, _c, h) = setup();
    let digest = h.adapter.gate.context_digest(Purpose::Connect).unwrap();
    for _ in 0..32 {
        h.adapter
            .gate
            .challenge(Purpose::Connect, digest.clone())
            .unwrap();
    }
    assert_eq!(
        h.adapter.gate.challenge(Purpose::Connect, digest),
        Err(ErrorCode::CapacityExceeded)
    );
}
#[test]
fn durable_reservation_and_terminal_faults_never_refund_or_redeliver() {
    for sequence in [3, 4, 5] {
        for fault in [
            Fault::BeforeWrite,
            Fault::PartialWrite,
            Fault::AfterWrite,
            Fault::AfterSync,
            Fault::BeforeAnchor,
            Fault::AfterAnchor,
        ] {
            let (_p, _c, h) = setup();
            let id = approved(&h, "io-fault");
            h.adapter.store.fault(sequence, fault);
            let result = h
                .invoke(
                    id,
                    h.kit
                        .actors
                        .sign(&h.invocation_challenge(id).unwrap())
                        .unwrap(),
                )
                .unwrap();
            assert!(matches!(
                result.state,
                Lifecycle::Failed | Lifecycle::OutcomeUnknown
            ));
            assert_eq!(h.control.remaining_uses().unwrap(), 3);
            assert_eq!(h.agent.invoke_operation(id).unwrap(), result);
            assert!(h.prepare("fresh", 1).is_err());
            assert_eq!(
                h.adapter.recipient.generation().unwrap(),
                u64::from(sequence == 5)
            );
        }
    }
}
#[test]
fn failed_approval_persistence_never_becomes_executable_authority() {
    for fault in [
        Fault::BeforeWrite,
        Fault::PartialWrite,
        Fault::AfterWrite,
        Fault::AfterSync,
        Fault::BeforeAnchor,
        Fault::AfterAnchor,
    ] {
        let (_p, _c, h) = setup();
        let id = prepared(&h, "approval-fault");
        h.adapter.store.fault(2, fault);
        assert!(h
            .approve(
                id,
                h.kit
                    .actors
                    .sign(&h.approval_challenge(id).unwrap())
                    .unwrap()
            )
            .is_err());
        assert_eq!(
            h.agent.invoke_operation(id),
            Err(ErrorCode::ApprovalRequired)
        );
        assert_eq!(h.control.remaining_uses().unwrap(), 4);
        assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
    }
}
#[test]
fn recipient_failure_panic_or_wrong_ack_preserves_consumed_uncertainty() {
    for fault in [
        RecipientFault::Reject,
        RecipientFault::BeforeWrite,
        RecipientFault::PartialWrite,
        RecipientFault::AfterSync,
        RecipientFault::PanicAfterInstall,
        RecipientFault::BadAck,
    ] {
        let (_p, _c, h) = setup();
        let id = approved(&h, "recipient-fault");
        h.adapter.recipient.fault(fault);
        let result = h
            .invoke(
                id,
                h.kit
                    .actors
                    .sign(&h.invocation_challenge(id).unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            result.state,
            if matches!(fault, RecipientFault::Reject) {
                Lifecycle::Failed
            } else {
                Lifecycle::OutcomeUnknown
            }
        );
        assert_eq!(h.agent.invoke_operation(id).unwrap(), result);
        assert_eq!(h.control.remaining_uses().unwrap(), 3);
        assert_no_canary(&serde_json::to_vec(&result).unwrap());
    }
}
#[test]
fn cold_start_cannot_resume_a_pending_delivery_or_old_request() {
    let (p, c, h) = setup();
    let id = approved(&h, "unknown");
    h.adapter.recipient.fault(RecipientFault::AfterSync);
    let result = h
        .invoke(
            id,
            h.kit
                .actors
                .sign(&h.invocation_challenge(id).unwrap())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(result.state, Lifecycle::OutcomeUnknown);
    drop(h);
    let report = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert_eq!(report.consumed_uses, 1);
    assert_eq!(report.unknown_deliveries, 1);
    assert_eq!(report.recipient_generation, 1);
    assert!(!report.automatic_retry_allowed);
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).err(),
        Some(ErrorCode::ReconciliationRequired)
    );
}
#[test]
fn concurrent_writer_open_is_rejected_and_drop_releases_locks() {
    let (p, c, h) = setup();
    assert!(Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c.clone()).is_err());
    drop(h);
    let reopened = Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).unwrap();
    assert_eq!(
        reopened.prepare("fresh", 1),
        Err(ErrorCode::AuthenticationRequired)
    );
}
#[test]
fn ciphertext_corruption_or_missing_anchor_fail_closed_on_restart() {
    for filename in [
        "secret-1.age",
        "secret-2.age",
        "manifest.jws",
        "journal.jws",
    ] {
        let (p, c, h) = setup();
        drop(h);
        let path = p.vault().join(filename);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).is_err());
    }
    let (p, c, h) = setup();
    drop(h);
    fs::remove_file(p.kit().join("anchor.jws")).unwrap();
    assert!(Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).is_err());
}
#[test]
fn valid_old_journal_is_rejected_by_newer_separate_anchor() {
    let (p, c, h) = setup();
    let old = fs::read(p.vault().join("journal.jws")).unwrap();
    let id = prepared(&h, "deliver");
    h.reviewed_invoke(id).unwrap();
    drop(h);
    fs::write(p.vault().join("journal.jws"), old).unwrap();
    assert!(Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).is_err());
}
#[test]
fn old_epoch_proof_cannot_be_used_after_a_valid_cold_start() {
    let (p, c, h) = setup();
    let id = prepared(&h, "pending");
    let proof = h
        .kit
        .actors
        .sign(&h.approval_challenge(id).unwrap())
        .unwrap();
    drop(h);
    let h = Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).unwrap();
    let id = prepared(&h, "pending");
    assert_eq!(h.approve(id, proof), Err(ErrorCode::AuthenticationRequired));
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
}
#[test]
fn recipient_history_deletion_cannot_reset_a_completed_generation() {
    let (p, c, h) = setup();
    let id = prepared(&h, "installed");
    h.reviewed_invoke(id).unwrap();
    drop(h);
    fs::write(p.recipient().join("accepted.jws"), []).unwrap();
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).err(),
        Some(ErrorCode::ReconciliationRequired)
    );
}
#[test]
fn second_install_with_new_id_cannot_overwrite_a_recipient_without_rotation() {
    let (_p, _c, h) = setup();
    let id = prepared(&h, "installed");
    h.reviewed_invoke(id).unwrap();
    assert_eq!(
        h.prepare("duplicate-install", 1),
        Err(ErrorCode::ScopeDenied)
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
}
#[test]
fn revocation_is_authenticated_and_survives_fresh_sessions() {
    let (p, c, h) = setup();
    h.connect().unwrap();
    assert_eq!(h.control.revoke(), Err(ErrorCode::AuthenticationRequired));
    h.revoke().unwrap();
    assert!(h.prepare("denied", 1).is_err());
    drop(h);
    let r = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert!(r.revoked);
    assert_eq!(r.consumed_uses, 0);
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).err(),
        Some(ErrorCode::GrantRevoked)
    );
}
#[test]
fn authenticated_snapshot_alone_does_not_claim_a_protected_anchor_or_host() {
    let (p, _c, h) = setup();
    drop(h);
    let r = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert!(!r.protected_anchor_verified);
    assert!(!r.ready_for_real_keys);
    assert_eq!(r.restored_sessions, 0);
    assert_eq!(
        require_live_deployment(),
        Err(ErrorCode::UnsupportedDeployment)
    );
}
#[test]
fn fixture_paths_reject_symlinks_and_preserve_existing_destinations() {
    use std::os::unix::fs::symlink;
    let p = Paths::new();
    fs::create_dir(p.vault()).unwrap();
    fs::write(p.vault().join("marker"), b"keep").unwrap();
    assert!(run_synthetic_vault_drill(&p.vault(), &p.kit(), &p.recipient()).is_err());
    assert_eq!(fs::read(p.vault().join("marker")).unwrap(), b"keep");
    let q = Paths::new();
    symlink(&q.0, q.0.join("alias")).unwrap();
    assert!(run_synthetic_vault_drill(&q.0.join("alias/vault"), &q.kit(), &q.recipient()).is_err());
}
#[test]
fn authenticated_principal_has_no_authority_when_acl_is_empty_or_other_version() {
    for acl in [
        vec![],
        vec![store::AclEntry {
            principal: crate::PrincipalId::new(auth::AGENT).unwrap(),
            profile: DeliveryProfile::fixture(2),
            max_uses: 4,
        }],
    ] {
        let p = Paths::new();
        let kit = store::Kit::create(&p.kit()).unwrap();
        let store = store::Store::create_with_acl(&p.vault(), kit.broker_material(), acl).unwrap();
        let receiver = store::Recipient::create(&p.recipient(), kit.recipient_material()).unwrap();
        let h = Host::compose(kit, store, receiver, 1, Arc::new(ManualClock::default())).unwrap();
        h.connect().unwrap();
        assert_eq!(h.prepare("denied-acl", 1), Err(ErrorCode::ScopeDenied));
        assert_eq!(
            h.agent.discover_versioned_operations(),
            Err(ErrorCode::ScopeDenied)
        );
        assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
        assert_eq!(h.control.remaining_uses().unwrap(), 4);
    }
}
#[test]
fn durable_budget_exhaustion_is_not_reset_by_cold_start() {
    let (p, c, h) = setup();
    h.connect().unwrap();
    h.adapter.recipient.fault(RecipientFault::Reject);
    for n in 0..4 {
        let id = h.prepare(&format!("rejected-{n}"), 1).unwrap();
        assert_eq!(h.reviewed_invoke(id).unwrap().state, Lifecycle::Failed);
    }
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    assert_eq!(h.adapter.store.remaining().unwrap(), 0);
    drop(h);
    let report = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert_eq!(report.consumed_uses, 4);
    assert_eq!(report.remaining_uses, 0);
    assert!(Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).is_err());
}
#[test]
fn pre_authentication_handle_and_another_broker_cannot_inherit_session_authority() {
    let (_p, _c, h) = setup();
    let unauthenticated = h.agent.clone();
    h.connect().unwrap();
    assert_eq!(
        unauthenticated.discover_versioned_operations(),
        Err(ErrorCode::AuthenticationRequired)
    );
    let id = h.prepare("bound-handle", 1).unwrap();
    assert_eq!(
        unauthenticated.operation_status(id),
        Err(ErrorCode::AuthenticationRequired)
    );
    h.agent.discover_versioned_operations().unwrap();
    let (_q, _d, other) = setup();
    let challenge = other
        .adapter
        .gate
        .challenge(
            Purpose::Connect,
            other.adapter.gate.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let ticket = other
        .adapter
        .gate
        .connect(other.kit.actors.sign(&challenge).unwrap())
        .unwrap();
    let substituted = h.agent.with_vault_session(ticket);
    assert_eq!(
        substituted.discover_versioned_operations(),
        Err(ErrorCode::AuthenticationRequired)
    );
}
struct Release(Arc<store::RecipientPause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
#[test]
fn duplicate_inflight_invocations_share_one_durable_reservation_and_handoff() {
    let (_p, _c, h) = setup();
    let id = approved(&h, "inflight");
    let proof = h
        .kit
        .actors
        .sign(&h.invocation_challenge(id).unwrap())
        .unwrap();
    h.adapter.gate.stage_agent(id, proof).unwrap();
    let (rx, pause) = h.adapter.recipient.pause();
    let release = Release(pause.clone());
    let client = h.agent.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(
        h.agent.invoke_operation(id).unwrap().state,
        Lifecycle::Dispatched
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    pause.release();
    drop(release);
    assert_eq!(worker.join().unwrap().state, Lifecycle::Succeeded);
    assert_eq!(h.adapter.store.history_counts().unwrap().0, 1);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 1);
}
#[test]
fn authentication_expiry_during_delivery_does_not_drop_the_committed_result() {
    let (_p, c, h) = setup();
    let id = approved(&h, "expiry-inflight");
    h.adapter
        .gate
        .stage_agent(
            id,
            h.kit
                .actors
                .sign(&h.invocation_challenge(id).unwrap())
                .unwrap(),
        )
        .unwrap();
    let (rx, pause) = h.adapter.recipient.pause();
    let release = Release(pause.clone());
    let client = h.agent.clone();
    let worker = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    c.set(600);
    pause.release();
    drop(release);
    let result = worker.join().unwrap();
    assert_eq!(result.state, Lifecycle::Succeeded);
    assert_eq!(h.adapter.store.history_counts().unwrap().0, 1);
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    assert_eq!(
        h.agent.operation_status(id),
        Err(ErrorCode::AuthenticationRequired)
    );
}
#[test]
fn revoked_before_reservation_denies_a_previously_approved_assertion() {
    let (_p, _c, h) = setup();
    let id = approved(&h, "revoke-before");
    let proof = h
        .kit
        .actors
        .sign(&h.invocation_challenge(id).unwrap())
        .unwrap();
    h.revoke().unwrap();
    assert_eq!(h.invoke(id, proof), Err(ErrorCode::GrantRevoked));
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
}
#[test]
fn legacy_handle_wrappers_cannot_probe_or_act_with_an_unbound_client() {
    let (_p, _c, h) = setup();
    let before = h.agent.clone();
    let id = prepared(&h, "legacy-auth");
    for handle in [id, id + 1] {
        for r in [
            before.request_approval(handle),
            before.cancel(handle),
            before.status(handle),
            before.invoke(handle),
        ] {
            assert_eq!(r, Err(ErrorCode::AuthenticationRequired));
        }
    }
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
}
#[test]
fn vault_crash_worker() {
    let Ok(mode) = std::env::var("AEGIS_SYNTHETIC_VAULT_CRASH") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("AEGIS_SYNTHETIC_VAULT_ROOT").unwrap());
    let h = Host::create(
        &root.join("vault"),
        &root.join("kit"),
        &root.join("recipient"),
        Arc::new(ManualClock::default()),
    )
    .unwrap();
    let id = prepared(&h, "crash-operation");
    if mode.starts_with("ledger-") {
        let parts: Vec<_> = mode.split('-').collect();
        let sequence = parts[1].parse().unwrap();
        let fault = if parts[2] == "anchor" {
            Fault::ExitAfterAnchor
        } else {
            Fault::ExitAfterSync
        };
        h.adapter.store.fault(sequence, fault);
    } else {
        h.adapter.recipient.fault(if mode == "recipient-before" {
            RecipientFault::ExitBeforeWrite
        } else {
            RecipientFault::ExitAfterSync
        });
    }
    h.reviewed_invoke(id).unwrap();
    h.revoke().unwrap();
    panic!("expected fixed synthetic crash boundary");
}
#[test]
fn subprocess_crashes_before_after_handoff_and_revocation_restore_no_authority() {
    let modes = [
        "ledger-2-anchor",
        "ledger-3-sync",
        "ledger-3-anchor",
        "ledger-4-sync",
        "ledger-4-anchor",
        "ledger-5-sync",
        "ledger-5-anchor",
        "ledger-6-sync",
        "ledger-6-anchor",
        "recipient-before",
        "recipient-after",
    ];
    for mode in modes {
        let p = Paths::new();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "vault::tests::vault_crash_worker", "--nocapture"])
            .env("AEGIS_SYNTHETIC_VAULT_CRASH", mode)
            .env("AEGIS_SYNTHETIC_VAULT_ROOT", &p.0)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(93),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_no_canary(&output.stdout);
        assert_no_canary(&output.stderr);
        let report = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient());
        if mode.ends_with("sync") || matches!(mode, "ledger-3-anchor" | "ledger-6-anchor") {
            assert!(report.is_err());
        } else {
            let report = report.unwrap();
            assert_eq!(report.restored_sessions, 0);
            assert!(!report.automatic_retry_allowed);
            assert!(!report.ready_for_real_keys);
            assert_eq!(report.consumed_uses, usize::from(mode != "ledger-2-anchor"));
            if mode == "ledger-6-anchor" {
                assert!(report.revoked);
            }
            if mode.starts_with("recipient") {
                assert_eq!(report.incomplete_deliveries, 1);
                assert_eq!(
                    report.recipient_generation,
                    u64::from(mode == "recipient-after")
                );
            }
        }
        let open = Host::open(
            &p.vault(),
            &p.kit(),
            &p.recipient(),
            1,
            Arc::new(ManualClock::default()),
        );
        if mode == "ledger-2-anchor" {
            let h = open.unwrap();
            assert_eq!(
                h.prepare("fresh-session", 1),
                Err(ErrorCode::AuthenticationRequired)
            );
        } else if mode == "ledger-5-anchor" {
            let h = open.unwrap();
            assert_eq!(
                h.prepare("before-auth", 1),
                Err(ErrorCode::AuthenticationRequired)
            );
            h.connect().unwrap();
            assert!(h.prepare("crash-operation", 1).is_err());
        } else {
            assert!(open.is_err());
        }
    }
}
#[test]
fn corruption_while_open_is_detected_before_a_new_approval_or_effect() {
    for name in [
        "journal.jws",
        "manifest.jws",
        "secret-1.age",
        "secret-2.age",
    ] {
        let (p, _c, h) = setup();
        let id = prepared(&h, "runtime-corruption");
        let proof = h
            .kit
            .actors
            .sign(&h.approval_challenge(id).unwrap())
            .unwrap();
        let path = p.vault().join(name);
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        fs::write(path, bytes).unwrap();
        assert_eq!(h.approve(id, proof), Err(ErrorCode::PersistenceUnavailable));
        assert_eq!(h.control.remaining_uses().unwrap(), 4);
        assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
    }
}
#[test]
fn missing_anchor_while_open_cannot_be_silently_recreated_to_continue() {
    let (p, _c, h) = setup();
    let id = prepared(&h, "anchor-deleted");
    let proof = h
        .kit
        .actors
        .sign(&h.approval_challenge(id).unwrap())
        .unwrap();
    fs::remove_file(p.kit().join("anchor.jws")).unwrap();
    assert_eq!(h.approve(id, proof), Err(ErrorCode::PersistenceUnavailable));
    assert!(!p.kit().join("anchor.jws").exists());
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
}

#[path = "review_regression_tests.rs"]
mod review_regression_tests;
