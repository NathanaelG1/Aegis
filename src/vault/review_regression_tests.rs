//! Regression cases reproduced during independent review; synthetic fixtures only.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

#[test]
fn inspection_rejects_erased_recipient_after_completed_delivery() {
    let (p, c, h) = setup();
    let id = prepared(&h, "inspection-mismatch");
    assert_eq!(h.reviewed_invoke(id).unwrap().state, Lifecycle::Succeeded);
    drop(h);
    fs::write(p.recipient().join("accepted.jws"), []).unwrap();
    assert_eq!(
        inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()),
        Err(ErrorCode::ReconciliationRequired)
    );
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).err(),
        Some(ErrorCode::ReconciliationRequired)
    );
}

#[test]
fn active_recipient_damage_cannot_acknowledge_rotation_as_succeeded() {
    for damage in ["truncate", "corrupt", "replace"] {
        let (p, c, h) = setup();
        let id = prepared(&h, "first-install");
        assert_eq!(h.reviewed_invoke(id).unwrap().state, Lifecycle::Succeeded);
        drop(h);
        let h = Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c.clone()).unwrap();
        h.connect().unwrap();
        let path = p.recipient().join("accepted.jws");
        match damage {
            "truncate" => fs::write(&path, []).unwrap(),
            "corrupt" => {
                let mut bytes = fs::read(&path).unwrap();
                let middle = bytes.len() / 2;
                bytes[middle] = b'!';
                fs::write(&path, bytes).unwrap();
            }
            "replace" => {
                fs::rename(&path, p.recipient().join("held-accepted.jws")).unwrap();
                let f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                f.sync_all().unwrap();
            }
            _ => unreachable!(),
        }
        let id = h.prepare("rotation-after-damage", 2).unwrap();
        let result = h.reviewed_invoke(id).unwrap();
        assert_eq!(result.state, Lifecycle::OutcomeUnknown, "{damage}");
        assert_eq!(
            h.adapter.recipient.generation(),
            Err(ErrorCode::ReconciliationRequired)
        );
        assert_eq!(h.adapter.store.history_counts().unwrap().2, 1);
        assert_eq!(h.control.remaining_uses().unwrap(), 2);
        drop(h);
        assert!(
            Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).is_err(),
            "{damage}"
        );
    }
}

#[test]
fn unknown_receipt_requires_the_original_authenticated_capability() {
    let (_p, c, h) = setup();
    let unbound = h.agent.clone();
    let id = approved(&h, "unknown-capability");
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
    assert_eq!(h.agent.operation_status(id).unwrap(), result);
    assert_eq!(h.agent.invoke_operation(id).unwrap(), result);
    let (_other_p, _other_c, other) = setup();
    let challenge = other
        .adapter
        .gate
        .challenge(
            Purpose::Connect,
            other.adapter.gate.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let foreign_ticket = other
        .adapter
        .gate
        .connect(other.kit.actors.sign(&challenge).unwrap())
        .unwrap();
    let foreign = h.agent.with_vault_session(foreign_ticket);
    for client in [&unbound, &foreign] {
        assert_eq!(
            client.operation_status(id),
            Err(ErrorCode::AuthenticationRequired)
        );
        assert_eq!(
            client.invoke_operation(id),
            Err(ErrorCode::AuthenticationRequired)
        );
        assert_eq!(
            client.request_operation_approval(id),
            Err(ErrorCode::AuthenticationRequired)
        );
        assert_eq!(
            client.cancel_operation(id),
            Err(ErrorCode::AuthenticationRequired)
        );
    }
    c.set(600);
    assert_eq!(
        h.agent.operation_status(id),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        h.agent.invoke_operation(id),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
}

#[test]
fn prewrite_reservation_failure_cannot_restore_unknown_authority_on_restart() {
    let (p, c, h) = setup();
    let id = approved(&h, "prewrite-unknown");
    h.adapter.store.fault(3, Fault::BeforeWrite);
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
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    assert_eq!(h.adapter.store.remaining().unwrap(), 4);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
    drop(h);
    assert!(p.vault().join("reservation.guard").is_file());
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).err(),
        Some(ErrorCode::ReconciliationRequired)
    );
    assert_eq!(
        inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()),
        Err(ErrorCode::ReconciliationRequired)
    );
}

#[test]
fn revoke_while_reserved_delivery_is_paused_preserves_result_and_durable_revocation() {
    let (p, c, h) = setup();
    let id = approved(&h, "revoke-after-reserve");
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
    let (entered, pause) = h.adapter.recipient.pause();
    let release = Release(pause.clone());
    let h = Arc::new(h);
    let client = h.agent.clone();
    let work = std::thread::spawn(move || client.invoke_operation(id).unwrap());
    entered
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    let revoked = h.clone();
    let (revocation_started, started) = std::sync::mpsc::channel();
    let revoke = std::thread::spawn(move || {
        revocation_started.send(()).unwrap();
        revoked.revoke()
    });
    started
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    pause.release();
    drop(release);
    assert_eq!(work.join().unwrap().state, Lifecycle::Succeeded);
    revoke.join().unwrap().unwrap();
    assert_eq!(h.agent.operation_status(id), Err(ErrorCode::GrantRevoked));
    assert_eq!(h.control.remaining_uses().unwrap(), 3);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 1);
    drop(h);
    let report = inspect_synthetic_vault(&p.vault(), &p.kit(), &p.recipient()).unwrap();
    assert!(report.revoked);
    assert_eq!(report.consumed_uses, 1);
    assert_eq!(report.unknown_deliveries, 0);
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).err(),
        Some(ErrorCode::GrantRevoked)
    );
}

#[test]
fn failed_revocation_write_cannot_be_forgotten_on_restart() {
    for fault in [
        Fault::BeforeWrite,
        Fault::PartialWrite,
        Fault::AfterWrite,
        Fault::AfterSync,
        Fault::AfterAnchor,
    ] {
        let (p, c, h) = setup();
        let id = prepared(&h, "before-revoke-failure");
        assert_eq!(h.reviewed_invoke(id).unwrap().state, Lifecycle::Succeeded);
        h.adapter.store.fault(6, fault);
        assert!(h.revoke().is_err());
        assert!(h.prepare("after-revoke-failure", 1).is_err());
        drop(h);
        assert!(p.vault().join("revocation.guard").is_file());
        assert_eq!(
            Host::open(&p.vault(), &p.kit(), &p.recipient(), 2, c).err(),
            Some(ErrorCode::ReconciliationRequired)
        );
    }
}

#[test]
fn incomplete_guard_never_consumes_in_memory_authority_or_reopens() {
    let (p, c, h) = setup();
    let id = approved(&h, "guard-exists");
    fs::write(
        p.vault().join("reservation.guard"),
        b"incomplete synthetic write",
    )
    .unwrap();
    let proof = h
        .kit
        .actors
        .sign(&h.invocation_challenge(id).unwrap())
        .unwrap();
    assert_eq!(h.invoke(id, proof), Err(ErrorCode::PersistenceUnavailable));
    assert_eq!(h.control.remaining_uses().unwrap(), 4);
    assert_eq!(h.adapter.recipient.generation().unwrap(), 0);
    drop(h);
    assert_eq!(
        Host::open(&p.vault(), &p.kit(), &p.recipient(), 1, c).err(),
        Some(ErrorCode::ReconciliationRequired)
    );
}
