use super::*;
use crate::vault::{
    crypto::Signed,
    runtime::Host,
    store::{Kit, Recipient, RecipientFault},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "aegis-composed-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    fn imported(&self) -> (Arc<Kit>, Arc<Store>) {
        let kit = Kit::create(&self.path("kit")).unwrap();
        let input =
            protected_entry::import_delivery_canary(&self.path("input"), &kit.broker_material())
                .unwrap();
        let store =
            Store::create_imported(&self.path("vault"), kit.broker_material(), input).unwrap();
        (kit, store)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn imported_record_delivers_through_core_and_only_its_reviewed_version_is_permitted() {
    let f = Fixture::new();
    let (kit, store) = f.imported();
    let recipient = Recipient::create(&f.path("recipient"), kit.recipient_material()).unwrap();
    let host = Host::compose(
        kit.clone(),
        store.clone(),
        recipient.clone(),
        1,
        Arc::new(ManualClock::default()),
    )
    .unwrap();
    host.connect().unwrap();
    let id = host.prepare("imported-one", 1).unwrap();
    let result = host.reviewed_invoke(id).unwrap();
    assert_eq!(result.state, Lifecycle::Succeeded);
    assert_eq!(host.agent.invoke_operation(id).unwrap(), result);
    assert!(recipient.contains_canary(1));
    assert_eq!(store.history_counts().unwrap(), (1, 0, 0, 3, false));
    store.check_imported_record(&f.path("input")).unwrap();
    drop(host);
    let unimported =
        Host::compose(kit, store, recipient, 2, Arc::new(ManualClock::default())).unwrap();
    unimported.connect().unwrap();
    assert_eq!(
        unimported.prepare("not-imported", 2),
        Err(ErrorCode::ScopeDenied)
    );
}

#[test]
fn invalid_import_before_reservation_never_regenerates_or_hands_off() {
    for missing in [false, true] {
        let f = Fixture::new();
        let (kit, store) = f.imported();
        let recipient = Recipient::create(&f.path("recipient"), kit.recipient_material()).unwrap();
        let host = Host::compose(
            kit,
            store.clone(),
            recipient.clone(),
            1,
            Arc::new(ManualClock::default()),
        )
        .unwrap();
        host.connect().unwrap();
        let id = host.prepare("damaged-import", 1).unwrap();
        host.agent.request_operation_approval(id).unwrap();
        let challenge = host.approval_challenge(id).unwrap();
        host.approve(id, host.kit.actors.sign(&challenge).unwrap())
            .unwrap();
        if missing {
            fs::remove_file(f.path("vault/secret-1.age")).unwrap();
        } else {
            fs::write(f.path("vault/secret-1.age"), b"tampered synthetic record").unwrap();
        }
        let challenge = host.invocation_challenge(id).unwrap();
        assert_eq!(
            host.invoke(id, host.kit.actors.sign(&challenge).unwrap()),
            Err(ErrorCode::PersistenceUnavailable)
        );
        assert_eq!(recipient.generation().unwrap(), 0);
        assert_eq!(store.history_counts().unwrap(), (0, 0, 0, 4, false));
        assert_eq!(fs::read(f.path("recipient/accepted.jws")).unwrap(), b"");
    }
}

#[test]
fn imported_record_unknown_handoff_stays_consumed_across_restart() {
    let f = Fixture::new();
    let (kit, store) = f.imported();
    let recipient = Recipient::create(&f.path("recipient"), kit.recipient_material()).unwrap();
    let host = Host::compose(
        kit,
        store.clone(),
        recipient.clone(),
        1,
        Arc::new(ManualClock::default()),
    )
    .unwrap();
    host.connect().unwrap();
    let id = host.prepare("uncertain-import", 1).unwrap();
    recipient.fault(RecipientFault::AfterSync);
    let run = host.reviewed_invoke(id).unwrap();
    assert_eq!(run.state, Lifecycle::OutcomeUnknown);
    assert_eq!(host.agent.invoke_operation(id).unwrap(), run);
    assert_eq!(store.history_counts().unwrap(), (1, 0, 1, 3, false));
    drop((host, store, recipient));
    let kit = Kit::open(&f.path("kit")).unwrap();
    let store = Store::open(&f.path("vault"), kit.broker_material()).unwrap();
    let recipient = Recipient::open(&f.path("recipient"), kit.recipient_material()).unwrap();
    store.check_imported_record(&f.path("input")).unwrap();
    store.check_recipient(&recipient).unwrap();
    assert_eq!(store.history_counts().unwrap(), (1, 0, 1, 3, false));
    assert_eq!(recipient.generation().unwrap(), 1);
    assert!(matches!(
        Host::compose(kit, store, recipient, 1, Arc::new(ManualClock::default())),
        Err(ErrorCode::ReconciliationRequired)
    ));
}

#[test]
fn manifest_keeps_standalone_two_record_shape_and_exact_imported_shape() {
    for imported in [false, true] {
        let f = Fixture::new();
        let (kit, store) = if imported {
            f.imported()
        } else {
            let kit = Kit::create(&f.path("kit")).unwrap();
            let store = Store::create(&f.path("vault"), kit.broker_material()).unwrap();
            (kit, store)
        };
        drop(store);
        let path = f.path("vault/manifest.jws");
        let signed = Signed::parse(&fs::read(&path).unwrap()).unwrap();
        let original: serde_json::Value = kit.writer.verifier().verify(&signed).unwrap();
        for variant in 0..3 {
            let mut changed = original.clone();
            let records = changed["records"].as_array_mut().unwrap();
            if imported {
                match variant {
                    0 => {
                        records[0]
                            .as_object_mut()
                            .unwrap()
                            .remove("import_metadata_digest");
                    }
                    1 => {
                        records.push(records[0].clone());
                    }
                    _ => {
                        changed["acl"][0]["profile"] =
                            serde_json::to_value(super::super::DeliveryProfile::fixture(2))
                                .unwrap();
                    }
                }
            } else {
                match variant {
                    0 => {
                        records.pop();
                    }
                    1 => {
                        records[0]["import_metadata_digest"] = serde_json::json!("x".repeat(43));
                    }
                    _ => {
                        records.reverse();
                    }
                }
            }
            fs::write(&path, kit.writer.sign(&changed).unwrap().bytes()).unwrap();
            assert_eq!(
                Store::open(&f.path("vault"), kit.broker_material()).err(),
                Some(ErrorCode::PersistenceUnavailable)
            );
        }
        fs::write(&path, signed.bytes()).unwrap();
        Store::open(&f.path("vault"), kit.broker_material()).unwrap();
    }
}
