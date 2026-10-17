use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Paths(PathBuf);
impl Paths {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aegis-custody-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn custody(&self) -> PathBuf {
        self.0.join("custody")
    }
    fn root(&self) -> PathBuf {
        self.0.join("vault")
    }
    fn recipient(&self) -> PathBuf {
        self.0.join("recipient")
    }
    fn role(&self, role: &str) -> PathBuf {
        self.custody().join(role)
    }
    fn create(&self) -> SyntheticProtocol {
        create_synthetic_protocol(
            &self.root(),
            &self.role("broker"),
            &self.role("recipient"),
            &self.recipient(),
            Arc::new(ManualClock::default()),
        )
        .unwrap()
    }
    fn open(&self, version: u64) -> Result<SyntheticProtocol, ErrorCode> {
        open_synthetic_protocol(
            &self.root(),
            &self.role("broker"),
            &self.role("recipient"),
            &self.recipient(),
            version,
            Arc::new(ManualClock::default()),
        )
    }
    fn actors(&self) -> (ActorRole, ActorRole) {
        let broker = BrokerRole::open(&self.role("broker")).unwrap();
        let id = &broker.material.vault_id;
        (
            ActorRole::open(&self.role("agent"), AGENT_KIND, id).unwrap(),
            ActorRole::open(&self.role("admin"), ADMIN_KIND, id).unwrap(),
        )
    }
}
impl Drop for Paths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join(ROLE_FILE)).unwrap()).unwrap()
}
fn update_json(path: &Path, value: &Value) {
    fs::write(path.join(ROLE_FILE), serde_json::to_vec(value).unwrap()).unwrap();
}
fn assert_safe(text: &str) {
    for forbidden in [
        store::CANARY_ONE,
        store::CANARY_TWO,
        "AGE-SECRET-KEY",
        "assertion",
        "private_key",
    ] {
        assert!(!text.contains(forbidden), "unexpected private content");
    }
}

#[test]
fn complete_custody_drill_uses_protocol_delivery_rotation_revoke_and_cold_inspection() {
    let paths = Paths::new();
    let report =
        run_synthetic_custody_drill(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!(report.separate_role_documents, 4);
    assert!(!report.all_role_kit_created);
    assert!(report.wrong_role_signing_denied);
    assert!(report.unauthenticated_agent_denied && report.unauthenticated_admin_denied);
    assert!(report.changed_review_denied);
    assert!(report.duplicate_reused && report.cold_start_required_authentication);
    assert!(report.previous_request_id_denied && report.revocation_survived_restart);
    assert_eq!(
        (
            report.completed_deliveries,
            report.consumed_uses,
            report.remaining_uses,
            report.recipient_generation
        ),
        (2, 2, 2, 2)
    );
    assert!(!report.delivery_responses_contain_canary);
    assert!(
        !report.ready_for_real_keys
            && !report.protected_custody_verified
            && !report.protected_deployment_verified
            && !report.independent_human_presence_verified
    );
    assert_safe(&serde_json::to_string(&report).unwrap());
    assert_safe(&format!("{report:?}"));
    // Inspection needs neither signer file, and does not create a fresh grant.
    fs::remove_dir_all(paths.role("agent")).unwrap();
    fs::remove_dir_all(paths.role("admin")).unwrap();
    let inspection =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert!(inspection.revoked);
    assert_eq!(inspection.restored_sessions, 0);
    assert!(!inspection.automatic_retry_allowed);
    assert!(matches!(paths.open(2), Err(ErrorCode::GrantRevoked)));
}

#[test]
fn role_documents_contain_only_their_private_material_and_bootstrap_never_overwrites() {
    let paths = Paths::new();
    let report = bootstrap_synthetic_custody(&paths.custody()).unwrap();
    assert_eq!(report.role_documents, 4);
    let broker = read_json(&paths.role("broker"));
    let recipient = read_json(&paths.role("recipient"));
    let agent = read_json(&paths.role("agent"));
    let admin = read_json(&paths.role("admin"));
    let private = [
        broker["storage"].as_str().unwrap(),
        broker["writer"].as_str().unwrap(),
        recipient["recipient"].as_str().unwrap(),
        recipient["receipt"].as_str().unwrap(),
        agent["signer"].as_str().unwrap(),
        admin["signer"].as_str().unwrap(),
    ];
    let docs = [&broker, &recipient, &agent, &admin];
    for (index, doc) in docs.iter().enumerate() {
        let encoded = serde_json::to_string(doc).unwrap();
        for (key_index, key) in private.iter().enumerate() {
            let owns = matches!(
                (index, key_index),
                (0, 0 | 1) | (1, 2 | 3) | (2, 4) | (3, 5)
            );
            assert_eq!(encoded.contains(key), owns);
        }
    }
    assert_eq!(broker.as_object().unwrap().len(), 9);
    assert_eq!(recipient.as_object().unwrap().len(), 6);
    assert_eq!(agent.as_object().unwrap().len(), 4);
    assert_eq!(admin.as_object().unwrap().len(), 4);
    assert!(!paths.custody().join("fixture-keys.json").exists());
    assert!(bootstrap_synthetic_custody(&paths.custody()).is_err());
    assert_eq!(read_json(&paths.role("broker")), broker);
}

#[test]
fn runtime_constructors_and_inspection_do_not_open_actor_files_or_combined_kit() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    fs::remove_dir_all(paths.role("agent")).unwrap();
    fs::remove_dir_all(paths.role("admin")).unwrap();
    fs::write(
        paths.custody().join("fixture-keys.json"),
        b"not a kit; must never be read",
    )
    .unwrap();
    let p = paths.create();
    assert_eq!(
        p.agent
            .handle(&frame("discover_operations", json!({})).unwrap().0)
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    drop(p);
    let p = paths.open(1).unwrap();
    assert_eq!(
        p.admin
            .handle(&frame("revoke_challenge", json!({})).unwrap().0)
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    drop(p);
    let report =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!(
        (
            report.consumed_uses,
            report.remaining_uses,
            report.recipient_generation
        ),
        (0, 4, 0)
    );
}

#[test]
fn actor_private_keys_can_be_dropped_before_the_bound_dispatch() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    let p = paths.create();
    let (agent, admin) = paths.actors();
    connect(&p, &agent, &admin).unwrap();
    let id = prepare(&p, "separate-signers", 1).unwrap();
    approve(&p, &admin, id).unwrap();
    let invocation = invocation(&p, &agent, id).unwrap();
    drop(agent);
    drop(admin);
    fs::remove_dir_all(paths.role("agent")).unwrap();
    fs::remove_dir_all(paths.role("admin")).unwrap();
    let response = p.agent.handle(&invocation.0);
    assert_safe(&serde_json::to_string(&response).unwrap());
    assert_eq!(run(response).unwrap().state, Lifecycle::Succeeded);
    drop(p);
    let report =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!(
        (
            report.consumed_uses,
            report.remaining_uses,
            report.recipient_generation
        ),
        (1, 3, 1)
    );
}

#[test]
fn wrong_roles_foreign_actors_and_foreign_recipient_are_rejected() {
    let paths = Paths::new();
    let other = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    bootstrap_synthetic_custody(&other.custody()).unwrap();
    let broker = BrokerRole::open(&paths.role("broker")).unwrap();
    assert!(BrokerRole::open(&paths.role("recipient")).is_err());
    assert!(open_recipient_role(&paths.role("broker")).is_err());
    assert!(ActorRole::open(&paths.role("admin"), AGENT_KIND, &broker.material.vault_id).is_err());
    assert!(ActorRole::open(&other.role("agent"), AGENT_KIND, &broker.material.vault_id).is_err());
    assert!(matches!(
        create_synthetic_protocol(
            &paths.root(),
            &paths.role("broker"),
            &other.role("recipient"),
            &paths.recipient(),
            Arc::new(ManualClock::default())
        ),
        Err(ErrorCode::ScopeDenied)
    ));
    assert!(!paths.root().exists() && !paths.recipient().exists());
    let p = paths.create();
    let (agent, admin) = paths.actors();
    let (foreign, _) = other.actors();
    let ac = challenge(
        p.agent
            .handle(&frame("connect_challenge", json!({})).unwrap().0),
    )
    .unwrap();
    let hc = challenge(
        p.admin
            .handle(&frame("connect_challenge", json!({})).unwrap().0),
    )
    .unwrap();
    assert!(agent.proof(&hc).is_err() && admin.proof(&ac).is_err());
    assert_eq!(
        p.agent
            .handle(&frame("connect", foreign.proof(&ac).unwrap()).unwrap().0)
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    drop(p);
    let report =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!((report.consumed_uses, report.recipient_generation), (0, 0));
}

#[test]
fn every_empty_recipient_custody_binding_is_checked_before_state_creation() {
    let paths = Paths::new();
    let other = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    bootstrap_synthetic_custody(&other.custody()).unwrap();
    let original = read_json(&paths.role("recipient"));
    let foreign = read_json(&other.role("recipient"));
    for field in ["vault_id", "recipient", "receipt", "writer_public"] {
        let mut changed = original.clone();
        changed[field] = foreign[field].clone();
        update_json(&paths.role("recipient"), &changed);
        assert!(
            matches!(
                create_synthetic_protocol(
                    &paths.root(),
                    &paths.role("broker"),
                    &paths.role("recipient"),
                    &paths.recipient(),
                    Arc::new(ManualClock::default())
                ),
                Err(ErrorCode::ScopeDenied)
            ),
            "{field}"
        );
        assert!(!paths.root().exists() && !paths.recipient().exists());
    }
    update_json(&paths.role("recipient"), &original);
    drop(paths.create());
}

#[test]
fn strict_bounded_custody_parsing_rejects_unknown_duplicate_oversize_and_symlink_files() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    let path = paths.role("broker");
    let original = fs::read(path.join(ROLE_FILE)).unwrap();
    let mut unknown: Value = serde_json::from_slice(&original).unwrap();
    unknown["admin"] = json!("unwanted extra private role");
    update_json(&path, &unknown);
    assert!(BrokerRole::open(&path).is_err());
    let duplicate = [b"{\"schema\":1,".as_slice(), &original[1..]].concat();
    fs::write(path.join(ROLE_FILE), duplicate).unwrap();
    assert!(BrokerRole::open(&path).is_err());
    fs::write(path.join(ROLE_FILE), vec![b' '; MAX_ROLE_DOCUMENT + 1]).unwrap();
    assert!(BrokerRole::open(&path).is_err());
    fs::write(path.join(ROLE_FILE), &original).unwrap();
    fs::rename(path.join(ROLE_FILE), path.join("original.json")).unwrap();
    std::os::unix::fs::symlink(path.join("original.json"), path.join(ROLE_FILE)).unwrap();
    assert!(BrokerRole::open(&path).is_err());
}

#[test]
fn cold_start_rejects_old_proofs_and_new_authentication_cannot_reuse_an_approval() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    let p = paths.create();
    let (agent, admin) = paths.actors();
    let old_agent = challenge(
        p.agent
            .handle(&frame("connect_challenge", json!({})).unwrap().0),
    )
    .unwrap();
    let old_admin = challenge(
        p.admin
            .handle(&frame("connect_challenge", json!({})).unwrap().0),
    )
    .unwrap();
    connect(&p, &agent, &admin).unwrap();
    let id = prepare(&p, "approved-only", 1).unwrap();
    approve(&p, &admin, id).unwrap();
    drop(p);
    let p = paths.open(1).unwrap();
    assert_eq!(
        p.agent
            .handle(
                &frame("connect", agent.proof(&old_agent).unwrap())
                    .unwrap()
                    .0
            )
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        p.admin
            .handle(
                &frame("connect", admin.proof(&old_admin).unwrap())
                    .unwrap()
                    .0
            )
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    connect(&p, &agent, &admin).unwrap();
    let id = prepare(&p, "fresh-request", 1).unwrap();
    assert_eq!(
        p.agent.handle(&invocation(&p, &agent, id).unwrap().0).error,
        Some(ErrorCode::ApprovalRequired)
    );
    drop(p);
    let report =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!(
        (
            report.consumed_uses,
            report.remaining_uses,
            report.recipient_generation
        ),
        (0, 4, 0)
    );
}

#[test]
fn separated_custody_preserves_consumed_uncertainty_without_a_new_grant() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    let broker = BrokerRole::open(&paths.role("broker")).unwrap();
    let store = Store::create(&paths.root(), broker.material).unwrap();
    let recipient = Recipient::create(
        &paths.recipient(),
        open_recipient_role(&paths.role("recipient")).unwrap(),
    )
    .unwrap();
    recipient.fault(store::RecipientFault::AfterSync);
    let p = SyntheticProtocol::assemble(
        broker.enrollment,
        store,
        recipient,
        1,
        Arc::new(ManualClock::default()),
    )
    .unwrap();
    let (agent, admin) = paths.actors();
    connect(&p, &agent, &admin).unwrap();
    let id = prepare(&p, "custody-unknown", 1).unwrap();
    approve(&p, &admin, id).unwrap();
    let input = invocation(&p, &agent, id).unwrap();
    let response = p.agent.handle(&input.0);
    assert_safe(&serde_json::to_string(&response).unwrap());
    let first = run(response).unwrap();
    assert_eq!(first.state, Lifecycle::OutcomeUnknown);
    assert_eq!(run(p.agent.handle(&input.0)).unwrap(), first);
    drop(p);
    let report =
        inspect_synthetic_custody(&paths.root(), &paths.custody(), &paths.recipient()).unwrap();
    assert_eq!(
        (
            report.consumed_uses,
            report.unknown_deliveries,
            report.remaining_uses,
            report.recipient_generation
        ),
        (1, 1, 3, 1)
    );
    assert!(!report.automatic_retry_allowed);
    assert!(matches!(
        paths.open(2),
        Err(ErrorCode::ReconciliationRequired)
    ));
}

#[test]
fn malformed_public_keys_and_reused_role_keys_fail_during_broker_loading() {
    let paths = Paths::new();
    bootstrap_synthetic_custody(&paths.custody()).unwrap();
    let path = paths.role("broker");
    let original = read_json(&path);
    for field in ["agent_public", "admin_public", "receipt_public"] {
        let mut bad = original.clone();
        bad[field] = json!(crypto::encode(b"not a public key"));
        update_json(&path, &bad);
        assert!(BrokerRole::open(&path).is_err());
    }
    let mut aliased = original.clone();
    aliased["admin_public"] = original["agent_public"].clone();
    update_json(&path, &aliased);
    assert!(BrokerRole::open(&path).is_err());
    let storage = identity(original["storage"].as_str().unwrap()).unwrap();
    let mut aliased = original.clone();
    aliased["recipient_public"] = json!(storage.recipient().to_string());
    update_json(&path, &aliased);
    assert!(BrokerRole::open(&path).is_err());
    update_json(&path, &original);
    assert!(BrokerRole::open(&path).is_ok());
}
