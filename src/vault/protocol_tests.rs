use super::*;
use crate::{Lifecycle, ManualClock, OperationIntent, ProfileId, RequestId};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Paths(PathBuf);
impl Paths {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "aegis-protocol-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn root(&self) -> PathBuf {
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
fn frame(method: &str, params: impl Serialize) -> Vec<u8> {
    serde_json::to_vec(&json!({"protocol": PROTOCOL, "version": VERSION, "action": {"method": method, "params": params}})).unwrap()
}
fn proof(actors: &auth::Actors, challenge: &ProofChallenge) -> Value {
    let signed = actors.sign(challenge).unwrap();
    json!({"assertion": std::str::from_utf8(signed.bytes()).unwrap()})
}
fn challenge(response: ProtocolResponse) -> ProofChallenge {
    assert_eq!(response.error, None);
    let Some(ProtocolResult::Challenge(c)) = response.result else {
        panic!("expected challenge")
    };
    c
}
fn review(response: ProtocolResponse) -> ReviewPlan {
    assert_eq!(response.error, None);
    let Some(ProtocolResult::Review(r)) = response.result else {
        panic!("expected review")
    };
    *r
}
fn run(response: ProtocolResponse) -> OperationRunView {
    assert_eq!(response.error, None);
    let Some(ProtocolResult::Run(r)) = response.result else {
        panic!("expected run")
    };
    r
}
fn setup() -> (Paths, Arc<ManualClock>, SyntheticProtocol, Arc<Kit>) {
    let paths = Paths::new();
    let clock = Arc::new(ManualClock::default());
    let protocol = SyntheticProtocol::create(
        &paths.root(),
        &paths.kit(),
        &paths.recipient(),
        clock.clone(),
    )
    .unwrap();
    let kit = Kit::open(&paths.kit()).unwrap();
    (paths, clock, protocol, kit)
}
fn connect_agent(p: &SyntheticProtocol, a: &auth::Actors) {
    let c = challenge(p.agent.handle(&frame("connect_challenge", json!({}))));
    assert!(matches!(
        p.agent.handle(&frame("connect", proof(a, &c))).result,
        Some(ProtocolResult::Connected)
    ));
}
fn connect_admin(p: &SyntheticProtocol, a: &auth::Actors) {
    let c = challenge(p.admin.handle(&frame("connect_challenge", json!({}))));
    assert_eq!(c.purpose, Purpose::AdminConnect);
    assert!(matches!(
        p.admin.handle(&frame("connect", proof(a, &c))).result,
        Some(ProtocolResult::Connected)
    ));
}
fn prepare(p: &SyntheticProtocol, id: &str, version: u64) -> u64 {
    let input = OperationPrepareInput {
        request_id: RequestId::new(id).unwrap(),
        profile_id: ProfileId::new("vault-delivery").unwrap(),
        operation: OperationIntent::Delivery(super::super::DeliveryParameters::fixture(version)),
    };
    let id = run(p.agent.handle(&frame("prepare_operation", input))).prepared_request_id;
    assert_eq!(
        run(p.agent.handle(&frame(
            "request_approval",
            json!({"prepared_request_id":id})
        )))
        .state,
        Lifecycle::AwaitingApproval
    );
    id
}
fn approve(p: &SyntheticProtocol, a: &auth::Actors, id: u64) {
    let expected = review(
        p.admin
            .handle(&frame("inspect_review", json!({"prepared_request_id":id}))),
    );
    let c = challenge(p.admin.handle(&frame("approval_challenge", &expected)));
    assert_eq!(
        run(p.admin.handle(&frame(
            "approve",
            json!({"expected":expected,"proof":proof(a,&c)})
        )))
        .state,
        Lifecycle::Approved
    );
}
fn invocation(p: &SyntheticProtocol, a: &auth::Actors, id: u64) -> Vec<u8> {
    let c = challenge(p.agent.handle(&frame(
        "invocation_challenge",
        json!({"prepared_request_id":id}),
    )));
    frame(
        "invoke_approved",
        json!({"prepared_request_id":id,"proof":proof(a,&c)}),
    )
}
fn safe(response: &ProtocolResponse) {
    let json = serde_json::to_string(response).unwrap();
    let debug = format!("{response:?}");
    for text in [&json, &debug] {
        assert!(!text.contains(super::super::store::CANARY_ONE));
        assert!(!text.contains(super::super::store::CANARY_TWO));
        assert!(!text.contains("AGE-SECRET-KEY"));
        assert!(!text.contains("assertion"));
    }
}

#[test]
fn serialized_roles_deliver_rotate_replay_and_revoke_across_cold_start() {
    let (paths, clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "wire-install", 1);
    approve(&p, &kit.actors, id);
    let frame = invocation(&p, &kit.actors, id);
    let result = p.agent.handle(&frame);
    safe(&result);
    let first = run(result);
    assert_eq!(first.state, Lifecycle::Succeeded);
    assert_eq!(run(p.agent.handle(&frame)), first);
    drop(p);
    let p =
        SyntheticProtocol::open(&paths.root(), &paths.kit(), &paths.recipient(), 2, clock).unwrap();
    assert_eq!(
        p.agent
            .handle(&self::frame(
                "get_run_status",
                json!({"prepared_request_id":id})
            ))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        p.admin
            .handle(&self::frame(
                "inspect_review",
                json!({"prepared_request_id":id})
            ))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "wire-rotate", 2);
    approve(&p, &kit.actors, id);
    let second = p.agent.handle(&invocation(&p, &kit.actors, id));
    safe(&second);
    assert_eq!(run(second).state, Lifecycle::Succeeded);
    let c = challenge(p.admin.handle(&self::frame("revoke_challenge", json!({}))));
    assert!(matches!(
        p.admin
            .handle(&self::frame("revoke", proof(&kit.actors, &c)))
            .result,
        Some(ProtocolResult::Revoked)
    ));
    assert_eq!(
        p.agent
            .handle(&self::frame(
                "get_run_status",
                json!({"prepared_request_id":id})
            ))
            .error,
        Some(ErrorCode::GrantRevoked)
    );
    drop(p);
    let report =
        super::super::inspect_synthetic_vault(&paths.root(), &paths.kit(), &paths.recipient())
            .unwrap();
    assert_eq!(report.consumed_uses, 2);
    assert_eq!(report.remaining_uses, 2);
    assert!(report.revoked);
    assert!(!report.ready_for_real_keys);
}

#[test]
fn every_non_bootstrap_handler_requires_its_own_role_authentication() {
    let (_paths, _clock, p, kit) = setup();
    for method in [
        "discover_operations",
        "request_approval",
        "invocation_challenge",
        "get_run_status",
        "cancel",
    ] {
        let params = if method == "discover_operations" {
            json!({})
        } else {
            json!({"prepared_request_id":999})
        };
        let result = p.agent.handle(&frame(method, params));
        safe(&result);
        assert_eq!(
            result.error,
            Some(ErrorCode::AuthenticationRequired),
            "{method}"
        );
    }
    for method in ["inspect_review", "revoke_challenge", "revoke"] {
        let params = match method {
            "inspect_review" => json!({"prepared_request_id":999}),
            "revoke" => json!({"assertion":"not-a-proof"}),
            _ => json!({}),
        };
        assert_eq!(
            p.admin.handle(&frame(method, params)).error,
            Some(ErrorCode::AuthenticationRequired),
            "{method}"
        );
    }
    connect_agent(&p, &kit.actors);
    let id = prepare(&p, "agent-alone", 1);
    assert_eq!(
        p.admin
            .handle(&frame("inspect_review", json!({"prepared_request_id":id})))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        p.agent
            .handle(&frame("inspect_review", json!({"prepared_request_id":id})))
            .error,
        Some(ErrorCode::InvalidRequest)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
}

#[test]
fn agent_proof_does_not_connect_admin_and_endpoint_methods_do_not_cross_roles() {
    let (_paths, _clock, p, kit) = setup();
    let agent_challenge = challenge(p.agent.handle(&frame("connect_challenge", json!({}))));
    let assertion = proof(&kit.actors, &agent_challenge);
    assert_eq!(
        p.admin.handle(&frame("connect", &assertion)).error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert!(matches!(
        p.agent.handle(&frame("connect", assertion)).result,
        Some(ProtocolResult::Connected)
    ));
    connect_admin(&p, &kit.actors);
    assert_eq!(
        p.admin
            .handle(&frame("discover_operations", json!({})))
            .error,
        Some(ErrorCode::InvalidRequest)
    );
    for method in [
        "revoke_challenge",
        "revoke",
        "approve",
        "import_secret",
        "export_secret",
    ] {
        assert_eq!(
            p.agent.handle(&frame(method, json!({}))).error,
            Some(ErrorCode::InvalidRequest)
        );
    }
}

#[test]
fn exact_review_and_proof_binding_survive_serialization() {
    let (_paths, _clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let first = prepare(&p, "first", 1);
    let second = prepare(&p, "second", 1);
    let expected = review(p.admin.handle(&frame(
        "inspect_review",
        json!({"prepared_request_id":first}),
    )));
    let c = challenge(p.admin.handle(&frame("approval_challenge", &expected)));
    let signed = proof(&kit.actors, &c);
    let mut changed = expected.clone();
    changed.operation.repository_id += 1;
    assert_eq!(
        p.admin
            .handle(&frame(
                "approve",
                json!({"expected":changed,"proof":signed})
            ))
            .error,
        Some(ErrorCode::ApprovalRequired)
    );
    let other = review(p.admin.handle(&frame(
        "inspect_review",
        json!({"prepared_request_id":second}),
    )));
    assert_eq!(
        p.admin
            .handle(&frame(
                "approve",
                json!({"expected":other,"proof":proof(&kit.actors,&c)})
            ))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    // The correctly signed but misbound attempt consumed the challenge.
    assert_eq!(
        p.admin
            .handle(&frame(
                "approve",
                json!({"expected":expected,"proof":proof(&kit.actors,&c)})
            ))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
    assert_eq!(p.agent.service.adapter.recipient.generation().unwrap(), 0);
}

#[test]
fn cold_start_rejects_old_agent_and_admin_assertions() {
    let (paths, clock, p, kit) = setup();
    let agent = challenge(p.agent.handle(&frame("connect_challenge", json!({}))));
    let admin = challenge(p.admin.handle(&frame("connect_challenge", json!({}))));
    let agent_proof = proof(&kit.actors, &agent);
    let admin_proof = proof(&kit.actors, &admin);
    drop(p);
    let p =
        SyntheticProtocol::open(&paths.root(), &paths.kit(), &paths.recipient(), 1, clock).unwrap();
    assert_eq!(
        p.agent.handle(&frame("connect", agent_proof)).error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        p.admin.handle(&frame("connect", admin_proof)).error,
        Some(ErrorCode::AuthenticationRequired)
    );
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
}

#[test]
fn parser_limits_unknown_fields_duplicates_and_errors_do_not_echo_assertions() {
    let (_paths, _clock, p, _kit) = setup();
    let mut unknown: Value =
        serde_json::from_slice(&frame("connect_challenge", json!({}))).unwrap();
    unknown["principal"] = json!("synthetic-vault-admin");
    let mut wrong_version = unknown.clone();
    wrong_version.as_object_mut().unwrap().remove("principal");
    wrong_version["version"] = json!(2);
    for bytes in [
        serde_json::to_vec(&unknown).unwrap(),
        b"{\"protocol\":\"a\",\"protocol\":\"b\",\"version\":1,\"action\":{}}".to_vec(),
        vec![b'x'; MAX_FRAME_BYTES + 1],
        frame(
            "connect",
            json!({"assertion":super::super::store::CANARY_ONE}),
        ),
        frame("connect", json!({"assertion":"x","approved":true})),
    ] {
        let result = p.agent.handle(&bytes);
        assert!(result.error.is_some());
        safe(&result);
    }
    assert_eq!(
        p.agent
            .handle(&serde_json::to_vec(&wrong_version).unwrap())
            .error,
        Some(ErrorCode::UnsupportedVersion)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
}

#[test]
fn admin_session_is_rechecked_inside_approval_mutation_hook() {
    let (_paths, clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    clock.set(590);
    let id = prepare(&p, "late-approval", 1);
    let actual = p
        .agent
        .service
        .control
        .inspect_operation_approval(id)
        .unwrap();
    let expected = Review::of(&actual).unwrap();
    let c = challenge(p.admin.handle(&frame("approval_challenge", &expected)));
    p.admin
        .service
        .adapter
        .gate
        .stage_admin(id, p.admin.session().unwrap(), kit.actors.sign(&c).unwrap())
        .unwrap();
    clock.set(600);
    assert_eq!(
        p.admin.service.adapter.gate.approval(&actual),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        p.admin
            .handle(&frame("inspect_review", json!({"prepared_request_id":id})))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
}

#[test]
fn runtime_roles_do_not_retain_actor_signers_or_broker_access_to_recipient_signing_keys() {
    let paths = Paths::new();
    let clock = Arc::new(ManualClock::default());
    let kit = Kit::create(&paths.kit()).unwrap();
    let agent = Arc::downgrade(&kit.actors.agent);
    let admin = Arc::downgrade(&kit.actors.admin);
    let receipt = Arc::downgrade(&kit.receipt);
    let store = Store::create(&paths.root(), kit.broker_material()).unwrap();
    let recipient = Recipient::create(&paths.recipient(), kit.recipient_material()).unwrap();
    let p =
        SyntheticProtocol::assemble(kit.actors.enrollment(), store, recipient, 1, clock).unwrap();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "drop-signers", 1);
    approve(&p, &kit.actors, id);
    let frame = invocation(&p, &kit.actors, id);
    drop(kit);
    assert!(agent.upgrade().is_none());
    assert!(admin.upgrade().is_none());
    assert_eq!(receipt.strong_count(), 1); // only recipient material owns the signing key
    assert_eq!(run(p.agent.handle(&frame)).state, Lifecycle::Succeeded);
}

#[test]
fn status_cancel_and_cached_results_require_the_original_live_connection() {
    let (_paths, clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "status-scope", 1);
    approve(&p, &kit.actors, id);
    let response = p.agent.handle(&invocation(&p, &kit.actors, id));
    assert_eq!(run(response).state, Lifecycle::Succeeded);
    let unbound = AgentEndpoint {
        service: p.agent.service.clone(),
        initial: p.agent.initial.clone(),
        client: Mutex::new(None),
        frames: AtomicUsize::new(0),
    };
    for method in [
        "get_run_status",
        "cancel",
        "request_approval",
        "invocation_challenge",
    ] {
        assert_eq!(
            unbound
                .handle(&frame(method, json!({"prepared_request_id":id})))
                .error,
            Some(ErrorCode::AuthenticationRequired)
        );
    }
    clock.set(600);
    assert_eq!(
        p.agent
            .handle(&frame("get_run_status", json!({"prepared_request_id":id})))
            .error,
        Some(ErrorCode::AuthenticationRequired)
    );
}

#[test]
fn endpoint_frame_budget_is_bounded_including_invalid_requests() {
    let (_paths, _clock, p, _kit) = setup();
    for _ in 0..MAX_ENDPOINT_FRAMES {
        assert_eq!(p.agent.handle(b"!").error, Some(ErrorCode::InvalidRequest));
    }
    assert_eq!(
        p.agent.handle(&frame("connect_challenge", json!({}))).error,
        Some(ErrorCode::CapacityExceeded)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
}

#[test]
fn serialized_duplicate_during_delivery_never_reserves_a_second_use() {
    let (_paths, _clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "concurrent-wire", 1);
    approve(&p, &kit.actors, id);
    let input = invocation(&p, &kit.actors, id);
    let (entered, pause) = p.agent.service.adapter.recipient.pause();
    let p = Arc::new(p);
    let worker = p.clone();
    let first_input = input.clone();
    let call = std::thread::spawn(move || worker.agent.handle(&first_input));
    let wait = entered.recv_timeout(std::time::Duration::from_secs(5));
    if wait.is_err() {
        pause.release();
    }
    wait.unwrap();
    let repeated = run(p.agent.handle(&input));
    pause.release();
    assert_eq!(repeated.state, Lifecycle::Dispatched);
    assert_eq!(run(call.join().unwrap()).state, Lifecycle::Succeeded);
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 3);
    assert_eq!(p.agent.service.adapter.store.history_counts().unwrap().0, 1);
    assert_eq!(p.agent.service.adapter.recipient.generation().unwrap(), 1);
}

#[test]
fn serialized_uncertainty_remains_consumed_and_safe() {
    let (_paths, clock, p, kit) = setup();
    connect_agent(&p, &kit.actors);
    connect_admin(&p, &kit.actors);
    let id = prepare(&p, "unknown-wire", 1);
    approve(&p, &kit.actors, id);
    p.agent
        .service
        .adapter
        .recipient
        .fault(super::super::store::RecipientFault::AfterSync);
    let input = invocation(&p, &kit.actors, id);
    let result = p.agent.handle(&input);
    safe(&result);
    let expected = run(result);
    assert_eq!(expected.state, Lifecycle::OutcomeUnknown);
    assert_eq!(run(p.agent.handle(&input)), expected);
    assert_eq!(
        run(p
            .agent
            .handle(&frame("get_run_status", json!({"prepared_request_id":id})))),
        expected
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 3);
    clock.set(600);
    assert_eq!(
        p.agent.handle(&input).error,
        Some(ErrorCode::AuthenticationRequired)
    );
}

#[test]
fn authenticated_wire_identity_with_an_empty_acl_cannot_discover_or_prepare() {
    let paths = Paths::new();
    let clock = Arc::new(ManualClock::default());
    let kit = Kit::create(&paths.kit()).unwrap();
    let store = Store::create_with_acl(&paths.root(), kit.broker_material(), vec![]).unwrap();
    let recipient = Recipient::create(&paths.recipient(), kit.recipient_material()).unwrap();
    let p =
        SyntheticProtocol::assemble(kit.actors.enrollment(), store, recipient, 1, clock).unwrap();
    connect_agent(&p, &kit.actors);
    assert_eq!(
        p.agent
            .handle(&frame("discover_operations", json!({})))
            .error,
        Some(ErrorCode::ScopeDenied)
    );
    let input = OperationPrepareInput {
        request_id: RequestId::new("no-acl").unwrap(),
        profile_id: ProfileId::new("vault-delivery").unwrap(),
        operation: OperationIntent::Delivery(super::super::DeliveryParameters::fixture(1)),
    };
    assert_eq!(
        p.agent.handle(&frame("prepare_operation", input)).error,
        Some(ErrorCode::ScopeDenied)
    );
    assert_eq!(p.agent.service.control.remaining_uses().unwrap(), 4);
    assert_eq!(p.agent.service.adapter.recipient.generation().unwrap(), 0);
}
