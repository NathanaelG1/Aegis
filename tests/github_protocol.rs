#![cfg(unix)]
use aegis::mcp::{Adapter, Bridge};
use aegis::*;
use serde_json::{json, Value};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "aegis-v2-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn setup() -> (Directory, Control, AgentClient) {
    let d = Directory::new();
    let (c, a) = Control::synthetic_github(
        OperationSetup::synthetic_github(),
        Arc::new(ManualClock::default()),
        &d.journal(),
    )
    .unwrap();
    (d, c, a)
}
fn prepare(id: &str) -> Value {
    json!({"version":2,"action":{"method":"prepare_operation","params":{"request_id":id,"profile_id":"github-metadata","operation":{"kind":"synthetic.github.repository-metadata.v1","parameters":{"repository_id":4242}}}}})
}
fn action(method: &str, id: u64) -> Value {
    json!({"version":2,"action":{"method":method,"params":{"prepared_request_id":id}}})
}
fn call(client: &AgentClient, value: Value) -> protocol::Response {
    protocol::handle(client, &serde_json::to_vec(&value).unwrap())
}
#[test]
fn v2_wire_pauses_for_review_and_returns_only_versioned_projection() {
    let (_d, c, a) = setup();
    let response = call(&a, prepare("wire"));
    assert_eq!(response.version, 2);
    let id = response.result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    assert_eq!(
        call(&a, action("invoke_approved", id)).error,
        Some(ErrorCode::ApprovalRequired)
    );
    call(&a, action("request_approval", id));
    let review = c.inspect_operation_approval(id).unwrap();
    c.approve_operation_reviewed(id, &review).unwrap();
    let result = call(&a, action("invoke_approved", id));
    assert_eq!(result.version, 2);
    assert_eq!(
        result.result.as_ref().unwrap()["result"],
        json!({"kind":"synthetic.github.repository-metadata.v1","value":{"repository_id":4242,"private":false,"archived":false}})
    );
    assert_eq!(
        call(&a, action("invoke_approved", id)).result,
        result.result
    );
    assert_eq!(c.remaining_uses().unwrap(), 19);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("AEGIS_SYNTHETIC"));
    assert!(!serialized.contains("token"));
}
#[test]
fn v1_handle_methods_cannot_mutate_or_dispatch_github_operations() {
    let (_d, c, a) = setup();
    let id = call(&a, prepare("legacy")).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    for method in [
        "request_approval",
        "invoke_approved",
        "get_run_status",
        "cancel",
    ] {
        let mut value = action(method, id);
        value["version"] = json!(1);
        assert_eq!(call(&a, value).error, Some(ErrorCode::ScopeDenied));
    }
    assert_eq!(a.operation_status(id).unwrap().state, Lifecycle::Prepared);
    assert_eq!(c.remaining_uses().unwrap(), 20);
}
#[test]
fn v2_rejects_unknown_duplicate_authority_and_operation_fields() {
    let (_d, c, a) = setup();
    let good = serde_json::to_string(&prepare("malformed")).unwrap();
    for bad in [
        good.replace(
            "\"repository_id\":4242",
            "\"repository_id\":999,\"repository_id\":4242",
        ),
        good.replace(
            "\"repository_id\":4242",
            "\"repository_id\":999,\"repository_\\u0069d\":4242",
        ),
        good.replace("\"version\":2", "\"version\":1,\"version\":2"),
        good.replace(
            "\"request_id\":\"malformed\"",
            "\"request_id\":\"malformed\",\"approved\":true",
        ),
        good.replace(
            "\"repository_id\":4242",
            "\"repository_id\":4242,\"token\":\"canary\"",
        ),
        good.replace(
            "\"repository_id\":4242",
            "\"repository_id\":4242,\"issue_number\":7",
        ),
        good.replace(
            "synthetic.github.repository-metadata.v1",
            "synthetic.github.repository-metadata.v2",
        ),
        r#"{"version":2,"action":{"method":"approve","params":{"prepared_request_id":1}}}"#.into(),
        r#"{"version":2,"action":{"method":"discover_operations","params":{"approved":true}}}"#
            .into(),
        r#"{"version":2,"action":{"method":"discover_operations","params":{},"extra":true}}"#
            .into(),
    ] {
        assert!(
            protocol::handle(&a, bad.as_bytes()).error.is_some(),
            "{bad}"
        );
    }
    assert_eq!(c.remaining_uses().unwrap(), 20);
    assert_eq!(a.operation_status(1), Err(ErrorCode::NotFound));
}
#[test]
fn v2_issue_shape_and_legacy_result_remain_compatible() {
    let (c, a) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(aegis::fake::FakeProvider::default()),
    )
    .unwrap();
    let request = json!({"version":2,"action":{"method":"prepare_operation","params":{"request_id":"issue-v2","profile_id":"issue-status","operation":{"kind":"synthetic.issue-status.v1","parameters":{"repository_id":4242,"issue_number":7}}}}});
    let id = call(&a, request).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    a.request_approval(id).unwrap();
    c.approve(id).unwrap();
    let result = call(&a, action("invoke_approved", id));
    assert_eq!(
        result.result.unwrap()["result"]["kind"],
        "synthetic.issue-status.v1"
    );
    assert_eq!(
        a.status(id).unwrap().result.unwrap().state,
        IssueState::Open
    );
}
struct Local(AgentClient);
impl Bridge for Local {
    fn exchange(&mut self, value: &Value) -> protocol::Response {
        call(&self.0, value.clone())
    }
}
fn rpc(id: u64, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap()
}
fn initialize(adapter: &mut Adapter<impl Bridge>) {
    assert!(adapter.handle(&rpc(1,"initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"untrusted-owner-label","version":"test"}}))).unwrap().get("result").is_some());
}
#[test]
fn explicit_v2_mcp_uses_same_six_tools_with_closed_versioned_inputs() {
    let (_d, c, a) = setup();
    let mut adapter = Adapter::new_v2(Local(a.clone()));
    initialize(&mut adapter);
    let listing = adapter.handle(&rpc(2, "tools/list", json!({}))).unwrap();
    assert_eq!(listing["result"]["tools"].as_array().unwrap().len(), 6);
    assert!(listing
        .to_string()
        .contains("synthetic.github.repository-metadata.v1"));
    let prepared = adapter
        .handle(&rpc(
            3,
            "tools/call",
            json!({"name":"prepare_operation","arguments":prepare("mcp")["action"]["params"]}),
        ))
        .unwrap();
    let response: Value =
        serde_json::from_str(prepared["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(response["version"], 2);
    let id = response["result"]["prepared_request_id"].as_u64().unwrap();
    adapter
        .handle(&rpc(
            4,
            "tools/call",
            json!({"name":"request_approval","arguments":{"prepared_request_id":id}}),
        ))
        .unwrap();
    assert_eq!(a.invoke_operation(id), Err(ErrorCode::ApprovalRequired));
    let review = c.inspect_operation_approval(id).unwrap();
    c.approve_operation_reviewed(id, &review).unwrap();
    let result = adapter
        .handle(&rpc(
            5,
            "tools/call",
            json!({"name":"invoke_approved","arguments":{"prepared_request_id":id}}),
        ))
        .unwrap();
    assert_eq!(result["result"]["isError"], false);
    assert!(!result.to_string().contains("AEGIS_SYNTHETIC"));
    let forged = adapter
        .handle(&rpc(
            6,
            "tools/call",
            json!({"name":"approve","arguments":{"prepared_request_id":id}}),
        ))
        .unwrap();
    assert_eq!(forged["error"]["message"], "scope_denied");
}
#[test]
fn v2_framing_still_requires_lf_and_respects_frame_limits() {
    let (_d, _c, a) = setup();
    let mut output = Vec::new();
    protocol::serve(
        Cursor::new(serde_json::to_vec(&prepare("partial")).unwrap()),
        &mut output,
        &a,
    )
    .unwrap();
    assert_eq!(a.operation_status(1), Err(ErrorCode::NotFound));
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("invalid_request"));
    assert_eq!(
        protocol::handle(&a, &vec![b'x'; protocol::MAX_FRAME_BYTES + 1]).error,
        Some(ErrorCode::InvalidRequest)
    );
}
#[test]
fn existing_journal_schema1_and_new_schema2_inspection_are_both_read_only() {
    let legacy = Directory::new();
    aegis::github::create_synthetic_intent_drill(&legacy.journal()).unwrap();
    let report = aegis::github::inspect_synthetic_intents(&legacy.journal()).unwrap();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.restored_sessions, 0);
    let (d, c, a) = setup();
    let id = call(&a, prepare("schema2")).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    a.request_operation_approval(id).unwrap();
    let r = c.inspect_operation_approval(id).unwrap();
    c.approve_operation_reviewed(id, &r).unwrap();
    a.invoke_operation(id).unwrap();
    drop(c);
    drop(a);
    let path = d.journal().join("intents.jsonl");
    let bytes = std::fs::read(&path).unwrap();
    let report = aegis::github::inspect_synthetic_intents(&d.journal()).unwrap();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
fn schema2_rejects_mixed_versions_modified_review_and_budget_claims() {
    let (d, c, a) = setup();
    let id = call(&a, prepare("schema2")).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    a.request_operation_approval(id).unwrap();
    let r = c.inspect_operation_approval(id).unwrap();
    c.approve_operation_reviewed(id, &r).unwrap();
    a.invoke_operation(id).unwrap();
    drop(c);
    drop(a);
    let path = d.journal().join("intents.jsonl");
    let original = std::fs::read_to_string(&path).unwrap();
    let records: Vec<Value> = original
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records[0]["event"]["enrollment"]["operation"],
        "synthetic.github.repository-metadata.v1"
    );
    assert_eq!(
        records[1]["event"]["intent"]["enrollment"]["operation"],
        "synthetic.github.repository-metadata.v1"
    );

    for (pointer, value) in [
        ("/schema_version", json!(1)),
        ("/event/review/principal", json!("other")),
        ("/event/review/session", json!(2)),
        ("/event/review/prepared_request_id", json!(0)),
        ("/event/review/reviewed_request_id", json!("other-id")),
        ("/event/review/profile_revision", json!(2)),
        ("/event/review/policy_generation", json!(2)),
        ("/event/review/credential_version", json!(2)),
        ("/event/review/remaining_before", json!(19)),
        ("/event/review/remaining_after", json!(20)),
        ("/event/review/reviewed_remaining_uses", json!(0)),
        ("/event/review/reviewed_expires_elapsed", json!(999)),
    ] {
        let mut changed = records.clone();
        *changed[1].pointer_mut(pointer).unwrap() = value;
        let encoded = changed
            .iter()
            .map(|record| serde_json::to_string(record).unwrap() + "\n")
            .collect::<String>();
        std::fs::write(&path, encoded).unwrap();
        assert!(
            aegis::github::inspect_synthetic_intents(&d.journal()).is_err(),
            "{pointer}"
        );
    }
    std::fs::write(&path, original).unwrap();
    assert!(aegis::github::inspect_synthetic_intents(&d.journal()).is_ok());
}
#[test]
fn new_github_foreground_requires_real_terminal_unless_explicit_fixture_flag() {
    let directory = Directory::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["synthetic-github-broker", "--socket-dir"])
        .arg(directory.0.join("socket"))
        .arg("--journal-dir")
        .arg(directory.journal())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interaction_required"));
    assert!(!directory.journal().exists());
}
