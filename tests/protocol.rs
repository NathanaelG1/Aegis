use aegis::{
    fake::{Executor, FakeProvider, ProviderOutcome, RawStatus, SYNTHETIC_CANARY},
    mcp::{Adapter, Bridge},
    protocol, *,
};
use serde_json::{json, Value};
use std::io::Cursor;
use std::sync::Arc;

fn fixture() -> (Control, AgentClient, Arc<FakeProvider>) {
    let provider = Arc::new(FakeProvider::default());
    let (control, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        provider.clone(),
    )
    .unwrap();
    (control, client, provider)
}
fn prepare() -> Value {
    json!({"version":1,"action":{"method":"prepare_operation","params":{"request_id":"wire-1","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}}})
}

#[test]
fn forged_authority_and_generic_operations_are_rejected_without_effects() {
    let (_, client, provider) = fixture();
    let mut forged = prepare();
    forged["action"]["params"]["approved"] = json!(true);
    let mut principal = prepare();
    principal["principal"] = json!("human");
    let mut url = prepare();
    url["action"]["params"]["parameters"]["url"] = json!("https://attacker.invalid");
    let cases = vec![
        forged,
        principal,
        url,
        json!({"version":1,"action":{"method":"approve","params":{"prepared_request_id":1}}}),
        json!({"version":1,"action":{"method":"get_secret"}}),
        json!({"version":1,"action":{"method":"exec","params":{"command":"env"}}}),
    ];
    for request in cases {
        assert_eq!(
            protocol::handle(&client, &serde_json::to_vec(&request).unwrap()).error,
            Some(ErrorCode::InvalidRequest)
        );
    }
    assert_eq!(provider.calls(), 0);
}
#[test]
fn malformed_frames_never_echo_input() {
    let (_, client, _) = fixture();
    for frame in [
        b"not JSON".as_slice(),
        b"{\"version\":1,\"version\":1,\"action\":{\"method\":\"discover_operations\"}}".as_slice(),
        SYNTHETIC_CANARY.as_bytes(),
    ] {
        let response = protocol::handle(&client, frame);
        assert_eq!(response.error, Some(ErrorCode::InvalidRequest));
        assert!(!serde_json::to_string(&response)
            .unwrap()
            .contains(SYNTHETIC_CANARY));
    }
    assert_eq!(
        protocol::handle(&client, &vec![b'x'; protocol::MAX_FRAME_BYTES + 1]).error,
        Some(ErrorCode::InvalidRequest)
    );
}
#[test]
fn version_and_integer_contracts_fail_closed() {
    let (_, client, _) = fixture();
    let mut version = prepare();
    version["version"] = json!(2);
    assert_eq!(
        protocol::handle(&client, &serde_json::to_vec(&version).unwrap()).error,
        Some(ErrorCode::UnsupportedVersion)
    );
    for issue in [
        json!(-1),
        json!(0),
        json!(1.5),
        json!(4294967296u64),
        json!("7"),
    ] {
        let mut request = prepare();
        request["action"]["params"]["parameters"]["issue_number"] = issue;
        assert_eq!(
            protocol::handle(&client, &serde_json::to_vec(&request).unwrap()).error,
            Some(ErrorCode::InvalidRequest)
        );
    }
}
#[test]
fn json_lines_vertical_slice_resume_and_retry() {
    let (control, client, provider) = fixture();
    let result = protocol::handle(&client, &serde_json::to_vec(&prepare()).unwrap());
    let id = result.result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    let call = |method| json!({"version":1,"action":{"method":method,"params":{"prepared_request_id":id}}});
    assert_eq!(
        protocol::handle(
            &client,
            &serde_json::to_vec(&call("invoke_approved")).unwrap()
        )
        .error,
        Some(ErrorCode::ApprovalRequired)
    );
    let pending = protocol::handle(
        &client,
        &serde_json::to_vec(&call("request_approval")).unwrap(),
    );
    assert_eq!(pending.result.unwrap()["state"], "awaiting_approval");
    control.approve(id).unwrap();
    let response = protocol::handle(
        &client,
        &serde_json::to_vec(&call("invoke_approved")).unwrap(),
    );
    assert_eq!(response.result.as_ref().unwrap()["result"]["state"], "open");
    assert_eq!(
        protocol::handle(
            &client,
            &serde_json::to_vec(&call("invoke_approved")).unwrap()
        )
        .result,
        response.result
    );
    assert_eq!(provider.calls(), 1);
}
#[test]
fn stream_limits_allocation_and_connection_work() {
    let (_, client, _) = fixture();
    let oversized = vec![b'x'; protocol::MAX_FRAME_BYTES * 4];
    let mut output = Vec::new();
    protocol::serve(Cursor::new(oversized), &mut output, &client).unwrap();
    assert_eq!(output.iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("invalid_request"));
    let line = "{\"version\":1,\"action\":{\"method\":\"discover_operations\"}}\n";
    let mut output = Vec::new();
    protocol::serve(
        Cursor::new(line.repeat(protocol::MAX_CONNECTION_FRAMES + 10)),
        &mut output,
        &client,
    )
    .unwrap();
    assert_eq!(
        output.iter().filter(|&&b| b == b'\n').count(),
        protocol::MAX_CONNECTION_FRAMES + 1
    );
    assert!(String::from_utf8(output)
        .unwrap()
        .ends_with("\"capacity_exceeded\"}\n"));
}
struct LocalBridge(AgentClient);
impl Bridge for LocalBridge {
    fn exchange(&mut self, request: &Value) -> protocol::Response {
        protocol::handle(&self.0, &serde_json::to_vec(request).unwrap())
    }
}
fn rpc(id: u64, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap()
}
fn initialize(adapter: &mut Adapter<impl Bridge>) {
    assert!(adapter.handle(&rpc(1,"initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"forged-admin-label","version":"test"}}))).unwrap().get("result").is_some());
}
fn tool(adapter: &mut Adapter<impl Bridge>, name: &str, arguments: Value) -> Value {
    adapter
        .handle(&rpc(
            2,
            "tools/call",
            json!({"name":name,"arguments":arguments}),
        ))
        .unwrap()
}
fn embedded(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
fn mcp_adapter_requires_initialization_and_exposes_only_fixed_tools() {
    let (_, client, _) = fixture();
    let mut adapter = Adapter::new(LocalBridge(client));
    assert_eq!(
        adapter.handle(&rpc(1, "tools/list", json!({}))).unwrap()["error"]["message"],
        "interaction_required"
    );
    initialize(&mut adapter);
    let tools = adapter.handle(&rpc(2, "tools/list", json!({}))).unwrap();
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 6);
    let names = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    for denied in ["approve", "get_secret", "exec", "proxy"] {
        assert!(!names.contains(&denied));
        assert!(tool(&mut adapter, denied, json!({})).get("error").is_some());
    }
}
#[test]
fn mcp_pending_is_not_authorization_and_host_metadata_is_not_identity() {
    let (control, client, provider) = fixture();
    let mut adapter = Adapter::new(LocalBridge(client));
    initialize(&mut adapter);
    let response = tool(
        &mut adapter,
        "prepare_operation",
        prepare()["action"]["params"].clone(),
    );
    let id = embedded(&response)["result"]["prepared_request_id"]
        .as_u64()
        .unwrap();
    let handle = json!({"prepared_request_id":id});
    assert_eq!(
        embedded(&tool(&mut adapter, "request_approval", handle.clone()))["result"]["state"],
        "awaiting_approval"
    );
    assert_eq!(
        embedded(&tool(&mut adapter, "invoke_approved", handle.clone()))["error"],
        "approval_required"
    );
    assert_eq!(
        control.inspect_approval(id).unwrap().principal.as_str(),
        "synthetic-host"
    );
    control.approve(id).unwrap();
    assert_eq!(
        embedded(&tool(&mut adapter, "invoke_approved", handle.clone()))["result"]["state"],
        "succeeded"
    );
    assert_eq!(
        embedded(&tool(&mut adapter, "invoke_approved", handle))["result"]["state"],
        "succeeded"
    );
    assert_eq!(provider.calls(), 1);
}
#[test]
fn mcp_notifications_cannot_trigger_operations() {
    let (_, client, provider) = fixture();
    let mut adapter = Adapter::new(LocalBridge(client));
    initialize(&mut adapter);
    let notification = json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"prepare_operation","arguments":prepare()["action"]["params"]}});
    assert!(adapter
        .handle(&serde_json::to_vec(&notification).unwrap())
        .is_none());
    assert_eq!(provider.calls(), 0);
    let forged = json!({"prepared_request_id":1,"approved":true});
    assert!(tool(&mut adapter, "invoke_approved", forged)
        .get("error")
        .is_some());
}
#[test]
fn mcp_stdout_is_json_only_without_credential_canary() {
    let (_, client, _) = fixture();
    let initialize = rpc(
        1,
        "initialize",
        json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"test"}}),
    );
    let mut input = initialize;
    input.push(b'\n');
    input.extend(rpc(2, "tools/list", json!({})));
    input.push(b'\n');
    let mut output = Vec::new();
    aegis::mcp::serve(Cursor::new(input), &mut output, LocalBridge(client)).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains(SYNTHETIC_CANARY));
    assert_eq!(output.lines().count(), 2);
    for line in output.lines() {
        assert_eq!(
            serde_json::from_str::<Value>(line).unwrap()["jsonrpc"],
            "2.0"
        );
    }
}
struct Hostile;
#[test]
fn mcp_marks_terminal_provider_failure_as_a_tool_error() {
    let setup = SyntheticSetup {
        approval_mode: ApprovalMode::BoundedSession,
        ..SyntheticSetup::default()
    };
    let (_, client) =
        Control::synthetic(setup, Arc::new(ManualClock::default()), Arc::new(Hostile)).unwrap();
    let mut adapter = Adapter::new(LocalBridge(client));
    initialize(&mut adapter);
    let prepared = tool(
        &mut adapter,
        "prepare_operation",
        prepare()["action"]["params"].clone(),
    );
    let id = embedded(&prepared)["result"]["prepared_request_id"]
        .as_u64()
        .unwrap();
    let response = tool(
        &mut adapter,
        "invoke_approved",
        json!({"prepared_request_id":id}),
    );
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        embedded(&response)["result"]["error"],
        "invalid_provider_result"
    );
    assert!(!response.to_string().contains(SYNTHETIC_CANARY));
}

#[test]
fn oversized_mcp_frame_closes_without_processing_following_tools() {
    let (_, client, provider) = fixture();
    let mut input = vec![b'x'; protocol::MAX_FRAME_BYTES + 1];
    input.push(b'\n');
    input.extend(rpc(
        1,
        "tools/call",
        json!({"name":"prepare_operation","arguments":prepare()["action"]["params"]}),
    ));
    let mut output = Vec::new();
    aegis::mcp::serve(Cursor::new(input), &mut output, LocalBridge(client)).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&output).unwrap()["error"]["message"],
        "invalid_request"
    );
    assert_eq!(provider.calls(), 0);
}
impl Executor for Hostile {
    fn execute(&self, d: &aegis::fake::Dispatch) -> ProviderOutcome {
        ProviderOutcome::Status(RawStatus {
            repository_id: d.parameters.repository_id,
            issue_number: d.parameters.issue_number,
            state: SYNTHETIC_CANARY.into(),
        })
    }
}
#[test]
fn hostile_provider_canary_is_rejected_without_raw_output() {
    let setup = SyntheticSetup {
        approval_mode: ApprovalMode::BoundedSession,
        ..SyntheticSetup::default()
    };
    let (_, client) =
        Control::synthetic(setup, Arc::new(ManualClock::default()), Arc::new(Hostile)).unwrap();
    let request = client
        .prepare(serde_json::from_value(prepare()["action"]["params"].clone()).unwrap())
        .unwrap();
    let response = client.invoke(request.prepared_request_id).unwrap();
    assert_eq!(response.error, Some(ErrorCode::InvalidProviderResult));
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(SYNTHETIC_CANARY));
}
