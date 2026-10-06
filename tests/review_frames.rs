//! Adversarial framing and MCP parser regressions from independent review.
use aegis::fake::FakeProvider;
use aegis::mcp::{self, Adapter, Bridge, MCP_VERSION};
use aegis::{protocol, Control, ErrorCode, ManualClock, SyntheticSetup};
use serde_json::{json, Value};
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct CountBridge(Arc<AtomicUsize>);
impl Bridge for CountBridge {
    fn exchange(&mut self, _: &Value) -> protocol::Response {
        self.0.fetch_add(1, Ordering::SeqCst);
        protocol::Response::failure(ErrorCode::InteractionRequired)
    }
}
fn initialize() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}})).unwrap()
}

#[test]
fn eof_cannot_execute_an_unterminated_broker_prepare_frame() {
    let (_, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let frame = br#"{"version":1,"action":{"method":"prepare_operation","params":{"request_id":"unterminated","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}}}"#;
    let mut output = Vec::new();
    protocol::serve(Cursor::new(frame), &mut output, &client).unwrap();
    let response: protocol::Response = serde_json::from_slice(&output).unwrap();
    assert_eq!(response.error, Some(ErrorCode::InvalidRequest));
    assert_eq!(client.status(1), Err(ErrorCode::NotFound));
}

#[test]
fn frame_byte_boundary_includes_the_required_newline() {
    let (_, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    for extra in [0, 1] {
        let mut frame = br#"{"version":1,"action":{"method":"discover_operations"}}"#.to_vec();
        frame.resize(protocol::MAX_FRAME_BYTES - 1 + extra, b' ');
        frame.push(b'\n');
        let mut output = Vec::new();
        protocol::serve(Cursor::new(frame), &mut output, &client).unwrap();
        let response: protocol::Response = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            response.error,
            if extra == 0 {
                None
            } else {
                Some(ErrorCode::InvalidRequest)
            }
        );
    }
}

#[test]
fn eof_cannot_execute_an_unterminated_mcp_tool_frame() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut input = initialize();
    input.push(b'\n');
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"discover_operations","arguments":{}}}"#);
    let mut output = Vec::new();
    mcp::serve(Cursor::new(input), &mut output, CountBridge(calls.clone())).unwrap();
    let responses: Vec<Value> = output
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1]["error"]["code"], -32600);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn mcp_rejects_duplicate_members_before_any_bridge_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut adapter = Adapter::new(CountBridge(calls.clone()));
    adapter.handle(&initialize()).unwrap();
    for frame in [
        r#"{"jsonrpc":"2.0","id":2,"method":"ping","method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"prepare_operation","arguments":{"request_id":"duplicate","profile_id":"issue-status","parameters":{"repository_id":9999,"repository_id":4242,"issue_number":7}}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"prepare_operation","arguments":{"request_id":"duplicate","profile_id":"issue-status","parameters":{"repository_id":9999,"repository_\u0069d":4242,"issue_number":7}}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"discover_operations","arguments":{},"arguments":{}}}"#,
    ] {
        let response = adapter.handle(frame.as_bytes()).unwrap();
        assert_eq!(response["error"]["code"], -32600);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn mcp_distinguishes_invalid_json_request_shape_and_absent_id() {
    let mut adapter = Adapter::new(CountBridge(Arc::new(AtomicUsize::new(0))));
    assert_eq!(adapter.handle(b"{").unwrap()["error"]["code"], -32700);
    for frame in [
        br#"{"jsonrpc":"2.0","id":1}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":true}"#,
    ] {
        assert_eq!(adapter.handle(frame).unwrap()["error"]["code"], -32600);
    }
    assert!(adapter
        .handle(br#"{"jsonrpc":"2.0","method":"ping"}"#)
        .is_none());
    let deeply_nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
    assert!(adapter
        .handle(deeply_nested.as_bytes())
        .unwrap()
        .get("error")
        .is_some());
}

#[test]
fn mcp_frame_byte_boundary_includes_the_required_newline() {
    for extra in [0, 1] {
        let mut input = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec();
        input.resize(protocol::MAX_FRAME_BYTES - 1 + extra, b' ');
        input.push(b'\n');
        let mut output = Vec::new();
        mcp::serve(
            Cursor::new(input),
            &mut output,
            CountBridge(Arc::new(AtomicUsize::new(0))),
        )
        .unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response.get("error").is_some(), extra == 1);
    }
}
