//! Policy-free stdio MCP adapter over the broker operation protocol.
use crate::{protocol, ErrorCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

pub const MCP_VERSION: &str = "2025-11-25";
pub trait Bridge {
    fn exchange(&mut self, request: &Value) -> protocol::Response;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rpc {
    jsonrpc: String,
    #[serde(default, deserialize_with = "present_id")]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Initialize {
    protocol_version: String,
    capabilities: Value,
    client_info: ClientInfo,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInfo {
    name: String,
    version: String,
    #[serde(default)]
    title: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    arguments: Value,
}

fn present_id<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(de).map(Some)
}

// serde_json::Value normally keeps the last duplicate member. Reject ambiguous
// objects before mapping tool arguments into the authoritative typed protocol.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON with unique object members")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| UniqueJson(Value::Number(v)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                    let UniqueJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        de.deserialize_any(Visitor)
    }
}

fn rpc_error(id: Value, code: i32, message: &'static str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn handle_schema() -> Value {
    json!({"type":"object","properties":{"prepared_request_id":{"type":"integer","minimum":1}},"required":["prepared_request_id"],"additionalProperties":false})
}
fn tools() -> Value {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    json!({"tools":[
        {"name":"discover_operations","description":"Unverified synthetic catalog; no approval assertion.","inputSchema":empty},
        {"name":"prepare_operation","description":"Resolve a bounded synthetic issue-status request.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$"},"profile_id":{"type":"string","enum":["issue-status"]},"parameters":{"type":"object","properties":{"repository_id":{"type":"integer","minimum":1},"issue_number":{"type":"integer","minimum":1}},"required":["repository_id","issue_number"],"additionalProperties":false}},"required":["request_id","profile_id","parameters"],"additionalProperties":false}},
        {"name":"request_approval","description":"Queue a private decision. This never grants authority.","inputSchema":handle_schema()},
        {"name":"invoke_approved","description":"Invoke only broker-authorized synthetic operations.","inputSchema":handle_schema()},
        {"name":"get_run_status","description":"Read this session's status; polling does not refresh authority.","inputSchema":handle_schema()},
        {"name":"cancel","description":"Prevent an undispatched request; cannot retract a dispatched effect.","inputSchema":handle_schema()}
    ]})
}

pub struct Adapter<B> {
    bridge: B,
    initialized: bool,
}
impl<B: Bridge> Adapter<B> {
    pub fn new(bridge: B) -> Self {
        Self {
            bridge,
            initialized: false,
        }
    }
    pub fn handle(&mut self, frame: &[u8]) -> Option<Value> {
        if frame.len() > protocol::MAX_FRAME_BYTES {
            return Some(rpc_error(Value::Null, -32600, "invalid_request"));
        }
        let UniqueJson(value) = match serde_json::from_slice::<UniqueJson>(frame) {
            Ok(value) => value,
            Err(error) => {
                return Some(rpc_error(
                    Value::Null,
                    if error.is_syntax() || error.is_eof() {
                        -32700
                    } else {
                        -32600
                    },
                    "invalid_request",
                ))
            }
        };
        let rpc: Rpc = match serde_json::from_value(value) {
            Ok(rpc) => rpc,
            Err(_) => return Some(rpc_error(Value::Null, -32600, "invalid_request")),
        };
        let id = rpc.id.clone().unwrap_or(Value::Null);
        if rpc.jsonrpc != "2.0"
            || rpc
                .id
                .as_ref()
                .is_some_and(|id| !id.is_string() && !id.is_i64() && !id.is_u64())
        {
            return Some(rpc_error(Value::Null, -32600, "invalid_request"));
        }
        // Notifications cannot execute tools or approval controls.
        rpc.id.as_ref()?;
        match rpc.method.as_str() {
            "initialize" if !self.initialized => {
                let params: Initialize =
                    match serde_json::from_value(rpc.params.unwrap_or(Value::Null)) {
                        Ok(value) => value,
                        Err(_) => return Some(rpc_error(id, -32602, "invalid_request")),
                    };
                if params.protocol_version != MCP_VERSION
                    || !params.capabilities.is_object()
                    || params.client_info.name.len() > 128
                    || params.client_info.version.len() > 64
                    || params.client_info.title.is_some_and(|s| s.len() > 128)
                {
                    return Some(rpc_error(id, -32602, "unsupported_version"));
                }
                // clientInfo is display metadata, never principal/session authority.
                self.initialized = true;
                Some(rpc_result(
                    id,
                    json!({"protocolVersion":MCP_VERSION,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"aegis-experimental","version":env!("CARGO_PKG_VERSION")},"instructions":"Synthetic-only. Private human approval happens in the foreground broker; never provide credentials here."}),
                ))
            }
            "ping" => Some(rpc_result(id, json!({}))),
            _ if !self.initialized => Some(rpc_error(id, -32000, "interaction_required")),
            "tools/list" => {
                if rpc.params.as_ref().is_some_and(|v| v != &json!({})) {
                    return Some(rpc_error(id, -32602, "invalid_request"));
                }
                Some(rpc_result(id, tools()))
            }
            "tools/call" => {
                let call: Call = match serde_json::from_value(rpc.params.unwrap_or(Value::Null)) {
                    Ok(call) => call,
                    Err(_) => return Some(rpc_error(id, -32602, "invalid_request")),
                };
                let method = match call.name.as_str() {
                    "discover_operations" => "discover_operations",
                    "prepare_operation" => "prepare_operation",
                    "request_approval" => "request_approval",
                    "invoke_approved" => "invoke_approved",
                    "get_run_status" => "get_run_status",
                    "cancel" => "cancel",
                    _ => return Some(rpc_error(id, -32602, "scope_denied")),
                };
                let mut action = json!({"method":method});
                if method == "discover_operations" {
                    if call.arguments != json!({}) {
                        return Some(rpc_error(id, -32602, "invalid_request"));
                    }
                } else {
                    action["params"] = call.arguments;
                }
                let request = json!({"version":protocol::PROTOCOL_VERSION,"action":action});
                // Validate the mapping before IPC, but broker remains the authority.
                if serde_json::from_value::<protocol::Envelope>(request.clone()).is_err() {
                    return Some(rpc_error(id, -32602, "invalid_request"));
                }
                let response = self.bridge.exchange(&request);
                let is_error = response.error.is_some()
                    || response.result.as_ref().is_some_and(|result| {
                        result.get("error").is_some_and(|error| !error.is_null())
                    });
                let serialized = serde_json::to_string(&response)
                    .unwrap_or_else(|_| "{\"error\":\"broker_unavailable\"}".into());
                Some(rpc_result(
                    id,
                    json!({"content":[{"type":"text","text":serialized}],"isError":is_error}),
                ))
            }
            _ => Some(rpc_error(id, -32601, "unsupported_method")),
        }
    }
}

/// Stdio is host-visible: protocol messages only; no credential elicitation or logs.
pub fn serve(
    input: impl BufRead,
    mut output: impl Write,
    bridge: impl Bridge,
) -> std::io::Result<()> {
    let mut input = input;
    let mut adapter = Adapter::new(bridge);
    for _ in 0..protocol::MAX_CONNECTION_FRAMES {
        let mut frame = Vec::new();
        let count = std::io::Read::take(&mut input, (protocol::MAX_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            return Ok(());
        }
        let oversized = frame.len() > protocol::MAX_FRAME_BYTES;
        if oversized || frame.last() != Some(&b'\n') {
            serde_json::to_writer(
                &mut output,
                &rpc_error(Value::Null, -32600, "invalid_request"),
            )?;
            output.write_all(b"\n")?;
            output.flush()?;
            return Ok(());
        }
        frame.pop();
        if let Some(response) = adapter.handle(&frame) {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    // A bounded client must start another connection instead of unbounded processing.
    Ok(())
}

/// An unavailable private workflow is a deterministic refusal, never a chat password prompt.
pub struct UnavailableBridge;
impl Bridge for UnavailableBridge {
    fn exchange(&mut self, _: &Value) -> protocol::Response {
        protocol::Response::failure(ErrorCode::InteractionRequired)
    }
}
