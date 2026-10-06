//! Strict JSON-lines protocol used by the synthetic harness and future thin IPC clients.
use crate::{AgentClient, ErrorCode, PrepareInput};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_CONNECTION_FRAMES: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Action {
    DiscoverOperations,
    PrepareOperation(PrepareInput),
    RequestApproval(Handle),
    InvokeApproved(Handle),
    GetRunStatus(Handle),
    Cancel(Handle),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handle {
    pub prepared_request_id: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub result: Option<Value>,
    pub error: Option<ErrorCode>,
}
impl Response {
    fn success(result: impl Serialize) -> Self {
        match serde_json::to_value(result) {
            Ok(result) => Self {
                version: PROTOCOL_VERSION,
                result: Some(result),
                error: None,
            },
            Err(_) => Self::failure(ErrorCode::BrokerUnavailable),
        }
    }
    pub fn failure(error: ErrorCode) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            result: None,
            error: Some(error),
        }
    }
}

pub fn handle(client: &AgentClient, frame: &[u8]) -> Response {
    if frame.len() > MAX_FRAME_BYTES {
        return Response::failure(ErrorCode::InvalidRequest);
    }
    let envelope: Envelope = match serde_json::from_slice(frame) {
        Ok(value) => value,
        Err(_) => return Response::failure(ErrorCode::InvalidRequest),
    };
    if envelope.version != PROTOCOL_VERSION {
        return Response::failure(ErrorCode::UnsupportedVersion);
    }
    match envelope.action {
        Action::DiscoverOperations => Response::success(client.discover_operations()),
        Action::PrepareOperation(input) => wrap(client.prepare(input)),
        Action::RequestApproval(handle) => {
            wrap(client.request_approval(handle.prepared_request_id))
        }
        Action::InvokeApproved(handle) => wrap(client.invoke(handle.prepared_request_id)),
        Action::GetRunStatus(handle) => wrap(client.status(handle.prepared_request_id)),
        Action::Cancel(handle) => wrap(client.cancel(handle.prepared_request_id)),
    }
}
fn wrap(result: Result<crate::RunView, ErrorCode>) -> Response {
    match result {
        Ok(value) => Response::success(value),
        Err(error) => Response::failure(error),
    }
}

/// Read complete LF-delimited frames, including LF in the byte limit.
/// Close after an oversized or unterminated frame without executing it.
pub fn serve(input: impl BufRead, output: impl Write, client: &AgentClient) -> std::io::Result<()> {
    serve_frames(input, output, client, |_| {})
}

pub(crate) fn serve_frames<R: BufRead>(
    mut input: R,
    mut output: impl Write,
    client: &AgentClient,
    mut begin_frame: impl FnMut(&mut R),
) -> std::io::Result<()> {
    for _ in 0..MAX_CONNECTION_FRAMES {
        begin_frame(&mut input);
        let mut frame = Vec::new();
        let count = std::io::Read::take(&mut input, (MAX_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            return Ok(());
        }
        if frame.len() > MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
            serde_json::to_writer(&mut output, &Response::failure(ErrorCode::InvalidRequest))?;
            output.write_all(b"\n")?;
            output.flush()?;
            return Ok(());
        }
        frame.pop();
        serde_json::to_writer(&mut output, &handle(client, &frame))?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    serde_json::to_writer(&mut output, &Response::failure(ErrorCode::CapacityExceeded))?;
    output.write_all(b"\n")?;
    output.flush()
}
