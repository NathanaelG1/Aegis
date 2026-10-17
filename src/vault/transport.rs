//! Bounded, in-memory transport contract for the fixed synthetic vault fixture.
//!
//! Only the dummy drill and its safe report are public. Bindings are host-created
//! fixture labels, not authenticated network peers or evidence of confidentiality.
//! No listener, general channel constructor, enrollment or secret-entry path exists.
//!
//! ```compile_fail
//! use aegis::vault::transport::AgentChannel;
//! ```
//! ```compile_fail
//! use aegis::vault::transport::AdminChannel;
//! ```
use super::{
    auth::Actors,
    crypto::PrivateBytes,
    protocol::{self, AdminEndpoint, AgentEndpoint, ProtocolResponse, SyntheticProtocol},
    store::Kit,
};
use crate::{
    ErrorCode, Lifecycle, ManualClock, OperationIntent, OperationPrepareInput, ProfileId, RequestId,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{self, Write},
    path::Path,
    sync::Arc,
};

const HEADER_BYTES: usize = 34;
const MAX_WIRE_BYTES: usize = protocol::MAX_FRAME_BYTES;
const MAX_BODY_BYTES: usize = MAX_WIRE_BYTES - HEADER_BYTES;
const REQUEST_MAGIC: [u8; 4] = *b"AVQ1";
const RESPONSE_MAGIC: [u8; 4] = *b"AVS1";

#[derive(Clone, Copy)]
struct Binding {
    role: u8,
    peer: u8,
    channel: [u8; 16],
}
impl Binding {
    fn fresh(role: u8, peer: u8) -> Result<Self, ErrorCode> {
        let mut channel = [0; 16];
        getrandom::getrandom(&mut channel).map_err(|_| ErrorCode::BrokerUnavailable)?;
        Ok(Self {
            role,
            peer,
            channel,
        })
    }
    fn header(self, magic: [u8; 4], sequence: u64, size: usize) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..4].copy_from_slice(&magic);
        header[4] = self.role;
        header[5] = self.peer;
        header[6..22].copy_from_slice(&self.channel);
        header[22..30].copy_from_slice(&sequence.to_be_bytes());
        header[30..].copy_from_slice(&(size as u32).to_be_bytes());
        header
    }
}

// Closed, payload-free failures. Any transport failure makes the channel terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Closed,
    InvalidHeader,
    BindingMismatch,
    InvalidSequence,
    FrameTooLarge,
    EmptyFrame,
    FrameLimit,
    Truncated,
    ResponseTooLarge,
}
struct Decoded {
    sequence: u64,
    body: PrivateBytes,
}
struct Progress<T> {
    consumed: usize,
    frame: Option<T>,
}
struct Decoder {
    binding: Binding,
    header: [u8; HEADER_BYTES],
    header_used: usize,
    body: PrivateBytes,
    body_size: Option<usize>,
    next_sequence: u64,
    frames: usize,
    closed: bool,
}
impl Decoder {
    fn new(binding: Binding) -> Self {
        Self {
            binding,
            header: [0; HEADER_BYTES],
            header_used: 0,
            body: PrivateBytes(Vec::new()),
            body_size: None,
            next_sequence: 0,
            frames: 0,
            closed: false,
        }
    }
    fn close(&mut self) {
        use zeroize::Zeroize;
        self.closed = true;
        self.header.zeroize();
        self.header_used = 0;
        self.body.0.zeroize();
        self.body_size = None;
    }
    fn finish(&mut self) -> Result<(), Failure> {
        let result = if self.closed {
            Err(Failure::Closed)
        } else if self.header_used != 0 {
            Err(Failure::Truncated)
        } else {
            Ok(())
        };
        self.close();
        result
    }
    // A call consumes at most one frame. Coalesced trailing bytes stay with the caller.
    fn receive(&mut self, input: &[u8]) -> Result<Progress<Decoded>, Failure> {
        let result = self.receive_inner(input);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn receive_inner(&mut self, input: &[u8]) -> Result<Progress<Decoded>, Failure> {
        if self.closed {
            return Err(Failure::Closed);
        }
        let head = (HEADER_BYTES - self.header_used).min(input.len());
        self.header[self.header_used..self.header_used + head].copy_from_slice(&input[..head]);
        self.header_used += head;
        if self.header_used != HEADER_BYTES {
            return Ok(Progress {
                consumed: head,
                frame: None,
            });
        }
        let size = match self.body_size {
            Some(size) => size,
            None => {
                if self.header[..4] != REQUEST_MAGIC {
                    return Err(Failure::InvalidHeader);
                }
                if self.header[4] != self.binding.role
                    || self.header[5] != self.binding.peer
                    || self.header[6..22] != self.binding.channel
                {
                    return Err(Failure::BindingMismatch);
                }
                let mut sequence = [0; 8];
                sequence.copy_from_slice(&self.header[22..30]);
                if u64::from_be_bytes(sequence) != self.next_sequence
                    || self.next_sequence.checked_add(1).is_none()
                {
                    return Err(Failure::InvalidSequence);
                }
                if self.frames >= protocol::MAX_ENDPOINT_FRAMES {
                    return Err(Failure::FrameLimit);
                }
                let mut size = [0; 4];
                size.copy_from_slice(&self.header[30..]);
                let size = u32::from_be_bytes(size) as usize;
                if size > MAX_BODY_BYTES {
                    return Err(Failure::FrameTooLarge);
                }
                if size == 0 {
                    return Err(Failure::EmptyFrame);
                }
                // No body allocation occurs until all header checks have passed.
                self.body = PrivateBytes(Vec::with_capacity(size));
                self.body_size = Some(size);
                size
            }
        };
        let bytes = (size - self.body.0.len()).min(input.len() - head);
        self.body.0.extend_from_slice(&input[head..head + bytes]);
        let consumed = head + bytes;
        if self.body.0.len() != size {
            return Ok(Progress {
                consumed,
                frame: None,
            });
        }
        let frame = Decoded {
            sequence: self.next_sequence,
            body: PrivateBytes(std::mem::take(&mut self.body.0)),
        };
        self.next_sequence += 1;
        self.frames += 1;
        self.header.fill(0);
        self.header_used = 0;
        self.body_size = None;
        Ok(Progress {
            consumed,
            frame: Some(frame),
        })
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.close();
    }
}

// Sealed to this module. The endpoint type fixes the role; no request routes it.
trait Endpoint {
    const ROLE: u8;
    const PEER: u8;
    fn handle(&self, body: &[u8]) -> ProtocolResponse;
}
impl Endpoint for AgentEndpoint {
    const ROLE: u8 = 1;
    const PEER: u8 = 1;
    fn handle(&self, body: &[u8]) -> ProtocolResponse {
        self.handle(body)
    }
}
impl Endpoint for AdminEndpoint {
    const ROLE: u8 = 2;
    const PEER: u8 = 2;
    fn handle(&self, body: &[u8]) -> ProtocolResponse {
        self.handle(body)
    }
}
struct Connection<E> {
    endpoint: Option<E>,
    decoder: Decoder,
    transcript_contains_canary: bool,
}
struct AgentChannel(Connection<AgentEndpoint>);
struct AdminChannel(Connection<AdminEndpoint>);
impl<E: Endpoint> Connection<E> {
    fn new(endpoint: E) -> Result<Self, ErrorCode> {
        Ok(Self {
            endpoint: Some(endpoint),
            decoder: Decoder::new(Binding::fresh(E::ROLE, E::PEER)?),
            transcript_contains_canary: false,
        })
    }
    fn close(&mut self) {
        self.decoder.close();
        // Destroy this connection's authenticated capability; never recycle it.
        self.endpoint.take();
    }
    fn finish(&mut self) -> Result<(), Failure> {
        let result = self.decoder.finish();
        self.endpoint.take();
        result
    }
    fn receive(&mut self, input: &[u8]) -> Result<Progress<PrivateBytes>, Failure> {
        let result = self.receive_inner(input);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn receive_inner(&mut self, input: &[u8]) -> Result<Progress<PrivateBytes>, Failure> {
        let endpoint = self.endpoint.as_ref().ok_or(Failure::Closed)?;
        let progress = self.decoder.receive(input)?;
        let frame = match progress.frame {
            None => None,
            Some(decoded) => {
                let response = endpoint.handle(&decoded.body.0);
                let body = bounded_json(&response).map_err(|_| Failure::ResponseTooLarge)?;
                // Fixed-fixture observation only, not a general output-redaction policy.
                self.transcript_contains_canary |=
                    [super::store::CANARY_ONE, super::store::CANARY_TWO]
                        .iter()
                        .any(|canary| {
                            body.0
                                .windows(canary.len())
                                .any(|part| part == canary.as_bytes())
                        });
                Some(
                    wire(
                        self.decoder.binding,
                        RESPONSE_MAGIC,
                        decoded.sequence,
                        &body.0,
                    )
                    .map_err(|_| Failure::ResponseTooLarge)?,
                )
            }
        };
        Ok(Progress {
            consumed: progress.consumed,
            frame,
        })
    }
}
fn bind(protocol: SyntheticProtocol) -> Result<(AgentChannel, AdminChannel), ErrorCode> {
    Ok((
        AgentChannel(Connection::new(protocol.agent)?),
        AdminChannel(Connection::new(protocol.admin)?),
    ))
}

// Refuse an oversized serialized response before extending its bounded buffer.
struct BoundedBody(PrivateBytes);
impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BODY_BYTES - self.0 .0.len() {
            return Err(io::Error::other("synthetic frame limit"));
        }
        self.0 .0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize) -> Result<PrivateBytes, ErrorCode> {
    let mut body = BoundedBody(PrivateBytes(Vec::with_capacity(MAX_BODY_BYTES)));
    serde_json::to_writer(&mut body, value).map_err(|_| ErrorCode::CapacityExceeded)?;
    Ok(body.0)
}
fn wire(
    binding: Binding,
    magic: [u8; 4],
    sequence: u64,
    body: &[u8],
) -> Result<PrivateBytes, ErrorCode> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut frame = Vec::with_capacity(HEADER_BYTES + body.len());
    frame.extend_from_slice(&binding.header(magic, sequence, body.len()));
    frame.extend_from_slice(body);
    Ok(PrivateBytes(frame))
}

#[derive(Serialize)]
struct Action<'a, T> {
    method: &'a str,
    params: T,
}
#[derive(Serialize)]
struct Request<'a, T> {
    protocol: &'static str,
    version: u32,
    action: Action<'a, T>,
}
#[derive(Serialize)]
struct Proof<'a> {
    assertion: &'a str,
}
#[derive(Serialize)]
struct Handle {
    prepared_request_id: u64,
}
#[derive(Serialize)]
struct Empty {}
fn request(method: &str, params: impl Serialize) -> Result<PrivateBytes, ErrorCode> {
    bounded_json(&Request {
        protocol: protocol::PROTOCOL,
        version: protocol::VERSION,
        action: Action { method, params },
    })
}
// Trusted dummy actor only, deliberately private: no arbitrary channel/input API.
fn exchange<E: Endpoint>(
    connection: &mut Connection<E>,
    method: &str,
    params: impl Serialize,
) -> Result<serde_json::Value, ErrorCode> {
    let body = request(method, params)?;
    let sequence = connection.decoder.next_sequence;
    let frame = wire(connection.decoder.binding, REQUEST_MAGIC, sequence, &body.0)?;
    let mut response = None;
    for fragment in frame.0.chunks(7) {
        let progress = connection
            .receive(fragment)
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if progress.consumed != fragment.len() || response.is_some() {
            return Err(ErrorCode::BrokerUnavailable);
        }
        response = progress.frame;
    }
    let response = response.ok_or(ErrorCode::BrokerUnavailable)?;
    if response.0.len() < HEADER_BYTES
        || response.0[..HEADER_BYTES]
            != connection.decoder.binding.header(
                RESPONSE_MAGIC,
                sequence,
                response.0.len() - HEADER_BYTES,
            )
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    serde_json::from_slice(&response.0[HEADER_BYTES..]).map_err(|_| ErrorCode::BrokerUnavailable)
}
fn value<T: DeserializeOwned>(reply: serde_json::Value, kind: &str) -> Result<T, ErrorCode> {
    if reply["error"].is_null() && reply["result"]["kind"] == kind {
        serde_json::from_value(reply["result"]["value"].clone())
            .map_err(|_| ErrorCode::BrokerUnavailable)
    } else {
        Err(ErrorCode::BrokerUnavailable)
    }
}
fn is_kind(reply: &serde_json::Value, kind: &str) -> bool {
    reply["error"].is_null() && reply["result"]["kind"] == kind
}
fn is_error(reply: &serde_json::Value, error: ErrorCode) -> bool {
    reply["result"].is_null()
        && matches!(serde_json::from_value::<ErrorCode>(reply["error"].clone()), Ok(found) if found == error)
}
fn sign(
    actors: &Actors,
    challenge: &protocol::ProofChallenge,
) -> Result<super::crypto::Signed, ErrorCode> {
    actors.sign(challenge)
}
fn proof(signed: &super::crypto::Signed) -> Result<Proof<'_>, ErrorCode> {
    Ok(Proof {
        assertion: std::str::from_utf8(signed.bytes()).map_err(|_| ErrorCode::BrokerUnavailable)?,
    })
}

/// Safe evidence from a fixed in-memory dummy workflow, never a transport attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticTransportReport {
    pub synthetic_only: bool,
    pub maximum_frame_bytes: usize,
    pub maximum_frames_per_channel: usize,
    pub partial_reads_verified: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub wrong_role_proof_denied: bool,
    pub agent_admin_method_denied: bool,
    pub completed_deliveries: usize,
    pub consumed_uses: usize,
    pub recipient_generation: u64,
    pub transport_replay_denied: bool,
    pub closed_channel_denied: bool,
    pub agent_transcript_contains_canary: bool,
    pub independent_peer_authentication_verified: bool,
    pub transport_confidentiality_verified: bool,
    pub independent_human_presence_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Create only new fixed canary paths and disposable fixture keys, run one reviewed
/// delivery through separate framed channels, then revoke and return safe evidence.
/// This does not open a socket, accept secret values, or expose authenticated handles.
pub fn run_synthetic_transport_drill(
    root: &Path,
    kit: &Path,
    recipient: &Path,
) -> Result<SyntheticTransportReport, ErrorCode> {
    let protocol =
        SyntheticProtocol::create(root, kit, recipient, Arc::new(ManualClock::default()))?;
    let actors = Kit::open(kit)?;
    let (mut agent, mut admin) = bind(protocol)?;
    let unauthenticated_agent_denied = is_error(
        &exchange(&mut agent.0, "discover_operations", Empty {})?,
        ErrorCode::AuthenticationRequired,
    );
    let unauthenticated_admin_denied = is_error(
        &exchange(&mut admin.0, "revoke_challenge", Empty {})?,
        ErrorCode::AuthenticationRequired,
    );
    let challenge: protocol::ProofChallenge = value(
        exchange(&mut agent.0, "connect_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    let wrong_role_proof_denied = is_error(
        &exchange(&mut admin.0, "connect", proof(&signed)?)?,
        ErrorCode::AuthenticationRequired,
    );
    if !is_kind(
        &exchange(&mut agent.0, "connect", proof(&signed)?)?,
        "connected",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(&mut admin.0, "connect_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    if !is_kind(
        &exchange(&mut admin.0, "connect", proof(&signed)?)?,
        "connected",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let agent_admin_method_denied = is_error(
        &exchange(&mut agent.0, "revoke_challenge", Empty {})?,
        ErrorCode::InvalidRequest,
    );
    let prepared: crate::OperationRunView = value(
        exchange(
            &mut agent.0,
            "prepare_operation",
            OperationPrepareInput {
                request_id: RequestId::new("transport-canary-one")?,
                profile_id: ProfileId::new("vault-delivery")?,
                operation: OperationIntent::Delivery(super::DeliveryParameters::fixture(1)),
            },
        )?,
        "run",
    )?;
    let id = prepared.prepared_request_id;
    let awaiting: crate::OperationRunView = value(
        exchange(
            &mut agent.0,
            "request_approval",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "run",
    )?;
    if awaiting.state != Lifecycle::AwaitingApproval {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let expected: protocol::ReviewPlan = value(
        exchange(
            &mut admin.0,
            "inspect_review",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "review",
    )?;
    let challenge = value(
        exchange(&mut admin.0, "approval_challenge", &expected)?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    #[derive(Serialize)]
    struct Approval<'a> {
        expected: &'a protocol::ReviewPlan,
        proof: Proof<'a>,
    }
    let approved: crate::OperationRunView = value(
        exchange(
            &mut admin.0,
            "approve",
            Approval {
                expected: &expected,
                proof: proof(&signed)?,
            },
        )?,
        "run",
    )?;
    if approved.state != Lifecycle::Approved {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(
            &mut agent.0,
            "invocation_challenge",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    #[derive(Serialize)]
    struct Invocation<'a> {
        prepared_request_id: u64,
        proof: Proof<'a>,
    }
    let response = exchange(
        &mut agent.0,
        "invoke_approved",
        Invocation {
            prepared_request_id: id,
            proof: proof(&signed)?,
        },
    )?;
    let run: crate::OperationRunView = value(response, "run")?;
    if run.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let replay =
        agent
            .0
            .decoder
            .binding
            .header(REQUEST_MAGIC, agent.0.decoder.next_sequence - 1, 1);
    let transport_replay_denied = matches!(agent.0.receive(&replay), Err(Failure::InvalidSequence));
    let challenge = value(
        exchange(&mut admin.0, "revoke_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    if !is_kind(
        &exchange(&mut admin.0, "revoke", proof(&signed)?)?,
        "revoked",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    admin.0.finish().map_err(|_| ErrorCode::BrokerUnavailable)?;
    let closed_channel_denied = matches!(admin.0.receive(&[]), Err(Failure::Closed))
        && matches!(agent.0.receive(&[]), Err(Failure::Closed));
    let agent_transcript_contains_canary = agent.0.transcript_contains_canary;
    drop((agent, admin, actors));
    let inspected = super::inspect_synthetic_vault(root, kit, recipient)?;
    if !(unauthenticated_agent_denied
        && unauthenticated_admin_denied
        && wrong_role_proof_denied
        && agent_admin_method_denied
        && transport_replay_denied
        && closed_channel_denied
        && inspected.consumed_uses == 1
        && inspected.recipient_generation == 1
        && inspected.revoked
        && !agent_transcript_contains_canary)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(SyntheticTransportReport {
        synthetic_only: true,
        maximum_frame_bytes: MAX_WIRE_BYTES,
        maximum_frames_per_channel: protocol::MAX_ENDPOINT_FRAMES,
        partial_reads_verified: true,
        unauthenticated_agent_denied,
        unauthenticated_admin_denied,
        wrong_role_proof_denied,
        agent_admin_method_denied,
        completed_deliveries: 1,
        consumed_uses: inspected.consumed_uses,
        recipient_generation: inspected.recipient_generation,
        transport_replay_denied,
        closed_channel_denied,
        agent_transcript_contains_canary,
        independent_peer_authentication_verified: false,
        transport_confidentiality_verified: false,
        independent_human_presence_verified: false,
        ready_for_real_keys: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ProtocolResult;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn binding() -> Binding {
        Binding {
            role: 1,
            peer: 1,
            channel: [9; 16],
        }
    }
    fn encoded(sequence: u64, body: &[u8]) -> PrivateBytes {
        wire(binding(), REQUEST_MAGIC, sequence, body).unwrap()
    }
    fn failed<T>(result: Result<T, Failure>, expected: Failure) {
        assert!(matches!(result, Err(actual) if actual == expected));
    }

    #[test]
    fn every_split_and_one_byte_fragments_preserve_one_frame() {
        let frame = encoded(0, b"bounded dummy payload");
        for split in 0..=frame.0.len() {
            let mut decoder = Decoder::new(binding());
            let first = decoder.receive(&frame.0[..split]).unwrap();
            assert_eq!(first.consumed, split);
            let second = decoder.receive(&frame.0[split..]).unwrap();
            assert_eq!(second.consumed, frame.0.len() - split);
            let decoded = first.frame.or(second.frame).unwrap();
            assert_eq!(decoded.sequence, 0);
            assert_eq!(decoded.body.0, b"bounded dummy payload");
            assert_eq!(decoder.frames, 1);
            assert_eq!(decoder.next_sequence, 1);
            assert!(decoder.finish().is_ok());
        }
        let mut decoder = Decoder::new(binding());
        for (index, byte) in frame.0.iter().enumerate() {
            let progress = decoder.receive(std::slice::from_ref(byte)).unwrap();
            assert_eq!(progress.consumed, 1);
            assert_eq!(progress.frame.is_some(), index + 1 == frame.0.len());
        }
    }

    #[test]
    fn coalesced_frames_return_exact_consumption_and_no_hidden_queue() {
        let first = encoded(0, b"first");
        let second = encoded(1, b"second");
        let both = [first.0.as_slice(), second.0.as_slice()].concat();
        let mut decoder = Decoder::new(binding());
        let progress = decoder.receive(&both).unwrap();
        assert_eq!(progress.consumed, first.0.len());
        assert_eq!(progress.frame.unwrap().body.0, b"first");
        let next = decoder.receive(&both[progress.consumed..]).unwrap();
        assert_eq!(next.consumed, second.0.len());
        assert_eq!(next.frame.unwrap().body.0, b"second");
        assert!(decoder.body.0.is_empty());
    }

    #[test]
    fn complete_wire_cap_includes_header_and_rejects_before_body_allocation() {
        let frame = encoded(0, &vec![b'x'; MAX_BODY_BYTES]);
        assert_eq!(frame.0.len(), 16 * 1024);
        let mut decoder = Decoder::new(binding());
        assert_eq!(
            decoder
                .receive(&frame.0)
                .unwrap()
                .frame
                .unwrap()
                .body
                .0
                .len(),
            MAX_BODY_BYTES
        );
        for size in [MAX_BODY_BYTES + 1, u32::MAX as usize] {
            let mut decoder = Decoder::new(binding());
            let header = binding().header(REQUEST_MAGIC, 0, size);
            failed(decoder.receive(&header), Failure::FrameTooLarge);
            assert_eq!(decoder.body.0.capacity(), 0);
            failed(decoder.receive(&frame.0), Failure::Closed);
        }
        let mut decoder = Decoder::new(binding());
        failed(
            decoder.receive(&binding().header(REQUEST_MAGIC, 0, 0)),
            Failure::EmptyFrame,
        );
    }

    #[test]
    fn immutable_role_peer_channel_and_direction_are_checked() {
        for offset in [4, 5, 6, 21] {
            let mut frame = encoded(0, b"body");
            frame.0[offset] ^= 1;
            let mut decoder = Decoder::new(binding());
            failed(decoder.receive(&frame.0), Failure::BindingMismatch);
            assert_eq!(decoder.body.0.capacity(), 0);
            failed(decoder.receive(&encoded(0, b"body").0), Failure::Closed);
        }
        for magic in [RESPONSE_MAGIC, *b"AVQ2", [0; 4]] {
            let mut decoder = Decoder::new(binding());
            failed(
                decoder.receive(&binding().header(magic, 0, 1)),
                Failure::InvalidHeader,
            );
        }
    }

    #[test]
    fn replay_gap_and_sequence_exhaustion_close_without_another_frame() {
        let mut decoder = Decoder::new(binding());
        assert!(decoder
            .receive(&encoded(0, b"first").0)
            .unwrap()
            .frame
            .is_some());
        failed(
            decoder.receive(&encoded(0, b"replay").0),
            Failure::InvalidSequence,
        );
        assert_eq!(decoder.frames, 1);
        failed(decoder.receive(&encoded(1, b"next").0), Failure::Closed);
        let mut decoder = Decoder::new(binding());
        failed(
            decoder.receive(&encoded(1, b"gap").0),
            Failure::InvalidSequence,
        );
        let mut decoder = Decoder::new(binding());
        decoder.next_sequence = u64::MAX;
        failed(
            decoder.receive(&encoded(u64::MAX, b"overflow").0),
            Failure::InvalidSequence,
        );
        assert_eq!(decoder.frames, 0);
    }

    #[test]
    fn eof_at_every_partial_position_is_truncated_and_terminal() {
        let frame = encoded(0, b"payload");
        for size in 1..frame.0.len() {
            let mut decoder = Decoder::new(binding());
            assert!(decoder.receive(&frame.0[..size]).unwrap().frame.is_none());
            failed(decoder.finish(), Failure::Truncated);
            assert!(decoder.header.iter().all(|&byte| byte == 0));
            assert!(decoder.body.0.is_empty());
            failed(decoder.receive(&frame.0[size..]), Failure::Closed);
        }
        let mut decoder = Decoder::new(binding());
        assert_eq!(decoder.receive(&[]).unwrap().consumed, 0);
        assert!(!decoder.closed);
        assert!(decoder.finish().is_ok());
        failed(decoder.finish(), Failure::Closed);
    }

    #[test]
    fn frame_budget_is_bounded_without_sequence_wrap() {
        let mut decoder = Decoder::new(binding());
        for sequence in 0..protocol::MAX_ENDPOINT_FRAMES {
            assert!(decoder
                .receive(&encoded(sequence as u64, b"x").0)
                .unwrap()
                .frame
                .is_some());
        }
        failed(
            decoder.receive(&encoded(protocol::MAX_ENDPOINT_FRAMES as u64, b"x").0),
            Failure::FrameLimit,
        );
        assert_eq!(decoder.frames, protocol::MAX_ENDPOINT_FRAMES);
        failed(decoder.receive(&[]), Failure::Closed);
    }

    struct Probe {
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        oversized: bool,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Endpoint for Probe {
        const ROLE: u8 = 1;
        const PEER: u8 = 1;
        fn handle(&self, _body: &[u8]) -> ProtocolResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ProtocolResponse {
                protocol: protocol::PROTOCOL,
                version: protocol::VERSION,
                synthetic_only: true,
                result: self.oversized.then(|| {
                    ProtocolResult::Challenge(protocol::ProofChallenge {
                        nonce: "x".repeat(MAX_WIRE_BYTES),
                        epoch: String::new(),
                        purpose: protocol::ProofPurpose::Connect,
                        digest: String::new(),
                        issued: 0,
                        expires: 0,
                        issued_elapsed: 0,
                        expires_elapsed: 0,
                        enrollment_revision: 0,
                        acl_revision: 0,
                    })
                }),
                error: (!self.oversized).then_some(ErrorCode::InvalidRequest),
            }
        }
    }
    fn probe(oversized: bool) -> (Connection<Probe>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let channel = Connection::new(Probe {
            calls: calls.clone(),
            drops: drops.clone(),
            oversized,
        })
        .unwrap();
        (channel, calls, drops)
    }

    #[test]
    fn failed_binding_and_truncation_drop_the_owned_endpoint_before_dispatch() {
        let (mut connection, calls, drops) = probe(false);
        failed(
            connection.receive(&encoded(0, b"x").0),
            Failure::BindingMismatch,
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(connection.endpoint.is_none());
        let (mut connection, calls, drops) = probe(false);
        let frame = wire(connection.decoder.binding, REQUEST_MAGIC, 0, b"payload").unwrap();
        assert!(connection
            .receive(&frame.0[..HEADER_BYTES + 1])
            .unwrap()
            .frame
            .is_none());
        failed(connection.finish(), Failure::Truncated);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn malformed_protocol_attempts_still_consume_sequence_and_frame_budget() {
        let (mut connection, calls, _) = probe(false);
        for sequence in 0..protocol::MAX_ENDPOINT_FRAMES {
            let frame = wire(
                connection.decoder.binding,
                REQUEST_MAGIC,
                sequence as u64,
                b"not json",
            )
            .unwrap();
            let response = connection.receive(&frame.0).unwrap().frame.unwrap();
            assert!(response.0.len() <= MAX_WIRE_BYTES);
            assert_eq!(&response.0[..4], &RESPONSE_MAGIC);
            let reply: serde_json::Value =
                serde_json::from_slice(&response.0[HEADER_BYTES..]).unwrap();
            assert!(is_error(&reply, ErrorCode::InvalidRequest));
        }
        let frame = wire(
            connection.decoder.binding,
            REQUEST_MAGIC,
            protocol::MAX_ENDPOINT_FRAMES as u64,
            b"x",
        )
        .unwrap();
        failed(connection.receive(&frame.0), Failure::FrameLimit);
        assert_eq!(calls.load(Ordering::SeqCst), protocol::MAX_ENDPOINT_FRAMES);
    }

    #[test]
    fn oversized_response_closes_after_one_dispatch_without_retry_or_partial_release() {
        let (mut connection, calls, drops) = probe(true);
        let frame = wire(connection.decoder.binding, REQUEST_MAGIC, 0, b"dummy").unwrap();
        failed(connection.receive(&frame.0), Failure::ResponseTooLarge);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        failed(connection.receive(&frame.0), Failure::Closed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut writer = BoundedBody(PrivateBytes(Vec::with_capacity(MAX_BODY_BYTES)));
        writer.write_all(&vec![b'x'; MAX_BODY_BYTES]).unwrap();
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.0 .0.len(), MAX_BODY_BYTES);
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aegis-transport-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
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

    #[test]
    fn fixed_drill_authenticates_each_role_delivers_once_and_reports_only_safe_evidence() {
        let paths = Paths::new();
        let report =
            run_synthetic_transport_drill(&paths.root(), &paths.kit(), &paths.recipient()).unwrap();
        assert!(report.synthetic_only && report.partial_reads_verified);
        assert!(report.unauthenticated_agent_denied && report.unauthenticated_admin_denied);
        assert!(report.wrong_role_proof_denied && report.agent_admin_method_denied);
        assert!(report.transport_replay_denied && report.closed_channel_denied);
        assert_eq!(report.completed_deliveries, 1);
        assert_eq!(report.consumed_uses, 1);
        assert_eq!(report.recipient_generation, 1);
        assert!(!report.agent_transcript_contains_canary);
        assert!(!report.independent_peer_authentication_verified);
        assert!(!report.transport_confidentiality_verified);
        assert!(!report.independent_human_presence_verified);
        assert!(!report.ready_for_real_keys);
        for text in [
            serde_json::to_string(&report).unwrap(),
            format!("{report:?}"),
        ] {
            for marker in [
                super::super::store::CANARY_ONE,
                super::super::store::CANARY_TWO,
                "assertion",
                "AGE-SECRET-KEY",
                "PRIVATE KEY",
            ] {
                assert!(!text.contains(marker));
            }
        }
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
    }

    #[test]
    fn cold_channel_has_fresh_binding_and_no_inherited_authenticated_endpoint() {
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
        let (mut agent, mut admin) = bind(protocol).unwrap();
        let challenge = value(
            exchange(&mut agent.0, "connect_challenge", Empty {}).unwrap(),
            "challenge",
        )
        .unwrap();
        let signed = sign(&kit.actors, &challenge).unwrap();
        assert!(is_kind(
            &exchange(&mut agent.0, "connect", proof(&signed).unwrap()).unwrap(),
            "connected"
        ));
        let stale_binding = agent.0.decoder.binding;
        assert!(agent.0.finish().is_ok());
        assert!(agent.0.endpoint.is_none());
        assert!(admin.0.finish().is_ok());
        drop((agent, admin, kit));
        let protocol =
            SyntheticProtocol::open(&paths.root(), &paths.kit(), &paths.recipient(), 1, clock)
                .unwrap();
        let (mut agent, _admin) = bind(protocol).unwrap();
        assert_ne!(stale_binding.channel, agent.0.decoder.binding.channel);
        assert!(is_error(
            &exchange(&mut agent.0, "discover_operations", Empty {}).unwrap(),
            ErrorCode::AuthenticationRequired
        ));
        assert!(is_error(
            &exchange(&mut agent.0, "connect", proof(&signed).unwrap()).unwrap(),
            ErrorCode::AuthenticationRequired
        ));
        let stale = wire(
            stale_binding,
            REQUEST_MAGIC,
            agent.0.decoder.next_sequence,
            b"x",
        )
        .unwrap();
        failed(agent.0.receive(&stale.0), Failure::BindingMismatch);
        assert!(agent.0.endpoint.is_none());
    }
}
