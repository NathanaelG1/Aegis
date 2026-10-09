# Bounded synthetic vault transport contract

This optional Unix `vault-spike` fixture wraps the [separate protocol endpoints](vault-protocol.md) in private, owning agent and administrator channels. It exercises a bounded byte-stream contract in memory. It is **not an authenticated network transport** and starts no listener. The only added public entry point is `aegis::vault::transport::run_synthetic_transport_drill(root, kit, recipient)`, returning `SyntheticTransportReport`. Its three paths must be new synthetic fixture destinations, as required by the existing fixed-canary constructor. It accepts no secret value, real key, peer identity, route, deployment flag or caller-supplied clock.

There is no public channel constructor, connection handle, frame ingestion API or administrator routing selector. Existing `AgentEndpoint` and `AdminEndpoint` APIs are unchanged; embeddings that use those transport-neutral endpoints directly remain responsible for their own transport boundary. The wrapper does not make that existing API a protected deployment.

## Ownership and authority

The trusted fixture consumes one `SyntheticProtocol` and moves its two endpoints into different, non-`Clone` wrapper types. A private endpoint implementation fixes each wrapper's role and synthetic peer marker. Each connection receives a fresh random 128-bit channel identifier. These bindings are immutable for that connection, and request metadata is compared with them; it never selects a handler or changes its identity.

Peer marker `1` means the fixed simulated agent (`synthetic-vault-agent`); marker `2` means the fixed simulated administrator (`synthetic-vault-admin`). They are fixture labels. Knowing, copying or changing a marker/channel identifier is not authentication. There is no external handshake, certificate validation, proxy trust, OS identity assertion, channel MAC, encryption or cryptographic binding of endpoint proofs to this new frame header.

The existing signed endpoint challenges and purpose/audience/epoch checks remain mandatory. Frame acceptance does not create an agent or admin session. A valid agent proof cannot authenticate the admin endpoint, and an admin method in an agent JSON request cannot choose the administrator route. Approval and invocation still use the main broker's exact-review, independent-proof and reservation machinery; this module adds no policy engine, signing service or operation.

Every receive requires exclusive mutable access to its owning connection. Closing, EOF or a transport failure drops that connection's endpoint and any authenticated capability it owns. There is no reopen/reset method or endpoint extraction API. Closing one role does not independently revoke all broker authority or roll back an accepted operation. A fresh assembly needs fresh endpoint authentication and a new channel binding; the fixture drill's final administrative revocation uses the existing durable revoke path.

## Fixed framing

This is a distinct binary fixture framing layer around the existing `aegis.synthetic.vault.v1` JSON body. It does not change that protocol's version or the existing Unix JSON-line/MCP contracts.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | Request magic `AVQ1`, or response magic `AVS1` |
| 4 | 1 | Fixed role: agent `1`, administrator `2` |
| 5 | 1 | Fixed peer marker: agent `1`, administrator `2` |
| 6 | 16 | Connection's fresh channel identifier |
| 22 | 8 | Unsigned big-endian sequence number |
| 30 | 4 | Unsigned big-endian JSON body byte count |
| 34 | declared count | Exactly one protocol JSON body; no delimiter |

The **whole frame, including its 34-byte header, is at most 16,384 bytes**. The body therefore holds at most 16,350 bytes, slightly less than the direct endpoint's 16 KiB JSON limit. Empty bodies are refused. Unknown magic/version/direction, mismatched bindings, sequence errors, invalid lengths and the connection attempt limit are checked before body allocation or endpoint dispatch. A response uses the same binding and the accepted request sequence, with a distinct response magic to reject reflected response frames as requests.

Each channel starts at sequence zero and accepts exactly its next sequence. Gaps, reordering and repeated sequence numbers close it. Counter overflow is checked rather than wrapping. At most 256 complete request attempts are dispatched per channel; invalid protocol JSON and protocol denials count and advance the sequence too. The endpoint's own independent attempt limit remains in place. Transport replay rejection is a stream property, not a substitute for request-ID deduplication, signed one-use challenges or durable reservation. Rewriting an unauthenticated frame's header is outside the protection supplied by this fixture.

A receive call copies at most one bounded frame and returns the exact consumed-byte count and, only on completion, one response frame. Partial headers and bodies are retained in bounded private storage. If multiple frames arrive together, the caller retains the unconsumed tail and feeds it again; the connection creates no pending-response queue. An empty fragment means no progress, not EOF. Explicit EOF at a frame boundary closes cleanly; EOF during any header/body prefix is a terminal truncation error. No body is dispatched before all declared bytes arrive.

Response JSON is serialized through a limited writer that refuses to grow beyond the body cap. No partial response is exposed. If serialization exceeds the limit after endpoint dispatch, the channel closes and does not retry: an effect may already have occurred, and the underlying retained outcome/budget rules still apply. No send/write acknowledgement or network delivery guarantee is implemented.

Selected owned request/frame buffers are zeroized when released, including truncated buffers. This does not cover all parser/native/allocator copies, process inspection, swap or dumps. Fixture canary checks observe the two known dummy markers in serialized responses; they are not a generic secret detector or the authority for releasing output.

## Failure contract

Private transport errors contain only fixed variants, never input bytes, proofs, keys or provider text:

- `InvalidHeader`: unrecognized framing version/magic or reflected response direction
- `BindingMismatch`: role, peer marker or channel does not match the owning connection
- `InvalidSequence`: replay, gap, reordered frame or counter exhaustion
- `FrameTooLarge` / `EmptyFrame`: invalid declared request body bound
- `FrameLimit`: more than 256 dispatched request attempts
- `Truncated`: EOF before completion of a declared frame
- `ResponseTooLarge`: response serialization cannot fit the bounded frame
- `Closed`: further use after a terminal close, failure or EOF

All transport failures are sticky and discard the owning endpoint. A complete, well-framed JSON request rejected by the existing endpoint instead receives its normal fixed `ProtocolResponse.error`; it consumes a sequence/attempt but does not itself close the transport. The public drill maps an unexpected transport failure to `BrokerUnavailable`, while fixture-construction and existing store errors retain their existing `ErrorCode`. It returns no raw transport input or error detail.

## Fixed drill and functional evidence

The drill creates the existing disposable key/canary fixture, checks both unauthenticated roles, rejects an agent proof on the administrator endpoint, authenticates each role through its own framed connection, and rejects an admin-only method on the agent channel. It then prepares one fixed canary delivery, requests approval, obtains and signs the exact admin review, approves, signs the agent invocation, and completes one delivery. All fixture exchanges are split into seven-byte fragments. It rejects a repeated transport sequence, revokes through the administrator channel, closes both connections, and inspects the durable evidence. The report contains only fixed booleans and counters.

Twelve inline functional tests cover:

- Every split point and one-byte fragments; exact handling of coalesced frames
- Full 16 KiB wire boundary, over-limit and `u32::MAX` declared sizes, and empty bodies
- Immutable role, peer and channel checks; unknown framing versions and response reflection
- Replay, gaps, overflow rejection and 256-frame exhaustion
- EOF at every partial header/body position, sticky failure and owned-endpoint destruction
- Invalid-protocol attempts consuming sequence/budget; bounded error responses
- Response overflow after one dispatch, with no partial result or automatic retry
- Actual signed agent/admin authentication, exact reviewed dummy delivery, final revoke and safe report serialization
- Fresh cold-start channel identifiers, denied unauthenticated access, rejected prior proof, and no inherited endpoint capability

The focused suite was exercised on Linux x86_64 with the repository's pinned Rust 1.96.1 toolchain, unchanged `Cargo.lock`, and all optional features enabled. It adds no dependency. These are ordinary functional tests, not an independent security review. They do not satisfy the existing independent-review gate.

## Explicit limits and future transport gate

The report always sets independent peer authentication, transport confidentiality, independent human presence and real-key readiness to `false`. The fixed same-process actor kit still contains all disposable private signing material. There is no separate-OS-role boundary, protected human signer, real-key entry, provider connection, real-time receive deadline, socket backpressure, multi-client listener, operational enrollment, renewed session or production transport constructor. Finite fragment handling does not establish a wall-clock timeout: a future host must supply and test absolute read/write/lifetime bounds and bounded connection admission.

A future authenticated transport must independently establish and freeze enrolled peer identity and role, confidentiality/integrity, connection/channel proof binding, protected agent/admin routing, fresh-session lifecycle, trusted time and fail-closed I/O behavior. It must not promote these synthetic peer markers or random channel identifiers into proof of identity. The [operator-owned deployment ceremony](operator-owned-deployment.md), existing [protocol limitations](vault-protocol.md), and [verification record](verification.md) remain applicable. No result here opens the real-key deployment gate.
