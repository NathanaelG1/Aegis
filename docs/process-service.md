# Fixed-canary broker process service

**Implemented fixed-canary process drill. Live use remains NO-GO.**
This milestone gives the broker and its TLS peers separate process-owned socket
I/O. It retains the actual encrypted import, main policy engine, durable
reservation and fixed recipient handoff from the [composed canary](composed-canary-flow.md).
The starting source is PR #3 head `85516f171a89d325ecb98419aa2a43cf74c02c96`,
whose tree equals local `4f0b692`. Earlier test results do not cover new service code.

## Fixed process and descriptor ownership

The public drill accepts one new absolute disposable root. No caller
can supply a credential, private key, recipient executable, remote address,
listener configuration, deployment assertion or fault selector.

A fixed supervisor owns both broker and recipient child handles. It supplies
two inherited Unix socketpairs for agent and administrator TLS, with immutable
role bindings. A third fixed inherited connection carries the existing signed
age capsule and recipient response. The supervisor terminates and reaps both
children after normal or failed execution, including broker termination before
recipient exit. Its successful report follows actual wait/reap observations.
This does not guarantee cleanup if the supervisor itself is killed, or real-time
interruption of uninterruptible native calls.

The broker process owns the protocol, store and core runtime. Its runtime custody
contains its private material and public actor/recipient enrollment; it does not
load agent/admin signing keys, TLS client private keys or recipient private keys. Client-side fixture
drivers retain their own signer and TLS material outside the broker process.
Any bootstrap process that generates all disposable roles is explicitly distinct
from this runtime loading claim.

These remain same-UID processes on an agent-administered development machine.
Neither possession of inherited descriptors nor splitting loaded keys establishes
independent human presence, protected custody, immutable application code or
denial of memory, tracing, filesystem, backup or control-plane access.

## Transport and authority

Reuse the existing Rustls TLS 1.3 authentication, standard certificate validation,
exact peer pins, role-specific ALPN and exporter-bound framing. Each endpoint
owns only one TLS connection side. Actual UnixStream reads and writes enforce
absolute handshake/frame/channel limits, bounded work and bytes, and terminal
failure after partial I/O, EOF, timeout or malformed input. There is no automatic
retransmission and no accept loop; the two fixed inherited channels bound this
increment's admission.

The socket-driver limits are fixed:

| Boundary | Limit |
| --- | --- |
| Full handshake | 2 seconds |
| Server request read / response write | 1 second each |
| Client send plus response | 1 second total |
| Connection lifetime, starting before handshake | 30 seconds |
| Stream byte / processing-step budget | 256 KiB / 4,096 steps |
| Application body / directional frame count | 16 KiB / 32 frames |
| Encrypted TLS record read | 18 KiB |

Each I/O operation rechecks the absolute deadline after its final byte. Parsing
and authentication also check elapsed time; Interrupted retries cannot reset
the budget. Standard Rustls record parsing still validates the bounded bytes.
An authenticated TLS close at a frame boundary ends the server; partial frames,
EOF, timeout and protocol errors close the owned endpoint. Client factories keep
resumption disabled, so reopening requires a full handshake and new exporter.

The client deadline does not undo an operation already dispatched by the broker.
Server request and response I/O bounds are separate from native handler work;
lost replies must preserve retained completion or consumed uncertainty according
to the durable broker's existing outcome. No timeout grants permission to retry.

TLS role authentication does not replace the actor challenge/proof protocol.
Agent requests remain reference-only, admin approval remains bound to the exact
broker-resolved review, and the main broker remains the sole reservation and
revocation authority. The simulated client signing does not authenticate a person.

The broker consumes the actual bounded imported record. It preserves
the signed manifest, exact reference/version/recipient/generation binding and
existing durable receipt path. It does not regenerate a parallel canary store or
treat an import permit as delivery approval. After an ambiguous effect, it retains
the consumed reservation and uncertainty without automatic retry or refund.

Transport deadlines operate around system I/O and processing boundaries. They
do not promise interruption of every native cryptographic or filesystem call.
Actual trusted UTC, suspend behavior, persistent enrollment/renewal and a deployed
network service remain separate operational work.

## Run and inspect

```sh
cargo run --locked --offline --all-features --bin aegis-process-service -- /tmp/aegis-service-new
cargo run --locked --offline --all-features --bin aegis-process-service -- inspect /tmp/aegis-service-new
```

Only Unix with the vault feature is supported. The destination must be new and
absolute. The fixed binary dispatches its own child modes; it accepts no caller
executable or generic entry endpoint. Bootstrap creates disposable custody and
TLS role documents, then exits. During runtime the broker owns agent TLS on
inherited stdin, admin TLS on stdout and recipient IPC on stderr; these streams
are protocol descriptors, not terminal logs. The recipient is another direct
child owned by the same supervisor. Child commands clear their environment.
The two TLS client drivers hold their own actor/signing material in the parent.

Normal execution retains one completed delivery, one consumed use, generation
one and three remaining uses. A duplicate reuses the completed outcome. A fresh
broker requires new authentication before revocation; a further inspection
process validates the actual import, signed journal and recipient observation
without restoring authority. The observation frame is capped at 4 KiB, phase
supervision at 35 seconds, and recipient exchange at 5 seconds.

The durable policy/journal clock remains a fixed fixture ManualClock, matching
the existing closed drills. Resetting a per-process elapsed clock would regress
journal timestamps on cold restart; an elapsed-first-phase regression covers
that case. Socket I/O, transport lifetime and process supervision use actual
Instant deadlines. Neither choice supplies operational trusted UTC, reboot or
suspend policy. Runtime report fields that describe this prescribed construction
or scope are declarations; they are not independent host measurements.

## Functional evidence

The [verification record](verification.md) identifies source, commands, platform
and hosted-CI state. Report booleans cannot admit a deployment. The focused
process suite includes seven substantive scenarios plus its fixed child-dispatch
test helper. Two response-loss cases execute across the real process path:

- Dropping the broker-to-agent TLS reply after successful dispatch retains one
  completed use and recipient generation one. The client fails closed; a fresh
  connection is required and cold request-ID reuse is refused.
- Exiting the recipient after durable acceptance but before its acknowledgement
  retains one consumed OutcomeUnknown, generation one and three remaining uses.
  The duplicate reuses that result; a cold runtime refuses with reconciliation
  required, while read-only inspection remains available.

These fault selectors exist only in private test builds. Broker termination,
client closure and expired supervisor-deadline cases verify owned-child cleanup
before dispatch with zero use. The elapsed-first-phase case verifies subsequent
cold revocation. Standalone TLS tests cover stalled I/O and peer/role failures;
not every transport fault is injected through the full composed workflow.
Public CLI acceptance covers exact reports, ciphertext identity, missing/corrupt
retained artifacts, no-overwrite/refusal, unchanged inspection state, bounded
outputs and Linux process-cleanup observations. Marker checks do not establish
OS secrecy. The covered acceptance categories are:

- Actual import through TLS socket requests, durable reservation and recipient
  acknowledgement; correct retained counts, duplicate results and revoke
- Fresh-process inspection/reopen without restored sessions or approval
- Wrong-role/peer and malformed/partial I/O refusal, bounded stalled reads and
  writes, disconnect and process termination with no automatic redispatch
- Failure before reservation versus uncertain outcome after a possible effect,
  including which cases traverse the full composition
- No overwrite, fixed CLI/default-feature refusal, bounded safe outputs and
  cleanup of both owned children
- Original TLS, import, recipient and composed drills remain covered; all
  default/all-feature targets, doctests and quality checks remain enabled

## Remaining operational work

This service increment advances the socket driver and process ownership parts
of C3/C4 in the [operator plan](operator-live-trial-plan.md). It adds no listener,
host installation, access/security change, real credential, grant, provider call
or Sprite wake. `require_live_deployment()` remains an unconditional refusal.

Next source work still includes protected input/custody and an independent human
client, one actual application credential slot with handle-based publication,
an independent anchor/fencing backend, lifecycle/time/audit handling, trusted
deployment observations, and the live GitHub App/token/recipient composition.
Exact host, service identities, human client, custody backend, immutable
recipient installation and external recovery authority must be chosen before
their operational adapters and authorized canary installation can be finalized.

The previously stopped independent adversarial review remains unresolved.
These ordinary functional tests neither resume nor replace that assurance gate.
