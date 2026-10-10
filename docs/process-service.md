# Fixed-canary broker process service

**Implementation contract; integrated evidence pending. Live use remains NO-GO.**
This milestone gives the broker and its TLS peers separate process-owned socket
I/O. It retains the actual encrypted import, main policy engine, durable
reservation and fixed recipient handoff from the [composed canary](composed-canary-flow.md).
The starting source is PR #3 head `85516f171a89d325ecb98419aa2a43cf74c02c96`,
whose tree equals local `4f0b692`. Earlier test results do not cover new service code.

## Fixed process and descriptor ownership

The proposed public drill accepts one new absolute disposable root. No caller
can supply a credential, private key, recipient executable, remote address,
listener configuration, deployment assertion or fault selector.

A fixed supervisor owns both broker and recipient child handles. It supplies
two inherited Unix socketpairs for agent and administrator TLS, with immutable
role bindings. A third fixed inherited connection carries the existing signed
age capsule and recipient response. The supervisor must terminate and reap both
children after normal or failed execution, including broker termination before
recipient exit. The implementation must record actual cleanup observations.

The broker process owns the protocol, store and core runtime. Its runtime custody
contains its private material and public actor/recipient enrollment; it must not
load agent/admin signing keys or TLS client private keys. Client-side fixture
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
owns only one TLS connection side. Actual UnixStream reads and writes must enforce
absolute handshake/frame/channel limits, bounded work and bytes, and terminal
failure after partial I/O, EOF, timeout or malformed input. There is no automatic
retransmission and no accept loop; the two fixed inherited channels bound this
increment's admission.

TLS role authentication does not replace the actor challenge/proof protocol.
Agent requests remain reference-only, admin approval remains bound to the exact
broker-resolved review, and the main broker remains the sole reservation and
revocation authority. The simulated client signing does not authenticate a person.

The broker must consume the actual bounded imported record. It must preserve
the signed manifest, exact reference/version/recipient/generation binding and
existing durable receipt path. Do not regenerate a parallel canary store or
treat an import permit as delivery approval. After an ambiguous effect, retain
the consumed reservation and uncertainty; do not retry or refund automatically.

Transport deadlines operate around system I/O and processing boundaries. They
do not promise interruption of every native cryptographic or filesystem call.
Actual trusted UTC, suspend behavior, persistent enrollment/renewal and a deployed
network service remain separate operational work.

## Required functional evidence

The final record must identify source, commands, platform and exact hosted CI.
It must distinguish observed results from private fault models and fixed report
declarations. Report booleans cannot admit a deployment.

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
