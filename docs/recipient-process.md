# Synthetic recipient process

The optional Unix `vault-spike` increment runs the existing fixed-canary recipient in a separate child process. It exercises real process creation, inherited IPC, age decryption, signed durable receipt storage, cold reopen, rotation and revocation. It is still **UNISOLATED**, with no real credentials, live provider, independent human presence, protected custody or verified host boundary.

The [composed canary](composed-canary-flow.md) reuses this same process transport
and durable recipient for one actual imported record. Agent/admin TLS terminates
in its parent fixture; the signed age capsule and receipt cross the inherited
socketpair. The composed flow exercises version one only. The standalone
two-version rotation drill below remains a separate regression.

## Run the closed drill

Use three new paths beneath a temporary directory. The first path stores the dummy broker state, the second stores separate dummy custody roles, and the third stores the recipient's durable encrypted acceptance journal.

```sh
cargo run --locked --offline --features vault-spike --bin aegis-recipient-process -- \
  /tmp/aegis-process-example/vault \
  /tmp/aegis-process-example/custody \
  /tmp/aegis-process-example/recipient
```

Create `/tmp/aegis-process-example` first; the three child paths must not already exist. The equivalent example is `cargo run --locked --offline --features vault-spike --example recipient_process -- ...`. Without the feature, or outside Unix, the executable exits with a closed unsupported message.

The public library surface consists of the three-path fixed drill, its closed report, and `synthetic_child_entry()`. An embedding executable must call the dispatcher before parsing its ordinary arguments. No API accepts a secret value, process executable, shell command, environment, provider, URL, recipient key or deployment assurance. The child flag is internal fixture plumbing, not an operational secret-ingestion interface. All dummy inputs still undergo the existing exact capsule/payload validation.

## Custody and process ownership

A bootstrap child generates the separate disposable broker, recipient, agent and admin fixture documents. It never creates the all-role kit. The parent then opens only the broker role and, for the simulated approval ceremony, the separate actor roles. Runtime constructors retain only public actor verifiers. Recipient identity and receipt-signing keys are loaded by the recipient child. The child uses `Recipient::create/open/accept` and `accepted.jws`; no parallel storage implementation is introduced.

The launcher uses the current executable with a fixed dispatcher and no shell. Its environment is cleared, stderr is null, and an anonymous Unix socketpair is inherited as stdin and stdout. There is no named socket or network listener, address, discovery route or generic executable parameter. A session owns one child, serializes exchanges, and kills and reaps its child on drop or transport/authentication failure. Malformed child output cannot become a diagnostic carrying raw content.

The bootstrap child temporarily holds every dummy provisioning key. The parent still holds broker decryption and writer material, and its test ceremony holds simulated actor signers. Distinct processes do not constrain the privileges of their shared account.

## Signed protocol and bounds

Each frame has a four-byte big-endian length followed by at most 65,536 bytes. Zero length, oversized, truncated and malformed input fails closed. Typed JSON requests reject unknown fields. Responses are purpose-specific RS256 documents using the existing strict maintained JWS implementation.

Every status query uses a new random 32-byte nonce. A signed status binds that nonce, vault identity, fixed recipient/slot/configuration revision, recipient encryption key, broker writer verifier digest, generation and durable signed acknowledgements. The parent verifies the configured receipt key and checks every acknowledgement. Generations are restricted to the two supported canary versions; duplicate request IDs or generations are rejected. Reconciliation compares the verified receipt digest map with the broker journal before assembling the runtime. Missing successful broker receipts and unrelated recipient acceptances fail closed.

A delivery exchanges the exact existing writer-signed, age-encrypted capsule. Its signed response binds a fresh nonce, vault and capsule digest, with exactly one closed result: acknowledged, rejected or unknown. An acknowledged response includes the existing recipient acknowledgement. The durable broker independently verifies its signature, request, exact recipient/version/generation and capsule digest before reporting success. Only an authenticated, structurally valid rejection is treated as a known rejection.

The parent uses a 30-second absolute bootstrap read deadline and a five-second absolute deadline covering the full request write plus response read for each exchange. It recomputes the remaining duration before each I/O call, so partial progress cannot reset the deadline. Each session allows at most 128 exchanges. A bounded frame is allocated only after validating its length. The child has the same frame and exchange limits; the parent owns its execution lifetime and terminates it on timeout. These are transport bounds, not a guarantee of storage-device latency, real-time scheduling or bounded kernel process reaping under host failure.

## Durable authority and failure behavior

This change extends the existing trusted computing base with the process launcher, IPC framing, signed status/reply validation and endpoint selection. It changes custody loading and the handoff transport, while preserving the core authorization and result-disclosure contracts.

`Store::deliver_via` still builds the existing capsule only after the normal authenticated approval and durable reservation. It commits handoff intent before calling the transport. Timeout, child loss, malformed/oversized response, stale nonce, mismatched capsule binding, invalid acknowledgement or post-handoff persistence failure leaves consumed `outcome_unknown`. There is no automatic retry or refund. Duplicate invocation reuses the core run; cold startup restores no authenticated sessions or executable approvals. Unknown history requires reconciliation and cannot be made executable by reopening the child. Revocation remains a durable prohibition on future dispatch, not erasure of previously delivered plaintext or recipient/provider revocation.

The closed drill installs version one, drops and reaps the child, opens fresh broker and recipient processes, requires authentication again, rotates to version two, commits authenticated revocation, and verifies it after reopening. Its report includes two deliveries, two consumed uses, two remaining uses and recipient generation two. It emits no capsule, receipt, plaintext slot or key. All human-presence, protected-custody, protected-deployment and real-key readiness fields remain false.

## Evidence and limits

Functional tests exercise the standalone child through delivery/rotation/reopen/revoke, default-feature refusal and malformed child input. Private transport fixtures exercise missing/truncated/oversized/malformed responses, bounded stalled/trickling I/O, stale response binding, a signed but invalid acknowledgement, startup receipt reconciliation, child cleanup, and consumed uncertainty after durable recipient acceptance and broker restart. Fault injection remains test-only; no executable or environment selector is exposed for production faults. Existing vault tests remain applicable to the local endpoint and shared durable path.

Tests of mock transport failures do not establish process/host isolation or power-loss durability. Same-UID code can inspect process memory and ordinary custody files, edit the executable or configuration, and coherently roll back fixture state. The current executable is not measured or attested, and the fixed recipient metadata is not evidence of its build/dependency provenance. The existing protected-recipient admission gates remain closed. This increment does not resume or replace an independent security review, demonstrate agent confinement, or authorize operational data.

See [custody](custody-spike.md), [recipient adapter contract](recipient-adapter-contract.md), [vault delivery](vault-delivery-spike.md), and [threat model](threat-model.md).

### Local verification, 2026-10-09

Tested on Linux x86_64 with Rust 1.96.1 (`31fca3adb`, LLVM 22.1.2), offline/locked dependencies, and unchanged Cargo.lock SHA-256 `bce720a604f8d12632fe69d669ef898a843a4319e4ab073e99ab9fc7d7f8f845`.

- All-feature library suite: 261 passed. The final focused process rerun passed all nine tests, including the added known-rejection/no-refund case.
- All-feature integration suites other than `interfaces`: 93 passed, including the two real-child cases. Default-feature library/access/GitHub and policy/protocol/review suites passed; the new default process refusal case passed.
- All-feature/all-target Clippy and rustdoc with warnings denied passed. All 22 all-feature doctests passed, including private-capability compile-fail checks.
- The aggregate `scripts/check.sh` did not complete: default `tests/interfaces.rs` had seven passes and 14 failures because this cloud sandbox rejects named Unix socket binding with `Operation not permitted`. No complete checkpoint pass or named-listener evidence is claimed. The anonymous socketpair path and its actual subprocess tests succeeded in this environment.
