# Synthetic recipient-adapter contract

This is a standalone, in-memory contract exercise for a future protected recipient adapter. It reuses the existing optional `vault-spike` age encryption, signed documents and fixed delivery types. It does not replace or integrate with `vault::runtime::Adapter`, its durable store, authenticated sessions, human approval or protocol handlers. It adds no dependencies, network transport, filesystem installation, provider calls, arbitrary secret entry or deployment activation. `require_live_deployment()` still unconditionally refuses.

The only intended public entry point is `run_synthetic_recipient_adapter_drill()`, which takes no arguments and returns a closed `SyntheticRecipientAdapterReport`. It generates disposable fixture identities, installs the two built-in canaries in sequence and revokes future fixture delivery. `Adapter`, `Transport`, `Enrollment`, `DummySink`, capsule and receipt types remain private. The drill is a synthetic prerequisite, not a production integration milestone.

## Trust and binding

A private enrollment contains the exact recipient ID, enrollment revision, configuration revision and slot; fixture executable, dependency, configuration and destination digests; destination revision; transport contract; encryption recipient and receipt-key revision. These values are generated or chosen by fixture setup. There is no public enrollment setter or agent-supplied replacement.

The sink compares the complete expected enrollment against its actual in-memory object under the same lock that checks and advances the installation generation. Tests change each enrolled field after a capsule has been prepared to demonstrate rejection at the installation point. A matching fixture digest does not establish executable measurement, independently protected provenance, OS isolation, an authenticated remote endpoint or a race-free filesystem path.

The signed capsule binds:

- Exact schema and capsule purpose, random fixture vault ID and delivery request ID
- The full reviewed fixed profile: profile revision, repository, secret ID/version, recipient/slot/revisions, ACL revision, adapter and output contracts
- A digest of the entire enrollment and the expected installed generation
- Age-encrypted fixed-canary content, checked against the selected exact version after decryption

The broker-side fixture writer and recipient receipt signer are separate disposable RSA keys. The sink pins the writer verifier; the adapter pins the receipt verifier. An acknowledged receipt must match the exact schema/purpose, vault, request, full profile, enrollment digest, prior and next generation, and digest of the actual signed capsule sent. A signed receipt for another request, version, recipient or ciphertext cannot become success. SHA-256 digests identify authenticated values; they are not independent attestation or rollback protection.

The dummy sink validates canary bytes temporarily and retains only capsule digests and signed receipts. It does not implement an application plaintext credential slot. Existing private-buffer zeroization is used, with the same native/parser/allocator-copy, swap and crash-dump limitations as the [vault spike](vault-delivery-spike.md).

## Reservation, duplicate handling and uncertainty

The fixture book serializes request equality, revoke, reconciliation block, remaining-use checks and reservation under one mutex. A new valid request consumes one of four uses before capsule construction or handoff. A known rejection consumes its reservation too. There is no refund path.

A repeated ID with the exact original typed parameters returns its retained outcome without another handoff. Changed parameters return `request_id_conflict`, even for a revoked or unknown request. A duplicate while the original is in flight returns `outcome_unknown` without starting a second handoff; this temporary observation does not overwrite the original invocation's later result. One distinct in-flight operation is permitted. Further distinct requests are rejected at capacity without consuming a use.

The sink independently deduplicates the exact signed capsule digest for a delivery ID and returns its previous receipt. A new encryption of the same value is a different capsule and is refused for that ID. There is no automatic capsule regeneration/retry after a handoff.

A trusted pre-installation rejection becomes the stable `provider_unavailable` result. A missing, malformed, mismatched or unverifiable acknowledgement, an unknown handoff, or a caught transport panic becomes `outcome_unknown`; the reservation remains consumed, retries return that unknown result and new request IDs return `reconciliation_required`. Tests include errors and panic after the sink has advanced its generation. No automatic reconciliation or reset operation is exposed. A future remote transport must not classify an uncertain connection or response as known rejection.

This book is deliberately separate from the runtime authority engine. It has no durable reservation, authenticated principal, approval proof, session expiry, cross-restart budget or recovery capability. Integrating a real adapter requires the existing main broker authority path and durable reservation before reading or delivering real material; this stand-alone book must not be promoted into a second production policy engine.

## Rotation and revocation

Version one requires generation zero; version two requires generation one. Installation advances exactly one generation under the sink lock. Early version-two delivery and stale generation delivery fail without installation, while keeping the attempted reservation consumed. Duplicate receipt lookup does not roll a newer generation back.

Revocation is serialized with reservation. If revoke wins first, no new request can reserve or hand off. If reservation wins first, the accepted handoff may finish after revocation. Retained outcomes remain inspectable through this private fixture API. Revocation does not retract an installed canary, erase plaintext, stop a recipient or revoke provider authority. The report explicitly sets `installed_value_retracted`, `durable_state_verified`, `protected_recipient_verified` and `ready_for_real_keys` to false.

## Bounds and result surface

| Boundary | Fixture bound |
| --- | --- |
| Caller request ID | Existing 64-byte identifier parser |
| Signed capsule | 16 KiB |
| Age ciphertext | 4 KiB decoded |
| Signed receipt | 8 KiB |
| Retained attempts / sink receipts | At most 32 each |
| Concurrent new handoffs | One |
| Total newly reserved uses | Four |
| Secret/version choices | Two built-in canaries only |
| Report | Eleven typed boolean/count fields; no opaque payload |

The four-use limit is normally stricter than retention capacity; tests seed test-local state to exercise both 32-entry checks independently. Byte limits constrain accepted messages. Existing signing and verification helpers still allocate within their separate 64 KiB document limit before some narrower adapter checks; this is not a precise peak-memory bound. The implementation has no hostile network parser or external transport lifetime, cancellation or timeout support, and must not be presented as bounded production I/O.

No capsule, raw receipt, key, secret, path, URL, environment, command, digest, arbitrary provider string or transport selector is returned in the public report. The tests check fixed-canary report JSON and Debug output, not every possible log or process-memory channel. No same-process or same-UID confidentiality boundary is claimed.

## Evidence and integration hooks

The contract source is `src/vault/recipient_adapter.rs`; the intended optional module hook is `pub mod recipient_adapter;` in `src/vault/mod.rs`. That hook exposes only the zero-input drill and report and does not connect it to runtime dispatch. The isolated implementation commit leaves the hook to its integration owner. Verification of this source uses that temporary hook under `vault-spike` / all features.

The focused suite covers every enrollment field, invalid request bindings before reservation, all signed capsule/profile context fields, forged signer/unknown fields/wrong encrypted canary or recipient, exact capsule replay, all receipt bindings, request conflict, rotation/revoke ordering, post-install receipt loss/malformed/mismatched response/panic, consumed known rejection, exhausted uses, concurrent duplicate/reservation behavior and byte/retention bounds. Compile-fail documentation keeps the private transport and capsule types inaccessible and rejects caller-provided secret input to the drill.

```sh
cargo test --locked --offline --all-features --lib recipient_adapter
cargo test --locked --offline --all-features --doc recipient_adapter
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
```

Passing these checks establishes the tested synthetic behavior only. Protected enrollment and custody, independently authenticated human control, OS-enforced recipient identity, real storage/handle/credential-store installation, bounded authenticated IPC, protected durable handoff and reconciliation, provider credential rotation/revocation and host-specific adversarial testing remain outstanding. The [operator-owned deployment ceremony](operator-owned-deployment.md) and [application-delivery acceptance gates](application-delivery.md) still apply. No security review or audit is claimed by this increment.

Verified on 2026-10-07 in the Linux x86_64 cloud workspace with Rust 1.96.1 (`31fca3adb`, host `x86_64-unknown-linux-gnu`), all features and the temporary module hook: 15 focused unit tests, three compile-fail doctests, formatting, all-feature/all-target Clippy with warnings denied, and all-feature rustdoc with warnings denied passed. `Cargo.lock` was unchanged (SHA-256 `bce720a604f8d12632fe69d669ef898a843a4319e4ab073e99ab9fc7d7f8f845`). These focused results do not replace a full integrated checkpoint, a host-boundary test or a security review.
