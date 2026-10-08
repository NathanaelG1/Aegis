# Approval-bound disposable signing composition

**Optional, synthetic only.** With `signing-spike`, `Control::synthetic_github_signed` connects the [private disposable signing source](signing-spike.md) to the [reviewed main-broker GitHub operation](github-broker.md). The existing constructors, CLI/MCP selection, default dependency graph and live-readiness gates remain unchanged. A real cryptographic signature is exercised with an unregistered ephemeral key and fixed synthetic issuer; no GitHub service accepts it and no network is called.

```sh
parent="$(mktemp -d /tmp/aegis-signed-demo.XXXXXX)"
cargo run --locked --offline --features signing-spike --example github_signed_spike -- "$parent/journal"
```

Only non-secret synthetic intent records are written in the new destination. The example performs trusted-host test approval, returns the bounded metadata result, replays without a second effect, explicitly revokes the mock token and inspects the journal after dropping the broker. It does not prove that a human approved. It takes no key or provider configuration.

## One authority path

1. The core validates the exact reviewed request, frozen profile, credential revision, instance/principal/session, limits, expiry and remaining budget.
2. Under the existing reserve/revoke serialization point, the core consumes one use and the adapter syncs schema-2 `BrokerReserve` before resolving a signing lease or producing a signature.
3. The reserved work carries a private, non-Clone signing permit. Its binding includes the complete `OperationApprovalView`, reservation time and actual remaining-before budget, separately from the previously reviewed remaining budget. No agent-provided approval boolean, label-only signer selection or standalone simulated approval can create it.
4. Execute removes the one-shot work and compares the frozen authorization with the actual dispatch. A new mint consumes the signing permit. The private envelope retains the zeroizing JWT wrapper and the matching public verifier; neither it nor its source/permit has a public export path.
5. The fixed mock exchange verifies the signature, exact issuance-derived claims and exact authorization. Existing request-policy, explicit metadata-only scope and result projection checks still apply. No token/JWT is returned to the agent or written to the journal.

The source also independently checks the fixed enrollment, instance/principal/session, policy generation, full limits and budget relationship before issuing a lease. The core remains the authority; these checks are not a new human-authentication mechanism. First-party crate internals and their private test hooks remain trusted code.

## Time, caching and revocation

Signing uses the same synthetic UTC origin and broker elapsed clock as the adapter. The source checks the reservation floor under its mutex and returns the exact checked issuance stamp with the opaque envelope. There is no extra untracked pre-sign observation. The adapter advances its latest observation, syncs mint intent, then samples the current time for exchange verification. This rejects expiry during a slow sync and detects rollback before calling the provider. Verifying only at issuance time would not establish current validity.

The source retains its 30-second signing-lease and 600-second source limits. Request expiry remains a reservation deadline, not cancellation of work that already won the core dispatch/revoke race; a source lease can still expire before signing. The fixture's installation-token expiry remains conservatively anchored to the original reservation, preserving existing schema-2 replay rules. This is not a live GitHub timestamp/TTL implementation; real exchange timing, trusted UTC and durable receipt semantics remain a release gate.

A usable cached installation token needs no new signature or key lease. Every cached read still needs its own exact core review and consumes one core use. Logical source lock/expiry does not revoke an already issued token; a test performs approved cached reads after both. Core grant revocation prevents new reservations, while previously reserved work may finish. Explicit provider-token revocation remains a separate trusted-control action. No source lock, grant revoke, process exit or private-key rotation can recall an already produced credential.

## Failure and restart rules

- Reservation-write/sync failure: no signature or provider call; consume the core use, retain uncertainty, block new work and never refund/retry.
- Source-resolution failure after durable reservation: no signature/exchange; core retains unknown and the journal retains incomplete work. No authority is reconstructed.
- Known signing-lease failure after reservation: record a failed result, consume once and never repeat that request ID.
- Panic before/after signing: retain unknown, block new effects and never remint. In-memory credential wrappers drop during unwinding; process exit does not imply memory erasure.
- Failure after mint/read may have started: preserve the existing unknown-outcome and receipt-quarantine rules. The uncertainty flag is explicit shared `Cell` state across the consuming unwind boundary.
- Real subprocess exit before/after signing: inspection reports consumed incomplete intent, zero restored grants/sessions and no automatic retry. No signature/key file exists to recover.
- Crypto/provider initialization failure: construction returns no handles. Because the journal header is created first, a header-only directory may remain; inspection shows zero reservations and no authority. The same destination cannot be reused. Start a separately chosen new synthetic destination rather than treating it as recovery.

Schema 2 is unchanged and does not attest whether a historical run used mock strings or disposable signing. It stores only synthetic policy/operation facts under the existing trusted-storage assumption. A valid rewritten, deleted or rolled-back journal is still not authenticated or rollback-resistant.

## Verification boundary

Focused tests cover complete source/permit/envelope binding, profile/key/owner/scope substitution, stale/unapproved requests, duplicate/concurrent dispatch, actual versus reviewed budget, current-time claims/signature verification, wrong keys, corruption, key lock, cached use, lease expiry, sticky rollback, 18 write/sync-fault combinations, pre/post-sign panics and process exits, provider-initialization failure and header-only recovery. Visibility doctests keep all source/permit/envelope types crate-private. The [verification record](verification.md) records exact totals and the existing Unix-listener restrictions.

This is the final planned preparation increment before choosing a supported deployment. The consolidated [readiness checklist](readiness-checklist.md) names the minimum missing end-to-end components, required permissions and estimated engineering scope. It is not permission to provision a host, configure access, import a key or enable live HTTP.
