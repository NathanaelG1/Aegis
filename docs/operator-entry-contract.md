# Synthetic operator-entry metadata contract

**Fixed-fixture state machine only. No operational key entry or production approval.** The optional `vault::entry` module models the metadata checks that must precede the [operator-owned ceremony](operator-owned-deployment.md). Its public `run_synthetic_operator_entry_drill()` takes no arguments and returns only an `OperatorEntryReport`. It does not collect a credential, open a vault, dispatch a canary, contact a provider, inspect host permissions or provision an environment.

This increment changes no broker authority, credential custody, persisted state or platform claim. It introduces an isolated metadata model, not another operational authorization path. `vault::require_live_deployment()` still unconditionally returns `unsupported_deployment`. The drill calls that gate and fails if it unexpectedly permits entry. No input flag or report field can turn the ceremony into real-key readiness.

## Exact fixture bindings

Every receipt and the frozen review carry the complete canonical binding, compared by typed equality:

- Artifact, dependency graph and configuration digest placeholders, plus ACL revision
- Separate operator, agent, broker, recipient, recovery operator and reviewer roles, each with principal, enrollment revision and public-verifier digest placeholder
- Recovery destination, independent-anchor identity, recipient destination and endpoint digest placeholders
- Fixed resource, secret reference and exact version, and expected recipient generation

These are built-in dummy metadata. The digest placeholders are not computed from an installed build, key, configuration or host. The role names do not authenticate anyone. No caller can provide bindings, receipts, a deployment description or an arbitrary value through the public API.

A fresh random ceremony instance binds its receipts and review. An observation from another instance cannot be reused, even when every deployment field otherwise matches. Private methods compare the supplied current fixture binding before review, approval and reservation. An observed change latches invalidation: reverting to the old values does not revive approval. This models the required check without claiming that the code can measure a real deployment.

## Prerequisite receipts

Exactly five typed slots are required before freezing a review:

| Receipt | Expected fixture observer | Intended future evidence |
| --- | --- | --- |
| Artifact and configuration review | Reviewer | Independent review of the exact installed artifact and configuration |
| Independent recovery and anchor | Recovery operator | Independently retained recovery material, fresh-process recovery and protected anchor |
| Privileged access removal | Operator | Effective removal of every identified privileged agent route |
| Remaining-tools canary | Reviewer | Actual permitted tools cannot bypass the boundary |
| Enrolled-recipient canary | Recipient | Correct enrolled recipient succeeds with safe agent-visible status |

The drill constructs simulated receipts. It does not perform any of the intended future measurements in this table, authenticate the observer or provide signed evidence. Production adapters would need a separately specified, independently verified receipt provenance contract; accepting caller-authored metadata is insufficient.

A receipt binds the ceremony instance, complete deployment metadata, prerequisite kind, exact observer role and observation/expiry interval. An observation before ceremony creation, from the future, already expired or extending beyond the ceremony lifetime is rejected. An exact duplicate is idempotent. A conflicting duplicate cannot replace existing evidence or fill another slot. Missing evidence prevents review. There is no growing receipt history, free-text evidence field or serialization/import path.

## Review and one-shot lifecycle

The private state machine is:

1. `Collecting`: accept exact, bounded fixture receipts.
2. `Frozen`: retain an immutable copy of all five receipts, bindings, instance, earliest expiry and a one-use canary limit. No additional or replacement receipt is accepted.
3. `Approved`: compare the submitted review with that exact frozen value, and compare the actor with the bound operator role. A name, changed review, other role or old enrollment does not satisfy this check. This remains simulated approval, not proof of a human action.
4. `CanaryReserved`: consume the sole use under the same mutex used by cancellation. Return a private, non-cloneable metadata token that no broker dispatcher accepts. No effect follows the reservation.

`Canceled`, `Expired`, `Invalidated` and `ClockInvalid` are terminal before reservation. Cancellation is operator-role-bound. A change of any exact deployment binding invalidates the ceremony. The injected clock is checked inside the mutex; regression latches failure, arithmetic overflow prevents construction, and the deadline is exclusive. The fixed maximum lifetime is 60 seconds; an earlier receipt expiry wins. Neither denied calls nor review/approval extend it.

At most one racing reservation succeeds. If cancellation wins the serialization point, no reservation occurs; if reservation wins, cancellation cannot undo it. After reservation, dropping the token, expiry, retries or cancellation do not refund the use or rewrite the reserved state. Mutex poisoning fails closed.

The model stores five receipt slots and one frozen review. It has no dynamic request queue, network listener or external execution lifetime. A fresh instance starts with zero evidence and no approval. There is no persistence, cross-process consumed-use guarantee, restore, reconciliation or retry mechanism. The metadata reservation is deliberately not wired into the existing delivery adapter or its durable budget.

## Public result and boundaries

The report contains a closed `synthetic_metadata_only` scope, receipt/reservation counts and stable errors observed for repeat, cancel, expiry and production entry. It has no raw receipt bodies, paths, artifact identifiers, private keys, secret values, assertions or readiness booleans. The report itself is never accepted as input or authority.

The implementation is gated with the existing optional Unix `vault-spike` module and adds no dependencies. The module declaration/integration hook is `pub mod entry;` in `src/vault/mod.rs`. It adds no agent/admin wire action, CLI command, HTTP endpoint, live provider or operational key-entry constructor.

## Functional verification

Focused command, after the module hook is present:

```sh
cargo test --locked --offline --features vault-spike vault::entry:: --lib
```

Tests cover missing/duplicate/conflicting receipts; wrong instance, binding, observer and time; every bound deployment field and role dimension; full frozen-review comparison; skipped approval; non-operator attempts; terminal cancellation; earliest expiry and clock regression/overflow; consumed reservations; concurrent reservation/cancel ordering; fresh-instance non-restoration; closed report shape and persistent production refusal. Compile-fail examples keep the ceremony and reservation private.

These are ordinary implementation/functional checks. They are not an independent security review, evidence that the actual host's agent privileges were removed, proof of human presence or production entry approval. The protected adapters, custody, independent anchor, authenticated transport, real recipient, durable entry transaction and operator-owned isolation work in the [deployment plan](operator-owned-deployment.md) remain required.
