# ADR 0019: compose the imported record with approved child delivery

**Status:** accepted for canary-only development, 9 October 2026. Based on
PR #2 head `0ab8a1ac9a385ed7d9fff4b6f5c6efa0727e3303`; operational activation
remains unavailable.

## Problem

The preceding milestone exercises real encrypted import, mutually authenticated
TLS protocol traffic and a separate recipient process. Those drills instantiate
their own fixtures. Their separate success cannot establish that an approved
recipient received the record created by the input/import mechanism.

## Decision

Provide one fixed-canary composition that preserves the existing core authority
and durable delivery path:

1. Freeze and approve the exact fixture input/import review. Bounded input
   produces an age-encrypted record for the configured broker storage identity.
2. Admit that actual imported record and its exact metadata into the broker
   manifest. Do not regenerate a value through the older `Store::create` path
   or silently fall back when the imported artifact is missing or invalid.
3. Authenticate the fixture agent and administrator through the existing mTLS
   channels and signed actor protocol. Review and approve the imported secret's
   exact version, operation and recipient binding.
4. Reserve durably through the existing broker before handing the signed,
   age-encrypted capsule to the fixed recipient child over inherited local IPC.
5. Validate the child's signed receipt and correlate it with that reservation.
   Retain consumed uncertainty after a lost, malformed or mismatched response;
   never automatically retry or refund.

TLS terminates at the agent/admin protocol endpoints in this composition. The
recipient handoff uses the existing signed age capsule and signed reply over an
inherited socketpair. No claim is made that TLS terminates in the recipient.

The composed path supports only its fixed imported canary and declared version.
It must preserve the original two-version fixture schema and validation rules
for existing callers. The public API accepts a new fixture destination and
returns a closed report; it cannot accept a real value, private key, executable,
provider route or caller-provided readiness claim.

## Acceptance evidence

The completed implementation must prove the data and authority chain, including
that the imported artifact is consumed, its review/reference/version/broker and
recipient bindings match, and corruption or substitution fails before an
unauthorized effect. Ciphertext equality alone is insufficient authority.
Exercise actual TLS records, the fixed child, durable counts, duplicate reuse,
revoke and fresh authentication. Preserve the standalone regression tests.

Independent functional integration tests cover the public executable, fixed
report, no-overwrite behavior, bad arguments and absence of canary values in
captured outputs and persisted fixture artifacts. These limited observations
are not confidentiality or isolation proofs. Record only checks actually run
against the final integrated source and its exact hosted CI head.

## Limits retained

The operator and agent signers remain simulated. The fixture process owns its
TLS identities, and parent and child share one operating-system UID and host
control plane. Ordinary fixture files and path checks do not constitute
protected custody or immutable installation. Independently authenticated human
interaction, operational enrollment, custody, recovery, an independent rollback
anchor, the selected GitHub App provider adapter and a supported operator-owned
host still require their own implementation and evidence.

The previously stopped independent adversarial review remains unresolved. This
composition and its normal functional checks neither resume nor replace it.
`require_live_deployment()` stays an unconditional refusal. No credential entry,
grant, deployment, host/security change, provider call or Sprite wake is implied.
