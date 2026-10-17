# Separated fixed-canary custody composition

The optional Unix `vault-spike` now provides a custody bootstrap and role-specific loaders that drive the **existing authenticated protocol, main broker, encrypted store and durable recipient path**. Unlike `SyntheticProtocol::create/open`, this path does not persist or reopen an all-role fixture kit. It is an ordinary functional increment, not a completed independent security review or an operator-owned production deployment.

No function accepts a provider secret, live account, host-protection assertion or readiness switch. The two installed values remain the built-in canaries. The [operator-owned deployment ceremony](operator-owned-deployment.md) and its missing production gates still apply.

## Public seams

The module is `aegis::vault::custody`:

- `bootstrap_synthetic_custody(custody)` requires a new destination and writes four role directories. It returns public fixture identity and safe observations, never private material. A failed bootstrap leaves a partial destination and cannot silently overwrite/repair it.
- `create_synthetic_protocol(root, broker_custody, recipient_custody, recipient_state, clock)` creates only fixed-canary records and the existing recipient. It opens only the two named runtime roles; it never opens actor files. It returns the existing typed `SyntheticProtocol` endpoints.
- `open_synthetic_protocol(root, broker_custody, recipient_custody, recipient_state, version, clock)` cold-starts the same durable path with no actor-key loading. Only fixture versions one and two are supported. Fresh agent/admin authentication and exact approval remain required.
- `run_synthetic_custody_drill(root, custody, recipient_state)` bootstraps fresh state and drives a complete serialized, role-signed workflow. It returns a closed report.
- `inspect_synthetic_custody(root, custody, recipient_state)` validates cold state and returns the existing safe recovery report. It needs no actor files and restores no sessions, executable approvals or grants.

Here `broker_custody` and `recipient_custody` are the corresponding child directories under a bootstrap destination. Signer/load implementation types stay private; this module provides no general signing, private-key export or arbitrary key-entry API. The generic protocol handlers retain their existing assertion-input format.

## Role documents and authority

Each role directory has one bounded `custody.json`, with a strict schema, exact kind and canonical random fixture vault identity. Documents reject unknown and duplicate fields; files use the existing new-destination, regular-file, owner, mode, link and non-following-leaf checks. The maximum document size is 16 KiB. These are the existing trusted-filesystem assumptions, not atomic path confinement.

| Role | Private material | Public material |
| --- | --- | --- |
| Broker | Storage age identity; journal/capsule writer key | Recipient age key; recipient receipt verifier; agent/admin verifiers |
| Recipient | Its age identity; its receipt-signing key | Broker writer verifier |
| Agent | Its one assertion-signing key | Fixture vault identity |
| Administrator | Its one assertion-signing key | Fixture vault identity |

The public-only RSA loader uses the existing AWS-LC parser and requires canonical fixture encoding. Broker loading rejects reused signing keys across the four signing roles and reuse of its storage identity as the recipient identity. No new dependency or cryptographic primitive is introduced.

The agent signer refuses administrator purposes; the administrator signer refuses agent purposes. The simulated approval helper compares the broker challenge digest with the exact retained review before signing. The actual endpoint and core hooks independently verify the signature, role, purpose, epoch, challenge, scope, session and canonical review. Signer refusal is therefore an additional fixture constraint, not a replacement policy engine.

Before creating any vault or recipient state, assembly compares vault identity, recipient encryption key, recipient receipt verifier and broker writer verifier across the loaded documents. `Store::check_recipient` also checks this tuple, including when both histories are empty. Previously a single kit supplied both roles; a separate loader must not treat empty matching histories as proof of recipient enrollment. Changed/foreign tuples fail before delivery.

The broker role document is trusted fixture enrollment, not an authenticated external enrollment service. Editing its verifiers changes the assumed trust root. File protection and public-key equality do not prevent a privileged actor from replacing a coherent set of custody/state files. No untrusted wire request can edit those files through this module.

## Executed workflow

The drill creates runtime state using the broker and recipient documents, then separately opens each actor's own signer. The bootstrap's generating objects have already been dropped. It verifies:

1. Unsigned agent/admin operations and wrong-role signing are denied.
2. The separately authenticated agent prepares only the fixed exact version-one recipient/resource/generation tuple.
3. The administrator inspects the broker review, rejects a changed review, and supplies the exact signed approval through the administrator endpoint.
4. The agent supplies a request-bound invocation assertion. The existing core reserves durably, encrypts and delivers the canary, verifies the receipt and returns only the safe projection. Repeating that invocation reuses its result.
5. Runtime and actors are dropped. The separated files are independently reopened for a cold version-two rotation. Fresh role authentication is mandatory; a consumed request ID cannot be reused, and rotation requires its own exact approval.
6. An administrator assertion durably revokes future reservations. Cold inspection reports two consumed uses, two remaining uses, recipient generation two and revocation. Restart cannot create new active authority.

The public drill does not merely run the earlier entry, recipient and transport reports beside one another. It composes the real optional vault/protocol implementation. It does not integrate the separate `recipient_adapter` fixture as an external process; the durable recipient still runs inside the trusted test process.

## Regression evidence and exclusions

Focused tests cover complete delivery/rotation/revoke, private-key exclusivity across role documents, strict parsing, malformed public keys, role-key reuse, actor-free runtime creation/open/inspection, signer drop before invocation, foreign role/custody mismatch, exact empty-history recipient bindings, old-epoch proof denial, no executable-approval restoration, and consumed uncertainty after an installed receipt loses acknowledgement. The last case leaves one consumed use, one unknown operation and generation one; cold restart refuses automatic delivery or refund.

Aggregate command results and platform evidence belong in [verification](verification.md). These tests do not resume or replace the stopped independent review.

All four files may still be readable to the same operating-system identity. Bootstrap temporarily holds every generated key; role loaders and the recipient still execute in one process in this demonstration. Selected owned buffers zeroize on drop, with the existing allocator/parser/native-copy, swap, dump and snapshot exclusions. Neither the library types nor the test directories prove agent-blind plaintext custody.

The journal anchor is under the broker role directory, in the same host/rollback domain. There is no independently protected anchor, recovery root, human UI/presence, real clock, authenticated production transport, immutable external application enrollment or measured removal of agent administrative access. The report keeps protected-custody, protected-deployment, independent-human-presence and real-key readiness false. `require_live_deployment()` remains closed.
