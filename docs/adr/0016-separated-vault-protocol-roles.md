# ADR 0016: Separate vault runtime key roles and connection handlers

- Status: accepted for the synthetic code milestone only
- Date: 2026-10-07

## Context

ADR 0015 established an integrated canary delivery path, but its private fixture host automatically signed both actor roles and passed an all-role key kit into runtime storage and recipient objects. Wrapping that composition in a network server would preserve unnecessary key ownership and obscure connection authentication. The requested preparation needs reusable boundaries before any later production deployment ceremony.

## Decision

Split runtime broker, recipient and actor material. Broker storage owns only storage/writer material and recipient public material; recipient owns only its decrypt/receipt material and broker verifier; the gate owns only actor public verifiers. Keep the all-role kit solely in explicitly synthetic construction/test helpers, never as a production custody design.

Expose separate typed, bounded agent/admin connection handlers over the existing core, with strict versioned frames, opaque per-connection capabilities, independent role/audience/purpose proofs, exact canonical review and closed safe results. Recheck the admin session alongside the approval/revocation assertion in the core mutation hook. All agent status/terminal paths retain their authenticated-handle requirement.

Do not add a listener, dependency, general signer/export, secret-entry endpoint, runtime caller-selected deployment mode or live activation. The public constructors remain fixed-canary fixtures. No same-process/UID memory-secrecy or human-presence claim is made. Network peer/channel binding, independent human UI/enrollment, protected custody/anchor, production time and a real isolated recipient remain prerequisites.

## Consequences

The connection handlers can be reused by a later reviewed TLS or protected IPC adapter, but must not be shared globally across unrelated remote peers. Separate library types do not establish operating-system separation. This increment adds no package or default dependency and preserves the legacy protocols. The fixture's file and rollback assumptions remain unchanged. A stopped independent review remains incomplete; developer and platform regression passes cannot replace that review.
