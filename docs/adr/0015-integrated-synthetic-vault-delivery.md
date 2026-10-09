# ADR 0015: Integrate authenticated synthetic vault delivery with the core

**Status:** Optional integrated synthetic milestone; real-key entry/deployment unavailable. **Date:** 2026-10-07.

## Decision

Reuse the main broker for a typed delivery operation instead of adding a second policy engine. Compose the already optional age/AWS-LC/JWT dependencies for fixed encrypted records, exact ACLs, distinct agent/admin assertions, opaque authenticated client capabilities and a private encrypted recipient capsule/acknowledgement. Verify human-control proof inside the existing approval critical section and agent proof/ACL before budget consumption; sync durable reservation before decryption/handoff.

Keep signed bounded history plus an explicit separate generation-anchor contract, consumed uncertainty, revocation and inspection-only recovery semantics. Fresh starts require fresh authentication/approval and preserve the durable remaining budget. The fixture anchor and key kit assume trusted storage and cannot resist coherent rollback or same-UID access. The recipient and human signer are test actors, not deployment attestations.

Expose only fixed create/inspect drills and safe reports, with no arbitrary secret input or live activation flag. Real-key readiness stays unavailable pending operator-owned entry, protected custody/anchor/recipient adapters, production clocks/authenticated transport and a verified administrative boundary. Existing default/synthetic GitHub behavior and dependency graphs remain unchanged. See [the integrated contract](../vault-delivery-spike.md) and [operator ceremony](../operator-owned-deployment.md).
