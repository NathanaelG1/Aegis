# ADR 0013: Application authentication and ACLs independent of network vendors

**Status:** Accepted architecture; remote enforcement remains unimplemented. **Date:** 2026-10-07.

## Context

The desired API must accept or reject an authenticated application's request using Aegis policy, without depending on a hosting or private-network vendor. Operators should also be able to use private networking in their own environments. Network membership does not identify the intended application principal or grant access to a secret/resource, and same-account local access does not establish agent-blind custody.

## Decision

Make authenticated application identity plus exact deny-by-default ACL evaluation the default future network-API architecture. Stable identity comes from a trusted issuer/subject/enrollment and verified credential, never a client label, address or forwarded claim. Apply ACL ceilings together with existing exact human review, secret/recipient/resource revisions, bounds, deduplication and serialized revoke/reservation. Missing verification/policy/context denies; partial rules cannot be combined into wider authority.

Keep independent human administration/approval, provider-neutral protected bootstrap and standards-based authentication choices. No network or hosting provider is mandatory. IP allowlists and operator-managed private networking are optional reachability defenses, not authorization grants. A future configurable listener requires TLS or an explicitly trusted secure reverse proxy with a protected backend hop, strict forwarded-identity handling and verified private-only exposure when selected.

Preserve existing synthetic Unix/JSON-lines/MCP behavior. Add acceptance regressions to the current typed protocol/core, not a second policy engine or dummy authentication adapter. Add no HTTP listener, authentication credential, ACL loader, networking configuration, dependency or live capability.

## Consequences

The [access-control contract](../access-control.md) defines exact decisions, bootstrap/proxy trust and implemented-versus-future acceptance evidence. Current trusted constructors still create fixed synthetic grants for one principal/session; they are not a default-deny remote ACL deployment. Protected custody, independent human presence, OS isolation, operational persistence and named-platform verification remain release gates. This decision refines the deployment choices in ADR 0012 without activating them or requiring Fly, WireGuard, Tailscale or an equivalent vendor.
