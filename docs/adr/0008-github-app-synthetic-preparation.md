# ADR 0008: GitHub App synthetic preparation

**Status:** Accepted synthetic adapter experiment; live integration and protected delivery remain gated. **Date:** 2026-10-06.

## Context

The intended first provider is a GitHub App for NathanaelG1's selected personal repositories. Its long-lived private key must remain in protected signing custody; short-lived installation tokens must reach only trusted broker operations or an enrolled isolated Git recipient. Existing broker inputs/results are specifically synthetic issue status and cannot truthfully authorize a new metadata or Git operation.

## Decision

Add a private, fixed-fixture GitHub adapter exercise, separate from the existing broker wire/MCP surface. Public API exposes only safe synthetic reports and closed live-readiness gates. No real key input, valid JWT, live transport, process runner or token-export API is added. The mock signer models standard JWT claims without implementing cryptography; actual RS256 requires a maintained library or reviewed sign-only service after custody review.

Freeze personal account numeric ID/login/User type, App/client/installation IDs, selected repository IDs/names, exact signer version and binding revision. Reject all-repository/organization scope and unrequested permissions. Model a one-repository metadata-only exchange, fixed provider routes, typed output projection, bounded records, single-flight reservation, elapsed/UTC expiry, refresh and separately explicit provider revocation. Preserve unknown outcomes and block new-ID retries after uncertainty. Synthetic approval is not human authentication.

Do not expose the fixture state machine as a parallel production policy engine. A subsequent versioned operation/result contract must integrate with the existing broker's canonical review, authorization and protocol lifecycle. Real minting also requires protected durable intent/recovery, independently authenticated approval, trusted live transport and proven OS isolation. Same-UID arbitrary-shell deployments are unsupported. Generic Git credential helpers, agent process environment/arguments and mutable Git configuration are not permitted destinations.

The [GitHub preparation contract](../github-app.md) defines the implementation, limitations, milestones and proposed trusted Git-worker constraints. No machine security changes, real credentials or live provider calls are authorized by this ADR.

## Consequences

This increment tests provider-boundary logic while deployment prerequisites are unresolved. It does not satisfy ADR 0007's protected application-delivery requirement or ADR 0004's operational storage/recovery gate. Mock request policy is not network enforcement, private Rust types are not an OS boundary, and in-memory uncertainty is not crash-safe persistence. No dependency or lockfile change is required for a deliberately non-cryptographic mock. Verification claims must identify the actual platform and keep historical Mac evidence separate from this increment.
