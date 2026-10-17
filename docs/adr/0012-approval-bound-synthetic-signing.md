# ADR 0012: Exact approval-bound disposable signing

**Status:** Implemented optional synthetic composition; live/deployment gates remain closed. **Date:** 2026-10-06.

## Context

ADR 0010 established the main broker as the GitHub authority and ADR 0011 proved a private disposable sign-only source independently. Composition must not introduce a parallel approval engine, general signing/export API, duplicate effect or new default native dependency.

## Decision

Add only explicit `Control::synthetic_github_signed` behind the existing optional feature. Reuse fixed main-broker policy and schema-2 journaling. After synced reservation, bind one private non-Clone permit to the complete reviewed view, actual consumed budget and reservation time. Compare it again at execute. Keep the JWT in its private zeroizing owner; the fixed mock exchange verifies its matching key, exact claims and authorization without exposing bytes.

Use one checked source issuance sample and a separate adapter-owned current-time observation after mint-intent sync. Preserve sticky regressions, existing conservative token-expiry anchor and journal schema. Cached tokens require fresh core approval but no source lease/signature. Grant revocation retains dispatch-wins semantics; future key signing and previously issued provider authority are separate controls.

Preserve consumed reservations and unknown outcomes across source failures, panic, crash and persistence faults. Restore no authority. Do not add CLI/MCP signing selection, live transport, key input, credentials, OS configuration or dependencies.

## Consequences

This joins the reviewed synthetic broker, disposable signing and mock exchange into one tested path. It does not establish protected custody, genuine human approval, operational time/persistence, OS isolation or live GitHub acceptance. The earlier standalone spike remains available; its “not composed” state is superseded only by this explicit constructor. Default mock behavior remains. Further implementation pauses pending the [readiness/deployment decisions](../readiness-checklist.md); [the composition contract](../github-signed-composition.md) records tests and limitations.
