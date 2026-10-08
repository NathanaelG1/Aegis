# ADR 0010: Versioned synthetic GitHub operation in the core broker

**Status:** Implemented synthetic policy integration; live composition remains gated. **Date:** 2026-10-06.

## Context

ADR 0008 intentionally kept GitHub outside the issue-specific broker contract. ADR 0009 added retained synthetic intent, but the mock's own approval simulation could not serve as the main broker's authority. A new operation needs exact typed review/result contracts without breaking issue-status callers.

## Decision

Generalize the broker's internal request/profile/result state to closed operation variants while preserving legacy types, issue-status methods, wire version 1 and default MCP behavior. Add explicit version-2 preparation/results and a fixed GitHub constructor requiring a new journal and per-request canonical reviewed approval. Legacy methods must reject GitHub handles before acting; unreviewed and bounded-session approval are unavailable for this operation.

Create private one-shot adapter work only after core authority checks. Consume the core use and sync the adapter reservation under the same lock as revocation, then execute provider work outside it. Disable the standalone simulated approval route on broker-owned adapters. Persist actual broker/review/budget context in journal schema 2; preserve schema-1 inspection and reject mixed schemas. Keep recovery read-only with no restored authority.

Preserve terminal uncertainty and blocked authority across all persistence failures. Permit only a same-bound-client/handle static GitHub unknown receipt after clock/session invalidation, without result data, renewed authority or changes to legacy issue behavior. Keep provider token revocation as a separate trusted-control action.

## Consequences

The fixed metadata operation now uses the main authorization engine. This supersedes ADR 0008's temporary exclusion of GitHub from the broker; its no-live-key/transport constraint and ADR 0009's trusted-storage limits remain. V2 commands/MCP wiring are compiled and in-process tested; cloud listener restrictions prevent a full Unix foreground claim. No cryptography, credentials, new dependency or OS deployment configuration is added. [The integration contract](../github-broker.md) and [verification](../verification.md) define current evidence and remaining gates.
