# ADR 0001: Operation-first synthetic foundation

**Status:** Accepted for the foundation. **Date:** 2026-10-06.

## Context

The design centers delegated operations rather than copying a credential into arbitrary agent-controlled code. The implementation and tests use synthetic fixtures, without live providers, real secrets, credential migration or production use.

## Decision

Implement a local Rust policy/broker core with a fixed fake status operation first. The agent receives only a reviewed bounded result. Keep the project separate from operational vaults and repositories. Declare experimental status throughout the CLI and documentation.

Exclude raw-secret agent methods, arbitrary execution, general URL/HTTP proxies, plugins, remote access, automatic startup/unlock, and production initialization. A future trusted-consumer path deliberately releases plaintext and requires its own review.

## Consequences

The foundation can test policy, concurrency, approval/resume API shape, and adversarial result handling without credentials or network access. It does not yet satisfy the first useful real-agent alpha, persistent storage, or containment gates.

## Unresolved evidence

Actual agent-host integration, useful reviewed provider selection, transport bounds, and real private human approval are phase-A/C work. No engineering estimate is inferred from the speed of the synthetic demo.
