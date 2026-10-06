# ADR 0005: Thin agent protocol and reviewed outputs

**Status:** Synthetic Unix/MCP implementation; broader host compatibility pending. **Date:** 2026-10-06.

## Context

An agent needs useful feedback, while raw provider output or a convenience URL proxy can disclose secrets or broaden effects. MCP adds framing and host interactions but should not create a second policy engine.

## Decision

Expose the same broker-owned prepare/approval-request/invoke/status/cancel contract through bounded typed messages. Reject unknown/invalid authority-bearing fields. The JSON-lines fixture is a development adapter; the implemented MCP stdio process is a thin client of the foreground broker through a current-UID-checked Unix socket.

The narrow MCP adapter supports protocol 2025-11-25 `initialize`, `ping`, `tools/list`, and six fixed tool calls. It maps arguments onto the same strict broker protocol, does not execute tools from notifications, and has no credentials, key custody, human control, or automatic broker startup. A cached random epoch rejects broker restart continuity. Initial MCP/policy tests pass on the recorded Mac; broad client-host compatibility is unverified.

Keep all credentials and human approval controls out of the agent protocol. Stdout contains only protocol messages. Stderr is host-observable and also excludes private input/material. No MCP form-based credential collection is allowed.

Review output disclosure per operation. The first projection consists only of expected numeric IDs and an enumerated status. Validate against dispatch bindings; do not release arbitrary bodies, headers, exception text, or provider-supplied strings. Future document/text access requires a separately reviewed data grant.

## Consequences

Protocol annotations/descriptions are hints, not authority. Client compatibility and framing tests do not prove peer authentication or human presence. A wrong/malformed output fails without dumping it; generic redaction is not the information-release contract.

## Unresolved work

Freeze the stable protocol evolution policy and expand per-platform peer/path tests, actual host capture tests, MCP lifecycle/version compatibility, distinct-client authority where needed, and the real-agent protected approval/resume flow. The existing adapter/IPC bounds and schemas are experimental, and same-account peer checking does not prove containment.
