# Architecture decisions

ADRs freeze the decisions made for the synthetic foundation and identify unresolved feasibility gates. They do not approve live operations or establish a security audit. Change an accepted decision by adding a superseding ADR with contract and test effects.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-operation-first-synthetic-scope.md) | Accepted for foundation; optional delivery direction superseded by 0007 | Operation-first interface; synthetic-only checkpoint |
| [0002](0002-control-authority-and-host-boundary.md) | API/terminal workflow implemented; protected mechanism pending | Separate control and agent channels; host/presence proof deferred |
| [0003](0003-session-state-reservation-and-retry.md) | Accepted for single process | Frozen exact bindings; volatile session budgets; one reserve/revoke serialization point; no blind retry |
| [0004](0004-age-and-independent-recovery-gate.md) | Synthetic spike implemented; operational backend pending | Established age and independent fresh-process recovery before persistent real secrets |
| [0005](0005-protocol-and-output-contracts.md) | Synthetic Unix/MCP implemented | Thin agent protocol/MCP; strict typed result projection |
| [0006](0006-release-evidence-and-license.md) | Accepted gate; MIT selected | Claims follow platform evidence and independent review; MIT first-party licensing with separate dependency review |
| [0007](0007-protected-application-delivery.md) | Required product design; implementation/enforcement pending | Agent-blind delivery to enrolled isolated applications, exact human approval and fail-closed OS boundary |
