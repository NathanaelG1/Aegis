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
| [0008](0008-github-app-synthetic-preparation.md) | Synthetic adapter implemented; live integration gated | Personal selected-repository GitHub App bindings, narrowed mock tokens, safe metadata and retained uncertainty; no key input/export |
| [0009](0009-synthetic-durable-github-intents.md) | Synthetic journal implemented; protected operational persistence gated | Sync-before-effect intent, explicit issuance references, strict read-only recovery and no restored authority |
| [0010](0010-versioned-synthetic-github-broker.md) | Synthetic core integration implemented; live composition gated | Closed operation variants, explicit V2 wire, exact reviewed GitHub approval, one-shot dispatch and broker-bound schema 2 |
| [0011](0011-optional-disposable-signing-source.md) | Optional synthetic signing implemented; protected custody gated | Disposable private sign-only leases, maintained RS256/JWT libraries, strict claims and no default graph expansion |
| [0012](0012-approval-bound-synthetic-signing.md) | Optional synthetic composition implemented; deployment decision pending | Durable approval-bound one-shot signing, private verified envelope, cached-token independence and no new live path |
| [0013](0013-vendor-neutral-authentication-and-acl.md) | Accepted design; remote implementation pending | Authenticated application identity and exact default-deny ACLs, optional operator networking, separate human administration and explicit proxy trust |
| [0014](0014-request-driven-delivery-lifecycle.md) | Accepted product/deployment design; lifecycle unimplemented | Episodic setup/delivery/rotation, wake-compatible durable state and fail-closed restart; optional separate API mediation |
| [0015](0015-integrated-synthetic-vault-delivery.md) | Optional integrated synthetic milestone; production entry/deployment unavailable | Main-core authenticated delivery, exact ACLs, encrypted canary capsules and durable state with explicit external-anchor limits |
| [0016](0016-separated-vault-protocol-roles.md) | Optional synthetic role separation and handlers | Role-specific material, exact authenticated connection capabilities and safe serialized responses |
| [0017](0017-synthetic-adapter-foundations.md) | Fixed-fixture adapter groundwork | Metadata-only entry ceremony, enrolled recipient handoff and bounded peer-bound channel framing; production activation refused |
| [0018](0018-protected-mechanism-development.md) | Accepted for canary-only mechanism development | Maintained mTLS, bounded encrypted import and separate recipient execution; deployment and real-key gates retained |
| [0019](0019-composed-canary-delivery.md) | Accepted for canary-only composition | Consume the actual reviewed import through TLS-approved durable delivery to the fixed child; preserve all operational gates |
| [0020](0020-process-owned-dummy-broker-service.md) | Accepted for fixed-canary process service | Separate TLS socket ownership and broker process, externally owned actor signing and fixed child cleanup; no listener or live admission |
| [0021](0021-fixed-application-slot.md) | Implemented canary-only mechanism; focused functional checks passed | One fixed application file, handle-relative staging/replacement and signed installation evidence; fail-closed reconciliation without replay or restored authority |
