# Roadmap and release gates

The design prioritizes a local capability broker with a portable `age` backend and required protected agent-blind application delivery. This checkpoint implements synthetic policy, foreground Unix/MCP workflow, and a separate optional saved-fixture age recovery spike. Protected delivery is not yet implemented or verified. The gates below determine what may be claimed; they are not authorization for real credentials, provider access, migration, permissions changes, or publication.

## A — Contracts and feasibility

**Implemented:** product/threat contracts, canonical typed request state, separate trusted control and agent API, fake status provider, exact binding/retry/concurrency tests, separate foreground terminal and Unix agent endpoint, thin MCP tools, broker epoch continuity, local developer docs, and optional fresh-process fixed-fixture recovery. Current observed test results are in [verification](verification.md).

**Still required before security claims:**

- Choose and test an actual human approval mechanism and host trust boundary.
- Show agent bypass attempts cannot reach human authority within the declared mode.
- Spike a delivery boundary using only synthetic canaries: separate service identities or actual agent confinement, independently authenticated human control, protected recipient code/dependencies/configuration and file/process/handle resources. Refuse unsupported same-UID/container/debug arrangements; see [delivery gates](application-delivery.md#synthetic-adversarial-acceptance-gates).
- Expand the completed [synthetic age spike](storage-spike.md) into independently protected custody and operational recovery verification; add reference-CLI and cross-platform interoperability.
- Specify and fault-test the platform storage/rekey arrangement before implementing a persistent custody promise.
- Exercise a real agent host with synthetic fixtures, including denial, private approval, resume, and concurrent requests.

Exit gate: enough evidence to freeze the host/mode matrix, operation and delivery request/grant schemas, exact recipient/configuration/destination approval bindings, recovery protocol, and platform transaction design. A pure encrypt/decrypt demo or broker-only provider call does not satisfy application delivery.

## B — Portable storage foundation

An optional [disposable sign-only source](signing-spike.md) now exercises exact key references, lifecycle and maintained-library JWT signing independently of the broker. It is not persistent custody. The subsequent [synthetic composition](github-signed-composition.md) binds leases to approved adapter revisions and preserves durable unknown outcomes. Implementation now pauses at the [deployment decision checkpoint](readiness-checklist.md) before considering a protected backend.

The optional age spike demonstrates fixed-schema encryption, two recipients, saved-kit fresh-process recovery, and disabled restored authority. It has no passphrase-protected identity or operational transaction protocol. Build the operational credential-source/backend interface while keeping key providers separate. Use bounded versioned snapshots, exact profiles, private human setup, ordinary serialized commits, backup, and restore to new destinations. Public metadata remains non-authoritative; restored grants are disabled.

Exit gate: actual encrypted snapshot restoration by a fresh process using an independently saved kit on the tested OS matrix; cancellation never overwrites another vault; invalid/corrupt inputs produce no effect; crashes leave a usable committed pair. Real-secret persistence remains gated until demonstrated.

No final on-disk rekey protocol or storage size limit is frozen by the current in-memory foundation.

## C — Useful agent alpha

**Implemented synthetic portion:** explicitly started bounded foreground sessions, current-UID-checked Unix IPC, a versioned operation protocol, and a thin stdio MCP client with six fixed tools. The terminal requires canonical inspection before approval. All clients share one bound session; same-account code can automate control.

**Remaining:** protected host/human integration, real-agent harness, distinct-principal/session integration where required, and one useful fixed reviewed read-only provider operation after separate authorization and transport tests. Reuse the existing broker policy and validated output contract.

Exit gate: a real agent receives useful authorized results, cannot broaden scope, pauses for the supported private human decision, resumes without credential material, and behaves correctly with concurrent sessions. State exact host/OS boundary limitations.

The current synthetic terminal/socket/MCP workflow does not complete the real-agent/presence gate. No auto-start, remote listener, unattended reboot unlock, generic proxy, or arbitrary plugins belong in the first foreground session release.

## D — Protected application delivery

**Design only:** [ADR 0007](adr/0007-protected-application-delivery.md) and the [delivery contract](application-delivery.md) require direct delivery to an enrolled isolated application's protected file, descriptor/handle or credential store. The agent proposes references and receives only safe status. No delivery API, destination adapter, recipient enrollment, durable handoff state or confinement verifier exists yet.

The implementation backlog is sequential where enforcement dependencies require it:

1. **Boundary and approval spike:** demonstrate agent denial for files/stores, environment, memory, handles, control and service/container/debug administration. Authenticate human control independently. Name the tested mode, effective identities/privileges and OS versions; refuse missing/changed protection before handoff.
2. **Protected recipient enrollment:** pin service and instance rules, executable/build/dependency closure, launch inputs, protected configuration revision, destination slot/mechanism and provider endpoint/scope. Reject agent-workspace security-relevant code/configuration, malicious plugin/import/proxy/diagnostic routes and substitution.
3. **Canonical reference-only policy:** define bounded proposal/approval/delivery/status/revocation schemas and exact immutable human receipt bindings. Build fake-recipient tests for approval/denial/resume, scoped status, ID conflict, replay and stale binding. Add no generic export, shell, arbitrary endpoint or plaintext-return route.
4. **Durable reservation and uncertainty:** specify protected pre-handoff journal, one delivery ID/reservation, restart reconciliation and retained ambiguous outcome. Force final-use/revoke races and crash/lost-acknowledgement cases; prohibit automatic repeat or refund after uncertainty. Distinguish delivery counts from downstream recipient/provider use limits.
5. **Protected destination adapter:** implement one narrowly reviewed mechanism on one named platform. For files, test symlink/hardlink, parent/mount/object races and atomic installation in enrolled protected directories. Test staging/flush/installation/journal/acknowledgement faults and prevent plaintext in environment, inherited resources, logs, backups, dumps and diagnostics.
6. **Lifecycle and revocation:** report future-delivery revocation, local cleanup, recipient termination and separately authorized provider revocation independently. Demonstrate supported expiry/lock/suspend/logout behavior without claiming that local cleanup erases delivered plaintext.
7. **Platform expansion and review:** complete the full synthetic adversarial matrix for each mechanism and platform before enabling it. Linux separate identities/systemd credentials, macOS protected identities or confined-agent/hardened-recipient IPC, and Windows service identities/DACLs/AppContainer are proposals only.

Exit gate: the agent configures two systems through approved references, the enrolled application can consume the synthetic credential, and the agent's actual tools cannot read or redirect it. Every approval binding, fail-closed decision, crash/replay, concurrency and revocation assertion has recorded platform evidence. Independently review the composition before real-secret delivery. No OS/security changes or live credential use are part of this documentation checkpoint.

## E — Reviewed release

Complete adversarial/fuzz, crash, corruption, permissions/path, platform, dependency, and lifecycle tests, including the required application-delivery gates. Establish a private security reporting route, maintenance policy, MIT dependency/attribution review, packaging/provenance, and independent composition review with remediation.

Exit gate: the published guarantees match demonstrated enforcement for each shipped configuration. Approval, adapters, output, sessions, recovery, and host boundaries are included in review; encryption alone is not the product's security model.

## Later, separately reviewed increments

Native unlock convenience, persistent background broker, persistent cross-session budgets, additional providers/write operations, additional isolated deployment modes, team synchronization, external credential sources, rotation/acquisition operations, and headless service mode each require their own acceptance and threat review. A tested OS boundary for required application delivery belongs in gate D, not an optional later increment. No later feature silently inherits the first mode's guarantees.

## Decisions still open

| Decision | Required input |
| --- | --- |
| Third-party licensing and attribution | MIT is selected for first-party code; complete resolved-per-target dependency review before a packaged release |
| Trusted human mechanism / agent host | Enforcement spike and human UX evidence |
| Protected delivery mode and first destination adapter | Synthetic confinement/approval spike, protected recipient/configuration enrollment, exact OS/mechanism and adversarial/fault evidence |
| Operational age release and features | Synthetic spike pins 0.11.1 with default features off; operational selection needs per-target review and expanded interop/resource evidence |
| Disk transaction and rekey layout | Per-platform fault injection and recovery matrix |
| Journal semantics | Required before protected delivery or durable budgets; ownership/privacy/consistency/rollback and ambiguous-handoff reconciliation |
| Real provider and result schema | Useful low-risk read operation with fixed transport and least privilege |
| Platform support | Named OS/architecture/context/filesystem integration evidence |
| Broader MCP-host compatibility | Narrow 2025-11-25 adapter and protocol tests exist; actual agent hosts, framing/lifecycle edge cases, and integration evidence remain |
| Security reporting and release ownership | Owner-approved contact, supported releases, response/disclosure policy |

## Effort treatment

Re-estimate storage, broker, provider, MCP, host integration, platform verification, and remediation after the feasibility spikes. Experimental alpha availability is distinct from stable reviewed release readiness.

## First integration — personal GitHub App

[ADR 0008](adr/0008-github-app-synthetic-preparation.md) implements the first [synthetic provider-boundary milestone](github-app.md#milestones). The next gates are protected deployment/human approval; sign-only key custody and durable pre-mint recovery; versioned broker metadata operation and bounded live transport; then a protected Git worker or individually reviewed writes. No milestone may bypass the application-delivery gates above. Selected personal repositories only; organization access, Workflows/admin permissions and user tokens remain excluded.

The next code milestone, [synthetic retained GitHub intents](github-intent-journal.md), is implemented: pre-effect synced records, strict recovery inspection and zero restored authority. This progresses fault-model evidence without completing protected storage, authenticated reconciliation or durable production grants. The next safe code slice is versioned broker operation/approval integration and protected-storage/recovery abstractions using fixtures; actual identity/confinement/human-channel/key provisioning requires a separate authorized deployment.

The [versioned synthetic core integration](github-broker.md) is now implemented: exact reviewed GitHub approval, shared broker invariants, one-shot dispatch, V2 JSON/MCP and schema-2 broker-bound journal context. Remaining safe code work includes protected-storage/key-source abstractions and authenticated recovery design using fixtures, followed by maintained signing and bounded live-transport implementations kept gated. Actual service/confinement/human-channel/key provisioning still requires an independently approved deployment.

## Vendor-neutral access decision (2026-10-07)

[ADR 0013](adr/0013-vendor-neutral-authentication-and-acl.md) accepts application authentication plus exact deny-by-default ACLs as the default future API design. Authentication bootstrap and stable principal mapping, ACL/admin integration, TLS/proxy enforcement and private-listener exposure tests are bounded implementation gates described in [access control](access-control.md). Private networking belongs to the operator and is optional; no hosting/VPN vendor is required. Architecture and synthetic acceptance work may proceed within its authorization, while remote activation, credential enrollment and host security changes remain gated.

## Request-driven delivery clarification (2026-10-07)

[ADR 0014](adr/0014-request-driven-delivery-lifecycle.md) prioritizes episodic setup/delivery/rotation with a wake-compatible lifecycle. Add protected persistent approval/revocation/use records, cold-start/rollback refusal, concurrent-wake fencing and retained handoff uncertainty to the delivery exit gates. Do not require mediation of every recipient API call; keep bounded API operations as an optional distinct mode. This is documentation only, with no selected host or implemented delivery/wake capability.
