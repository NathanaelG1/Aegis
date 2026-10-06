# Roadmap and release gates

The design prioritizes a local capability broker with a portable `age` backend. This checkpoint implements synthetic policy, foreground Unix/MCP workflow, and a separate optional saved-fixture age recovery spike. The gates below determine what may be claimed; they are not authorization for real credentials, provider access, migration, permissions changes, or publication.

## A — Contracts and feasibility

**Implemented:** product/threat contracts, canonical typed request state, separate trusted control and agent API, fake status provider, exact binding/retry/concurrency tests, separate foreground terminal and Unix agent endpoint, thin MCP tools, broker epoch continuity, local developer docs, and optional fresh-process fixed-fixture recovery. Current observed test results are in [verification](verification.md).

**Still required before security claims:**

- Choose and test an actual human approval mechanism and host trust boundary.
- Show agent bypass attempts cannot reach human authority within the declared mode.
- Expand the completed [synthetic age spike](storage-spike.md) into independently protected custody and operational recovery verification; add reference-CLI and cross-platform interoperability.
- Specify and fault-test the platform storage/rekey arrangement before implementing a persistent custody promise.
- Exercise a real agent host with synthetic fixtures, including denial, private approval, resume, and concurrent requests.

Exit gate: enough evidence to freeze the host/mode matrix, request/grant schema, recovery protocol, and platform transaction design. A pure encrypt/decrypt demo does not satisfy it.

## B — Portable storage foundation

The optional age spike demonstrates fixed-schema encryption, two recipients, saved-kit fresh-process recovery, and disabled restored authority. It has no passphrase-protected identity or operational transaction protocol. Build the operational credential-source/backend interface while keeping key providers separate. Use bounded versioned snapshots, exact profiles, private human setup, ordinary serialized commits, backup, and restore to new destinations. Public metadata remains non-authoritative; restored grants are disabled.

Exit gate: actual encrypted snapshot restoration by a fresh process using an independently saved kit on the tested OS matrix; cancellation never overwrites another vault; invalid/corrupt inputs produce no effect; crashes leave a usable committed pair. Real-secret persistence remains gated until demonstrated.

No final on-disk rekey protocol or storage size limit is frozen by the current in-memory foundation.

## C — Useful agent alpha

**Implemented synthetic portion:** explicitly started bounded foreground sessions, current-UID-checked Unix IPC, a versioned operation protocol, and a thin stdio MCP client with six fixed tools. The terminal requires canonical inspection before approval. All clients share one bound session; same-account code can automate control.

**Remaining:** protected host/human integration, real-agent harness, distinct-principal/session integration where required, and one useful fixed reviewed read-only provider operation after separate authorization and transport tests. Reuse the existing broker policy and validated output contract.

Exit gate: a real agent receives useful authorized results, cannot broaden scope, pauses for the supported private human decision, resumes without credential material, and behaves correctly with concurrent sessions. State exact host/OS boundary limitations.

The current synthetic terminal/socket/MCP workflow does not complete the real-agent/presence gate. No auto-start, remote listener, unattended reboot unlock, generic proxy, or arbitrary plugins belong in the first foreground session release.

## D — Reviewed release

Complete adversarial/fuzz, crash, corruption, permissions/path, platform, dependency, and lifecycle tests. Add only a narrowly reviewed trusted-consumer runner with explicit plaintext disclosure and mutable-code analysis. Establish a private security reporting route, maintenance policy, selected license, packaging/provenance, and independent composition review with remediation.

Exit gate: the published guarantees match demonstrated enforcement for each shipped configuration. Approval, adapters, output, sessions, recovery, and host boundaries are included in review; encryption alone is not the product's security model.

## Later, separately reviewed increments

Native unlock convenience, persistent background broker, persistent cross-session budgets, additional providers/write operations, isolated deployments, team synchronization, external credential sources, rotation/acquisition operations, and headless service mode each require their own acceptance and threat review. No later feature silently inherits the first mode's guarantees.

## Decisions still open

| Decision | Required input |
| --- | --- |
| Third-party licensing and attribution | MIT is selected for first-party code; complete resolved-per-target dependency review before a packaged release |
| Trusted human mechanism / agent host | Enforcement spike and human UX evidence |
| Operational age release and features | Synthetic spike pins 0.11.1 with default features off; operational selection needs per-target review and expanded interop/resource evidence |
| Disk transaction and rekey layout | Per-platform fault injection and recovery matrix |
| Journal semantics | Needed only before durable budgets; ownership/privacy/consistency/rollback analysis |
| Real provider and result schema | Useful low-risk read operation with fixed transport and least privilege |
| Platform support | Named OS/architecture/context/filesystem integration evidence |
| Broader MCP-host compatibility | Narrow 2025-11-25 adapter and protocol tests exist; actual agent hosts, framing/lifecycle edge cases, and integration evidence remain |
| Security reporting and release ownership | Owner-approved contact, supported releases, response/disclosure policy |

## Effort treatment

Re-estimate storage, broker, provider, MCP, host integration, platform verification, and remediation after the feasibility spikes. Experimental alpha availability is distinct from stable reviewed release readiness.
