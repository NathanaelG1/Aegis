# Project status

Aegis is an experimental synthetic-only capability broker. Source and documentation are licensed under MIT; no production secrets product, live provider, protected approval channel or audited release is available. Protected agent-blind application delivery is required but not yet implemented or verified.

## Broker process service checkpoint (10 October 2026)

The [fixed-canary process service](process-service.md) now drives actual bounded
TLS socket I/O between simulated clients and a separate broker child. A common
supervisor owns and reaps that broker and its fixed recipient child. Runtime
broker custody excludes client signing/TLS private keys and recipient private
keys. Actual imported ciphertext, exact approval, reservation, duplicate reuse,
cold authentication and durable revoke follow the existing policy engine.

Integrated local validation passed all 317 library tests, seven feature-enabled
and two default CLI acceptance tests, 1/28 doctests, formatting, unrestricted
Clippy and rustdoc. Default/all-feature aggregates produced 160/430 passes plus
the unchanged 14 denied listener cases, with zero ignored tests. Exact-head
hosted CI for this increment is pending publication; older green runs do not
cover it. The [verification record](verification.md) describes both actual
process reply-loss cases, child cleanup and their limits. Dependencies are
unchanged.

This remains UNISOLATED and dummy-only: same UID/control plane, simulated human
approval, disposable bootstrap custody and fixed fixture journal time. An
operational listener/admission policy, trusted time, protected input/custody,
independent human client, immutable application slot, external rollback anchor,
lifecycle/audit/provider adapters and required assurance remain open. All live
readiness gates remain false.

## Composed canary checkpoint (9 October 2026)

The [composed canary](composed-canary-flow.md) consumes the actual bounded
import into a signed one-record vault, authenticates exact approval/invocation
through agent/admin TLS, and hands the encrypted signed capsule to the fixed
recipient child. It retains duplicate state, fresh authentication, durable
revoke and inspection without restored authority. The standalone mechanisms
and two-version store remain available.

Local integrated validation passed 300 library tests, 6 all-feature and 2
default CLI acceptance tests, 1/27 doctests, formatting, Clippy and rustdoc.
Full default/all-feature runs produced 158/406 passes plus the same 14 denied
listener-dependent cases and zero ignored tests. Its later exact-head hosted
CI passed all 172 default and 420 all-feature tests, including the listener
cases; see [verification](verification.md). No dependencies changed.

This is a fixed dummy-input flow. Its TLS peers and simulated human signers are
controlled by the parent fixture; its child shares the development UID and
control plane. It reports UNISOLATED and real-key readiness false. Operational
input/custody, independent human enrollment, actual connection service,
immutable isolated application delivery, external recovery anchor, lifecycle
and audit, the live GitHub adapter and permissible assurance remain open. The
operator plan lists the exact host, human client, service identities, custody,
anchor and effective-access choices required before any canary installation.

## Protected mechanism checkpoint (9 October 2026)

The [TLS experiment](tls-transport.md) now carries the existing approved canary
delivery through actual mutually authenticated TLS 1.3 records. The
[input/import experiment](protected-entry.md) adds bounded zeroizing input and
ciphertext-only no-clobber publication. The [recipient child](recipient-process.md)
loads its own role material and uses the existing durable reservation/receipt
path across process boundaries. These remain separate fixed-fixture experiments;
an operational protected human-to-recipient service is not available.

Integrated local checks passed all 293 library tests, 26 doctests, formatting,
Clippy and rustdoc. All three examples and the legacy default CLI demo passed.
Full local default/all-feature runs produced 156/393 passes plus the same 14
restricted listener failures and no ignored tests. The later exact-head hosted run passed 170 default and 407 all-feature tests,
including all listener cases; see [verification](verification.md).

The recipient explicitly reports UNISOLATED because it shares the development
UID and host control plane. The operator-controlled Linux host, independently
authenticated human client, operational enrollment/custody/recovery, external
anchor, actual provider adapter and required assurance remain open. No real-key
entry, access change, deployment or live provider call has been enabled.

## Previous custody checkpoint (8 October 2026)

The separate-role custody path now drives the existing authenticated durable vault/protocol without loading an all-role fixture kit. It exercises exact signed approval, delivery, cold rotation and revoke; the deployment-prerequisite API remains report-only NO-GO. The first use case remains a GitHub App limited to selected personal repositories, with no organization access; see the [operator trial plan](operator-live-trial-plan.md).

Current-source local checks passed 252 library tests, 21 doctests, formatting, Clippy and rustdoc. Full default/all-feature totals are 155/350 passes plus the same 14 listener failures. Separate-process custody create/inspect passed. No external-host verification or live provider activation was performed for this increment. The [verification record](verification.md#separated-custody-and-report-only-deployment-checkpoint-2026-10-08) separates these results from the older pilot pass. Real-key entry remains unavailable.

## Previous adapter checkpoint (7 October 2026)

The recovered 4979ae3 runtime is the starting point for three independent fixed-fixture adapter increments: metadata-only operator-entry ceremony, immutable recipient handoff/receipt handling, and peer-bound bounded framing over existing protocol handlers. Their tests establish executable contract behavior only. Generic key entry, protected custody, a live authenticated transport, independent human interaction and the operating boundary remain absent. The recipient fixture is not integrated into the durable runtime.

[Source provenance](source-recovery-2026-10-07.md) records the verified archive and the missing original unpublished commit history. The stopped independent review remains incomplete. The integrated runtime passes all 225 all-feature library tests, 16 doctests, formatting, Clippy and rustdoc. Full local aggregates retain the same 14 listener failures. The immutable-source Linux pilot passed all 169 default and 337 all-feature tests, all 21 Unix cases in both configurations, 16 doctests, the quality checks, the adapter drill and separate-process inspection. See [verification](verification.md#recovered-adapter-foundation-checkpoint-2026-10-07).

## Implemented

- An optional [integrated synthetic vault-to-recipient path](vault-delivery-spike.md): actual signed actor verification, exact ACLs, proof-gated main-core review/dispatch, encrypted fixed records/capsules, recipient acknowledgement, rotation and durable cold-start/revocation. No generic real-key input, HTTP service, human-presence or isolated-recipient claim.

- An optional [disposable-key signing experiment](signing-spike.md) using maintained RSA/JWT libraries, private exact-bound sign-only leases and safe reports. No persistent/imported keys or default dependency expansion. The subsequent [approval-bound composition](github-signed-composition.md) joins it to the synthetic broker only through an explicit optional constructor.

- Canonical typed inputs, exact profile/resource/credential/output bindings, stable errors, and bounded safe status projections.
- Separate trusted control and bound agent handles, frozen grants, monotonic idle/max limits, bounded retention/concurrency, atomic reservation/revocation, cancellation and retained idempotent outcomes.
- A [versioned GitHub metadata operation in the main broker](github-broker.md), with exact reviewed control approval, shared budget/dedup/revoke policy, explicit V2 JSON/MCP and broker-bound schema-2 journal context. Legacy issue-status interfaces remain compatible; real access is unavailable.
- A Unix-only [synthetic GitHub intent journal](github-intent-journal.md), with sync-before-effect records, strict read-only recovery, consumed reservations and zero restored grants/sessions. It stores no credentials and assumes trusted storage.
- A separate fixed-fixture [GitHub App adapter exercise](github-app.md): personal selected-repository binding, metadata-only mock token exchange, safe metadata projection, expiry/refresh, retained uncertainty and explicit mock provider revocation. No live adapter, key input or protocol tool.
- A fixed fake status provider with synthetic credential material; no network or generic execution/proxy route.
- Strict bounded JSON-lines, an explicitly started Unix foreground broker and a thin stdio MCP client using the same policy engine.
- An optional fixed-fixture age recovery experiment with saved-kit fresh-process recovery, disabled restored grants and no retained sessions. It accepts no real credential input.
- Architecture/threat contracts, developer/agent quickstarts, ADRs, security-policy draft, roadmap and dependency inventory.

## Observed checks

The macOS 26.6.2 arm64 source checkpoint passed 85 default tests and 99 all-feature tests, formatting, all-target/all-feature Clippy with warnings denied and all-feature rustdoc with warnings denied. Focused reviewers reproduced and checked lifecycle, approval, framing, duplicate-key and slow-client regressions; this was not a security audit. Clean-copy quickstarts and a copied release executable passed synthetic workflows without a checkout or child environment.

The later Linux GitHub preparation checkpoint passed all 31 new tests, the non-listener suites, formatting, Clippy, rustdoc and a clean all-feature/all-target build. Default/all-feature aggregates report 102/116 passes respectively plus 14 existing Unix-interface failures caused by denied listener binding (`EPERM`). The [quality script](../scripts/check.sh) therefore does not pass in this Linux context; the original Mac result is historical and does not cover the new code. See [verification](verification.md), [review remediation](review-checkpoint.md), [quickstart verification](quickstart-verification.md), and [standalone binary](standalone-binary.md).

The subsequent synthetic journal checkpoint passed 56 GitHub tests (31 adapter tests plus 25 journal/fault tests), including injected write/sync failures and nine fresh-process crash points. Final default/all-feature totals are 127/141 passes respectively, plus the unchanged 14 listener-binding failures. Clean builds, both journal processes and the focused independent review passed. This adds retained synthetic facts, not protected operational persistence or restored authority.

The latest main-broker integration passed 71 library tests, 9 V2 integration tests and all runnable legacy suites. Default/all-feature totals are 151/165 passes plus the same 14 Unix listener failures. Formatting, Clippy, rustdoc, examples, clean builds and focused independent review passed. New V2 foreground wiring is compiled; end-to-end listener behavior is still unverified on this host.

The optional signing increment adds 23 passing disposable-key tests. Default/signing-only/all-feature totals are 151/174/188 passes with the unchanged 14 listener-dependent failures. Formatting, Clippy, rustdoc, both visibility doctests and the safe-report example pass. Default and storage-only dependency graphs are unchanged; native signing dependencies are opt-in.

The approval-bound composition adds 22 passing tests. Default/signing-only/all-feature totals are 151/196/210 passes with the same 14 denied listener tests. Five visibility doctests, formatting, Clippy, rustdoc and the signed broker example pass. No dependency or lockfile change is made.

The private Linux synthetic pilot subsequently passed all 169 default and 228 all-feature baseline tests on `e353a6b`, including all 21 interfaces, plus actual GitHub foreground/MCP v2 workflow. Same-UID negative tests still demonstrate that administrative access and automated terminal control are not protected human/secret boundaries. The new integrated vault candidate has 41 focused tests; its independent review/platform checkpoint is separate.

## Access-control design update

The [vendor-neutral access contract](access-control.md) and ADR 0013 define authenticated application identity, exact deny-by-default ACLs, separate human administration and optional operator-managed private networking. Four additional wire/core acceptance tests reject identity/network/proxy/ACL claims and preserve exact review/revocation. These are existing-protocol regressions; remote authentication, HTTP/TLS, proxy trust and configurable ACL enforcement remain unimplemented. Current default/all-feature totals are 155/214 passes with the same 14 listener failures; formatting, Clippy, rustdoc and five doctests pass. Runtime source and dependencies are unchanged.

## Request-driven product flow

[ADR 0014](adr/0014-request-driven-delivery-lifecycle.md) clarifies episodic project setup and secret delivery/rotation as the primary workflow, compatible with waking on request and becoming idle afterward. Recipients may use their providers directly; bounded API mediation is optional. Durable approval/revocation/use state and cold-start/restore enforcement remain unimplemented. The later private Sprite pilot is approved for bounded synthetic development; it has no production approval. This lifecycle design does not itself change runtime or test results.

## Readiness decision

Synthetic preparation now has a composed approval/journal/signing/mock-provider path. Remote activation and real-key deployment remain gated by the [consolidated readiness and deployment decisions](readiness-checklist.md); the separately authorized architecture/acceptance increment does not activate those capabilities. A real GitHub App private key must not be entered into the current workspace.

## Remaining gates

The required [application-delivery design](application-delivery.md) now specifies reference-only proposal/approval/delivery/status/revocation, immutable recipient and protected configuration bindings, direct protected destinations, fail-closed OS separation, ambiguous handoff reconciliation and distinct revocation effects. The application-delivery contract remains design work only. The GitHub synthetic increments add Rust and tests for their narrower provider boundary; the separate optional signing experiment adds cryptographic dependencies without changing the default graph. None implements protected delivery. The [delivery backlog](roadmap.md#d--protected-application-delivery) requires enforcement spikes and adversarial platform tests before implementation claims.

Protected application delivery and recipient enrollment, independent human/agent integration, real-agent host testing, native lifecycle faults, actual OS separation, operational storage transactions/rekey/recovery, protected durable handoff/budgets, reference age CLI interoperability, other platforms, supply-chain/unsafe review and independent security composition review remain open. Same-account control is workflow separation, not containment. See [roadmap](roadmap.md).
