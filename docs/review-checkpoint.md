# Independent review and remediation checkpoint

Recorded October 6, 2026, approximately 03:05 UTC. Two separate read-only reviewers inspected the initial synthetic implementation, reproduced defects in isolated scratch harnesses, and reviewed the fixes. A third worker ran the documented workflows from a clean disposable copy with a separate fresh build directory. This is focused correctness and maintainability evidence, not a security audit.

## Findings and fixes

| Reproduced finding | Resulting behavior | Regression evidence |
| --- | --- | --- |
| Late approval could expire a dispatched request or overwrite success, cancellation, or `outcome_unknown` | Expiry changes only pre-dispatch states; late control approval rejects without rewriting history; accepted completion has a consistent result/error | `review_regressions`: active dispatch, each terminal outcome, cancellation after deadline |
| A frozen bounded grant followed a new policy generation when profile fields matched or were restored | The original grant generation is immutable; fresh requests reject changed generations | `generation_change_never_reactivates_a_frozen_bounded_grant` |
| Repeated preparation returned an expired pending request as still prepared/approved | Deduplication observes pre-dispatch expiry before returning stored state | `duplicate_prepare_observes_expiry_without_a_prior_status_poll` |
| CLI compared the review before reacquiring the approval lock | `approve_reviewed` compares the canonical plan, handle and remaining budget and approves under one lock; CLI uses this method | Stale budget rejection and exact-handle regressions, existing subprocess budget test |
| Equal local counters permitted a review from another broker instance in the embedding API | Control-only approval views include a private random 128-bit instance binding from the existing `getrandom` dependency | Cross-instance rejection/origin acceptance regression |
| Byte trickles held all eight connection slots past a nominal one-second read timeout | Each frame has an absolute one-second read deadline independent of partial progress | Eight-slot trickle test followed by a healthy connection |
| MCP `Value` parsing silently collapsed nested duplicate keys | A recursive serde visitor rejects duplicate decoded member names before tool mapping | Duplicate top-level/nested/escaped-equivalent keys; zero bridge calls |
| Complete JSON without LF was executed at EOF | Operation/MCP/control/greeting/response readers require LF; frame byte limits include it | Incomplete-EOF tests across all five readers and exact/over-limit boundaries |
| MCP conflated invalid JSON with invalid requests and explicit null IDs with notifications | JSON syntax and request-shape errors have distinct codes; explicit null MCP IDs are rejected | Malformed JSON, invalid shapes/null IDs, absent-ID notification and parser-depth tests |
| Documented startup assumed the default build directory and short checkout paths | Quickstarts use Cargo commands and a short canonical temporary parent; socket paths over 100 bytes reject before creation | Clean-copy checks with external `CARGO_TARGET_DIR`; overlong-path regression |

The first six newly added lifecycle regressions failed against the initial implementation before the fixes. Reviewers independently confirmed the corresponding reproductions. Two newly written fake-peer EOF fixtures initially failed because immediate peer destruction caused an I/O/identity error; clean write-half shutdown while retaining the peer made the intended incomplete-EOF assertions deterministic. Their corrected tests pass.

## Validation

The complete offline [quality script](../scripts/check.sh) passed with the pinned Rust 1.96.1 toolchain on macOS 26.6.2 arm64. Recorded outcomes were:

- Default: **85 tests** — 37 policy, 12 protocol/MCP, 21 subprocess/interfaces, 9 lifecycle/approval review regressions, and 6 framing/parser regressions.
- All features: **99 tests**, including 14 fixed synthetic age/recovery tests.
- Formatting, all-target/all-feature Clippy with warnings denied, and all-feature rustdoc with warnings denied.
- Reviewers separately reran 37 policy + 9 review regressions and 21 interfaces + 12 protocol + 6 framing/parser tests.

The [clean-copy quickstart record](quickstart-verification.md) also passed the revised documented commands from a fresh external build.

The initial implementation had 78 passing tests. Review remediation added 21 regressions without changing dependency versions or feature resolution. Machine-specific raw logs and private history are not distributed.

## Interpretation and remaining gates

`approve_reviewed` is a trusted host capability, not proof that a human acted. The lower-level `approve` remains available for explicitly trusted embeddings and does not validate a displayed review. Approval views are instance-local and are not serialized onto the agent wire. A changed policy generation requires a newly authorized broker session; restoring old profile fields does not reactivate the grant.

A dispatched invocation may return its already authorized validated completion after revocation or session expiry. It cannot revive expired authority, and later lookup/replay still requires a valid session. Neither request expiry nor transport read deadlines bound a trusted executor's actual execution duration. Write timeouts are per syscall; they are not a total execution deadline.

Same-account code can reach or automate control. This work establishes no separate-identity containment, protected human presence, native lock/suspend handling, durable budgets, live-provider safety, production recovery, Linux/Windows coverage, reference age CLI interoperability, complete supply-chain review, or comprehensive security composition review. Those gates remain in [verification](verification.md) and [roadmap](roadmap.md). First-party source is licensed under MIT; that does not satisfy the outstanding production/security gates. The required [application-delivery design](application-delivery.md) adds enforcement and review gates; this earlier focused review did not test or establish protected delivery.

## GitHub synthetic preparation review (2026-10-06)

A separate focused read-only reviewer assessed the private GitHub fixture code and updated contracts, then reran the final 31 GitHub tests. Four concrete lifecycle issues were corrected before this checkpoint:

1. A final invalid clock could overwrite a known unknown outcome. Preserve the uncertainty and exact-bound replay while preventing new effects.
2. Clock observations during the exchange/read path were compared only with reservation time. Track each latest observation, merge it with state time, and make regression sticky.
3. Anchoring elapsed expiry at token receipt could extend authority while UTC stalled during exchange. Anchor to exchange start and reject an already-expired receipt before use.
4. A panic immediately after a successful mint could drop its receipt before retention. Store the issued envelope before further fallible processing, and preserve uncertainty while validating it.

Regressions cover each issue, plus successful revocation of an older token while an unknown refresh remains unresolved. The reviewer found no remaining blocking issue in the fixed synthetic-only scope. This was correctness review, not a security audit or authorization for live keys. Linux counts and the existing listener-binding `EPERM` limitation are recorded separately in [verification](verification.md#linux-github-preparation-checkpoint-2026-10-06).

## Synthetic intent-journal review (2026-10-06)

A separate read-only reviewer assessed the durable GitHub fixture increment and independently reran all 56 GitHub tests. Four findings were fixed:

1. The creation drill discarded an uncertain provider-revocation status. It now requires `ProviderConfirmed`; incomplete outcomes cannot print success.
2. An in-memory revoked flag could make a failed durable local revocation return success on a later call. Its persistence failure is now sticky.
3. Serde's internally tagged unit variant accepted unknown fields on `revoke_authority`. An empty struct variant now rejects them, with specific unknown/duplicate-field regressions.
4. Replay allowed a new reservation after an outcome that the runtime permanently blocks. Persisted terminal blocked state now rejects subsequent reservations, including unknown and quarantined-receipt cases.

The implementation also explicitly releases the writer lock at owner drop so an unrelated concurrent process launch cannot temporarily extend its lifetime through an inherited open-file description. Regression tests cover that case, all write/sync fault stages and real subprocess exits. The reviewer found no remaining blocker in the fixed synthetic scope. No live-key readiness, authenticated storage, rollback resistance or device-power-loss guarantee follows from this review.

## Versioned core GitHub review (2026-10-06)

A separate reviewer assessed unified core authority, V1 compatibility, private one-shot dispatch, V2 protocol/MCP and schema-2 binding. Findings addressed before completion:

1. The schema-1 adapter operation ID used an underscore while the approved V2 broker ID uses a hyphen. Schema 2 now records and validates the exact approved ID; schema 1 retains its original spelling.
2. Main-broker time checks hid a retained static GitHub unknown receipt after expiry/rollback/stop. A same-session/handle, Github-only unknown-status path now preserves it without result data or renewed authority; legacy behavior remains unchanged.
3. New legacy wrapper guards changed missing-handle error precedence. Missing handles now proceed through canonical session/revocation checks while actual GitHub handles are still rejected before mutation.

The resolved V2 review includes complete grant/session/request limits. Schema 2 records actual context and separately records reviewed and consumed budgets; it does not prove authenticated human consent or every historical idle decision. The reviewer reran updated library/V2/legacy suites and Clippy successfully, with no remaining blocking authority/durability finding. Unix listener workflows and live composition remain outside verified coverage.

## Optional signing-source review (2026-10-06)

A separate read-only reviewer assessed the optional sign-only source, cryptographic library configuration, strict claims, lifecycle/clock/concurrency behavior, dependency inventory and matching contracts. Two hardening suggestions were incorporated: wrap an encoded JWT before the size-check error branch so cleanup also applies there, and revoke/clear key material when the owning source drops even if private lease references survive. A new owner-drop regression verifies future signing is denied while an already issued JWT remains valid.

The reviewer independently reran all 23 signing tests and both visibility doctests, matched all four saved dependency inventories against fresh Cargo metadata, checked artifact sizes and final documentation, and found no remaining blocking issue in this synthetic-only scope. This does not audit native dependencies, establish memory isolation, authenticate a human or authorize live composition. Full Linux regression totals and the unchanged listener-binding failures are recorded in [verification](verification.md#linux-optional-signing-checkpoint-2026-10-06).

## Approval-bound signing review (2026-10-06)

A separate read-only reviewer assessed the composed authority path, exact review/budget binding, durable ordering, one-shot ownership, credential non-export, cached-token independence, timing, panic/crash behavior, constructor failure and readiness/deployment documentation. The review identified an extra pre-sign clock observation that could detect a regression without making the source invalidation sticky. The source now samples once under its signing mutex, checks a reservation floor before crypto and returns the exact checked stamp. The adapter separately samples current exchange time after mint-intent sync and retains the latest observation. Scripted-clock, reservation-floor and slow-sync expiry/rollback regressions cover the correction.

The review also made two semantics explicit: existing cached tokens do not require a fresh unlocked signing source, and crypto initialization failure can leave a header-only new journal directory but returns no broker handles or authority. Dedicated tests cover both. A new recovery test initially expected reconciliation for a known pre-provider clock denial; it now checks the existing schema's zero unresolved-effect/no-retry/no-restored-authority behavior instead of redefining recovery semantics.

The reviewer independently reran 116 signing-feature library tests and five visibility doctests, reviewed final contracts/ADR0012/readiness checklist and found no remaining blocking findings. This is a focused correctness review, not a native-library or security-composition audit. The complete regression counts, clean-build evidence and unchanged 14 listener restrictions are tracked in [verification](verification.md#linux-approval-bound-signing-checkpoint-2026-10-06).

## Vendor-neutral application access review (2026-10-07)

A separate read-only reviewer checked ADR 0013, the access-control/readiness contracts and four new existing-protocol/core regressions. Review focused on distinguishing future default-deny remote ACLs from the current fixed synthetic grant; stable authenticated issuer/subject enrollment; separate API and operational credentials; closed bootstrap and independent human administration; exact rules without partial-match union; authenticated proxy/backend hops and stripping; and verified private IPv4/IPv6 exposure. The reviewer checked the cited NIST/RFC principles and found no blocking finding or implementation overclaim.

The reviewer suggested including accepted MCP capability/title metadata as well as client names; the tests now demonstrate that these claims do not change the host-bound principal or establish approval. The reviewer independently reran all four new tests and checked the diff. No runtime source or dependency changed. Real HTTP/authentication/ACL/proxy/private-network acceptance remains unimplemented and unverified; [the matrix](access-control.md#acceptance-matrix-and-current-evidence) labels those future gates explicitly.
