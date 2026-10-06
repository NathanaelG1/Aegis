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

Same-account code can reach or automate control. This work establishes no separate-identity containment, protected human presence, native lock/suspend handling, durable budgets, live-provider safety, production recovery, Linux/Windows coverage, reference age CLI interoperability, complete supply-chain review, or comprehensive security composition review. Those gates remain in [verification](verification.md) and [roadmap](roadmap.md). First-party source is now public under MIT; that does not satisfy the outstanding production/security gates.
