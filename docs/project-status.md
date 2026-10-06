# Project status

Aegis is an experimental synthetic-only capability broker. Source and documentation are licensed under MIT; no production secrets product, live provider, protected approval channel or audited release is available. Protected agent-blind application delivery is required but not yet implemented or verified.

## Implemented

- Canonical typed inputs, exact profile/resource/credential/output bindings, stable errors, and bounded safe status projections.
- Separate trusted control and bound agent handles, frozen grants, monotonic idle/max limits, bounded retention/concurrency, atomic reservation/revocation, cancellation and retained idempotent outcomes.
- A fixed fake status provider with synthetic credential material; no network or generic execution/proxy route.
- Strict bounded JSON-lines, an explicitly started Unix foreground broker and a thin stdio MCP client using the same policy engine.
- An optional fixed-fixture age recovery experiment with saved-kit fresh-process recovery, disabled restored grants and no retained sessions. It accepts no real credential input.
- Architecture/threat contracts, developer/agent quickstarts, ADRs, security-policy draft, roadmap and dependency inventory.

## Observed checks

The macOS 26.6.2 arm64 source checkpoint passed 85 default tests and 99 all-feature tests, formatting, all-target/all-feature Clippy with warnings denied and all-feature rustdoc with warnings denied. Focused reviewers reproduced and checked lifecycle, approval, framing, duplicate-key and slow-client regressions; this was not a security audit. Clean-copy quickstarts and a copied release executable passed synthetic workflows without a checkout or child environment.

The current publication snapshot is checked with the same [quality script](../scripts/check.sh). See [verification](verification.md), [review remediation](review-checkpoint.md), [quickstart verification](quickstart-verification.md), and [standalone binary](standalone-binary.md).

## Remaining gates

The required [application-delivery design](application-delivery.md) now specifies reference-only proposal/approval/delivery/status/revocation, immutable recipient and protected configuration bindings, direct protected destinations, fail-closed OS separation, ambiguous handoff reconciliation and distinct revocation effects. This is design work only: no Rust source, dependencies, executable behavior or test cases changed. The [delivery backlog](roadmap.md#d--protected-application-delivery) requires enforcement spikes and adversarial platform tests before implementation claims.

Protected application delivery and recipient enrollment, independent human/agent integration, real-agent host testing, native lifecycle faults, actual OS separation, operational storage transactions/rekey/recovery, protected durable handoff/budgets, reference age CLI interoperability, other platforms, supply-chain/unsafe review and independent security composition review remain open. Same-account control is workflow separation, not containment. See [roadmap](roadmap.md).
