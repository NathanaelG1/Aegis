# Project status

Aegis is an experimental synthetic-only capability broker. Source is public under MIT; no production secrets product, live provider, protected approval channel or audited release is available.

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

Protected human/agent integration, real-agent host testing, native lifecycle faults, separate identities where required, operational storage transactions/rekey/recovery, durable budgets, reference age CLI interoperability, other platforms, supply-chain/unsafe review and independent security composition review remain open. Same-account control is workflow separation, not containment. See [roadmap](roadmap.md).
