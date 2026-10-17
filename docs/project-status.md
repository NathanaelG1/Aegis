# Project status

Aegis is an experimental synthetic-only capability broker. Source and documentation are licensed under MIT; no production secrets product, live provider or audited release is available. The opt-in owner-controlled Sprite experiment now provides separate owner/agent credential authentication and exact approval; deployed client/admin isolation and physical human presence remain unverified. Protected agent-blind application delivery is required but not yet implemented or verified.

## Implemented

- Canonical typed inputs, exact profile/resource/credential/output bindings, stable errors, and bounded safe status projections.
- Separate trusted control and bound agent handles, frozen grants, monotonic idle/max limits, bounded retention/concurrency, atomic reservation/revocation, cancellation and retained idempotent outcomes.
- A fixed fake status provider with synthetic credential material; no network or generic execution/proxy route.
- Strict bounded JSON-lines, an explicitly started Unix foreground broker and a thin stdio MCP client using the same policy engine.
- An optional fixed-fixture age recovery experiment with saved-kit fresh-process recovery, disabled restored grants and no retained sessions. It accepts no real credential input.
- Architecture/threat contracts, developer/agent quickstarts, ADRs, security-policy draft, roadmap and dependency inventory.
- Optional Unix `sprite-demo` HTTP service, private generation of separate role credentials and a fake provider key, exact one-use owner review receipts, explicit restart-instance binding, Python role clients/agent-only stdio MCP bridge, sanitized audit counters, and a reproducible fresh-key output-disclosure evidence harness. See [setup/evidence](sprite-demo.md) and [ADR 0008](adr/0008-owner-controlled-sprite-demo.md). Provisioning/deployment/gateway remain owner-managed.

## Observed checks

The October 17 owner-controlled fake-secret extension passed 85 default/101 all-feature Rust tests, formatting, all-feature Clippy/rustdoc with warnings denied, a release build and 111 fresh-key HTTP/MCP workflow assertions. Saved [evidence](../Evidence/sprite-demo-local-2026-10-17/report.json) includes binary/source hashes and explicit limits. This is local macOS evidence; no Sprite/Linux deployment, TLS gateway, protected client custody or OS/admin isolation was verified. See the current [verification extension](verification.md#october-17-2026-owner-controlled-fake-secret-httpmcp-extension).

The macOS 26.6.2 arm64 source checkpoint passed 85 default tests and 99 all-feature tests, formatting, all-target/all-feature Clippy with warnings denied and all-feature rustdoc with warnings denied. Focused reviewers reproduced and checked lifecycle, approval, framing, duplicate-key and slow-client regressions; this was not a security audit. Clean-copy quickstarts and a copied release executable passed synthetic workflows without a checkout or child environment.

The current publication snapshot is checked with the same [quality script](../scripts/check.sh). See [verification](verification.md), [review remediation](review-checkpoint.md), [quickstart verification](quickstart-verification.md), and [standalone binary](standalone-binary.md).

## Remaining gates

The required [application-delivery design](application-delivery.md) specifies reference-only proposal/approval/delivery/status/revocation, immutable recipient and protected configuration bindings, direct protected destinations, fail-closed OS separation, ambiguous handoff reconciliation and distinct revocation effects. That delivery feature remains design work only. The Sprite operation demo changes Rust/Python behavior but implements no protected recipient or secret handoff. The [delivery backlog](roadmap.md#d--protected-application-delivery) requires enforcement spikes and adversarial platform tests before delivery implementation claims.

Protected application delivery and recipient enrollment, independent human/agent integration, real-agent host testing, native lifecycle faults, actual OS separation, operational storage transactions/rekey/recovery, protected durable handoff/budgets, reference age CLI interoperability, other platforms, supply-chain/unsafe review and independent security composition review remain open. Same-account control is workflow separation, not containment. See [roadmap](roadmap.md).
