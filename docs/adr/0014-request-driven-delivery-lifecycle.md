# ADR 0014: Request-driven setup, delivery and rotation

**Status:** Accepted product/deployment design; delivery and wake lifecycle unimplemented. **Date:** 2026-10-07.

## Context

The primary use is episodic project setup and secret delivery/rotation. Aegis need not remain in the path of every ordinary application API call. Deployment should accommodate a broker that wakes for an authorized request and becomes idle afterward, without losing revocation, approval or consumption history.

## Decision

Prefer a wake-on-request-compatible lifecycle for the protected delivery product. Authenticate and revalidate current policy/recipient/credential state after wake; obtain independent human approval where required; durably reserve and record handoff/rotation outcomes before reporting success or becoming idle. The recipient may then call its provider directly while the broker is idle. Bounded broker-mediated API operations remain a separate optional mode; there is still no arbitrary proxy or secret-export route.

Persist protected revocation, approval-decision, use/reservation and delivery/rotation evidence across cold starts. Authenticate state and reject missing/corrupt/stale or rolled-back recovery; serialize simultaneous wakes using a durable single-writer/fencing arrangement. A fresh process creates a fresh epoch/session and reauthenticates/revalidates. Persisted decisions do not automatically revive old sessions or instance-bound approvals. Any approval intended to survive cold starts requires an explicitly reviewed durable scope/schema and current revalidation; until that exists, require fresh approval. Unknown handoffs remain consumed and cannot be repeated or refunded.

Sleeping, stopping or revoking a broker grant cannot retract a credential already delivered. Recipient/provider expiry, local cleanup and separately authorized provider revocation/rotation determine downstream validity. Renewal of short-lived credentials may require additional wakes; no uninterrupted-use or instantaneous-revocation promise follows from this lifecycle.

## Consequences

Vendor-neutral application authentication/ACLs and optional operator-managed private networking from ADR 0013 remain the default. Sprites is only a deployment candidate, neither selected nor approved; no wake, persistence, isolation, latency or cost property of it is asserted here. A hosting candidate must prove the same custody, cold-start, durable-state and exposure gates. Current synthetic foreground processes and inspection-only recovery remain unchanged. See [the delivery lifecycle](../application-delivery.md#request-driven-lifecycle) and [deployment readiness](../readiness-checklist.md).
