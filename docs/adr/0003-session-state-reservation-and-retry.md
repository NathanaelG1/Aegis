# ADR 0003: Session state, reservation, and retry

**Status:** Accepted for one in-memory broker process. **Date:** 2026-10-06.

## Context

Concurrent callers can overrun a final use if checking and decrementing are separate. A retry can duplicate an external effect when receipt is lost. A revision can broaden approved authority if plans follow a mutable reference.

## Decision

Freeze exact profile, resource, credential, implementation, result contract, and policy generation bindings. Bind concrete typed parameters to prepared requests. Deduplicate within the host-bound session using caller request ID; changed inputs are a conflict.

Serialize authorization, remaining-use reservation, dispatch state, and revoke in the same broker-owned synchronization domain. Execute the provider outside the lock. Once dispatch commits, preserve consumed authority even on failure or uncertainty; no transparent refund/repeat is defined.

Use bounded volatile sessions/counters initially. Restart requires new trusted authorization. Denied calls and polling do not extend idle lifetime; maximum lifetime never extends. Reject stale/expired authority at dispatch.

The Unix broker generates a random 128-bit epoch, and an existing bridge rejects a changed epoch after restart. All current socket clients share one host-bound session and its counters. The epoch prevents accidental bridge continuity across reused numeric handles; it is not an authorization token or defense against malicious same-account code.

## Consequences

At most one concurrent request can reserve a final use. A post-dispatch revoke cannot retract the already started effect. Local deduplication does not promise exactly-once external effects or persistence across crashes.

## Unresolved work

Durable budgets require a tested pre-effect journal and rollback/privacy/consistency design. Provider writes require idempotency/reconciliation. Executor timeouts, lifecycle loss, and platform suspend/lock behavior need separate enforcement tests.
