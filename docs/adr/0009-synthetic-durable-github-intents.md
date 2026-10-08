# ADR 0009: Synthetic durable GitHub intents

**Status:** Implemented synthetic file experiment; operational protected persistence remains gated. **Date:** 2026-10-06.

## Context

The GitHub fixture previously lost all reservation and provider-outcome evidence on process exit. A future real mint or revoke must not be silently repeated after a crash. Operational key storage, writer authenticity, protected approval and OS deployment have not been established.

## Decision

Add a Unix-only append/sync journal to the private fixed GitHub fixture. Persist exact synthetic enrollment/permission/approval revision/epoch bindings, consumed reservation and per-effect intent before a mock provider call; persist completion before success. Identify tokens by broker-assigned mint-attempt IDs, never by token values/hashes. Store no credential material. Serialize reservations against local revocation and hold a lifetime OS file lock; poison the writer after any persistence uncertainty.

Expose only a fixed create drill and read-only inspection. Existing destinations cannot resume execution. Restore zero grants/sessions, keep reservations consumed, retain unknown operations/mints/revocations and require reconciliation for issued-but-unrevoked tokens. Reject malformed, partial, unsupported or semantically inconsistent logs without repairing a tail. Internally valid complete prefixes remain conservative crash evidence.

Assume trusted local storage and namespace: no authenticated-writer, tamper-proof, rollback-resistant or hostile same-UID property is claimed. No checksum/custom cryptography is added. New-file modes, locks and path checks are not an OS containment boundary. Test ordering, partial writes, sync acknowledgement failures, actual subprocess exits, concurrency, corruption and clock changes; do not claim device-power-loss or cross-platform durability.

## Consequences

This extends ADR 0003's invariant experiments with retained synthetic facts; it does not restore production authority or replace the main broker. ADR 0004's protected operational custody/recovery gate and ADR 0007's isolated delivery requirements remain unmet. Real reconciliation, key provisioning, live transport and independently authenticated approvals are unimplemented. The full [journal contract](../github-intent-journal.md) and [verification evidence](../verification.md) define the boundary.
