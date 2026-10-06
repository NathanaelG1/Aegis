# ADR 0004: Age and independent recovery gate

**Status:** Synthetic feasibility spike implemented; operational backend and transaction layout pending. **Date:** 2026-10-06.

## Context

Portable encrypted recovery is required, but a synthetic demo does not justify storing a real credential. Multi-file rekey and restored authority create risks beyond encryption interoperability.

## Decision

Use an established released Rust `age` implementation when the backend is added. Do not implement custom cryptography. Plan a bounded full snapshot encrypted to the local X25519 recipient and an independently held recovery recipient; protect the local private identity with passphrase encryption.

Gate persistent real-secret setup on `uninitialized -> pending_recovery -> ready`. Verification requires a fresh process restoring the saved snapshot with independently saved recovery material. Restore uses a new destination and disables all grants/sessions. A changed recovery recipient requires a new kit/drill.

Keep manifest/catalog non-authoritative. Recipient encryption is not authorized-writer provenance. Retain owner-controlled live storage and explicitly document rollback/backup limits.

## Consequences

The current broker has no operational persistent setup or recovery-ready claim. The separate spike successfully restores only its saved fixed fixture using a saved recovery key in a fresh process, disables persisted grants, and clears sessions. It does not authorize real values, implement identity passphrase custody, or become broker authority. Operational age version/features, resource limits, dependency review, custody lifetime, commit/rekey arrangement, and support matrix remain open.

The optional `storage-spike` feature selects age 0.11.1 with default features disabled for feasibility work. Its primary documentation labels pre-1.0 releases as beta/testing-only. This version selection does not approve a production backend or complete the resolved-per-target dependency review.

See [storage-spike.md](../storage-spike.md) for the 14 integration tests, executable bounds, filesystem evidence, and exact remaining gaps.

## Spike before storage promises

Test standard age interoperability, full final-chunk validation, corruption/truncation, resource/header limits, missing/wrong independently saved recovery material, canceled setup, fresh-process restore, and per-platform crash points. Demonstrate usable old/new matching identity/snapshot pairs before freezing multi-file rekey design. No shared/network filesystem support is assumed.
