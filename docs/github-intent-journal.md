# Synthetic GitHub intents and restart inspection

**Status: synthetic local-file experiment, not protected operational persistence.** The GitHub mock can now write an append-only intent journal before simulated effects and inspect it in a fresh process without resuming authority. No real credentials, valid JWT, provider networking, human authentication, operational recovery or OS isolation is enabled.

```sh
# Use a new directory below an existing canonical absolute parent.
cargo run --locked --offline --example github_intent_spike -- create /absolute/test-parent/new-journal
# Run after the creating process exits.
cargo run --locked --offline --example github_intent_spike -- inspect /absolute/test-parent/new-journal
```

Only fixed fictional GitHub enrollment and mock operations are accepted. `create_synthetic_intent_drill` creates a new directory and performs one mock metadata operation followed by explicit mock token revocation. `inspect_synthetic_intents` is read-only: it returns counts/categories, zero restored grants/sessions and `automatic_retry_allowed: false`. There is no reopen-for-execution, repair, refund, reset, retry or reauthorization method. Existing destinations are never overwritten or reused for execution. A new fixture directory is a new synthetic experiment, not permission to retry a real operation.

## Stored data and authority

`intents.jsonl` contains bounded JSON-lines records with schema version, contiguous sequence number and a closed event type. It stores only:

- Fixed App/client/installation IDs, account numeric ID/login/User type, selected repository ID/name/owner, signer reference/version and binding revision.
- Explicit Contents/Metadata permission ceiling, metadata-only requested scope, operation/output version, random fixture epoch and fixed simulated approval revision.
- Request ID, reservation time/approval deadline, broker-assigned mint-attempt references, reported token expiry and closed lifecycle/revocation categories.

No private key, signed JWT, installation token, token hash, provider response body, metadata text or enabled grant/session is persisted. Mint-attempt IDs identify issuance attempts independently of token bytes. Cached reads refer to the original mint; overlapping refreshed tokens retain distinct issuance references.

The fixed approval revision and epoch are bookkeeping, not human consent or cryptographic signatures. Files cannot become authority: parsing validates the exact synthetic fixture and returns only an inspection report. The later [core integration](github-broker.md) preserves issue-status and wire version 1 while adding explicit V2 GitHub requests and broker-bound journal schema 2. The private GitHub fixture follows its reservation/revoke/dedup invariants; a production provider must still integrate the versioned operation contract with the main broker.

## Write ordering and file ownership

On Unix, create a new mode-0700 directory and a new mode-0600 regular single-link file with no-follow/close-on-exec flags. Hold an OS-backed exclusive file lock for the writer's entire lifetime. Inspection takes a compatible shared lock and refuses while a cooperating writer is active. The lock is on the journal inode; no separate stale lockfile is used or removed. Explicit unlock at owner drop avoids briefly inherited open-file descriptions keeping the lock alive during concurrent process launch.

Before the runtime is attached, sync the header/file, new directory and its existing parent. Before a reservation can lead to effects, append and `sync_all` its record. Append and sync each mint/read/revoke intent before that provider call. Persist the corresponding completion before claiming success. The runtime's authorization/reservation/revocation lock orders the reservation against local revocation; the provider runs outside it, so already-reserved work may finish after revocation.

The journal's mutex orders appends and its state-machine validation. A write, sync, invalid transition, or size failure permanently disables that writer. Failed durable local revocation remains a failure on repeated calls; the fixed creation drill requires confirmed provider revocation and never reports completion for an uncertain revoke. It never truncates a failed tail, rolls back a reservation, retries an effect, or refunds authority. A failure before dispatch prevents the call; a failed terminal append after a provider effect becomes retained uncertainty and blocks future requests. An acknowledgement lost after successful sync is handled conservatively too.

Checks cover absolute/non-symlink paths, final-file type, ownership, link count and private mode. **These are not race-safe hostile namespace enrollment.** Parent namespace ownership/mounts and same-UID writers are trusted. This code does not implement descriptor-relative protected path traversal, deny debugger/process access, authenticate a writer, detect hostile rollback or test network filesystems. No system permissions, services, users or security settings are changed.

## Lifecycle and recovery meaning

| Last retained evidence | Inspection result |
| --- | --- |
| Reservation, no provider intent | Consumed reservation, incomplete operation, no asserted provider dispatch; no automatic retry/refund |
| Mint intent, neither receipt nor known-rejection terminal | Uncertain mint and unknown operation; a token might exist |
| Received token, not yet validated | Known unresolved token; incomplete operation; no token value is recoverable |
| Validated token or read intent without terminal | Unresolved token plus incomplete/unknown operation |
| Successful read terminal | Completed operation; token still unresolved until separately confirmed revoked |
| Known failed mint terminal | Reservation remains consumed; no token is asserted |
| Local authority revoked | Future local authority was revoked; no claim that GitHub revoked a token |
| Revoke intent, missing/unknown acknowledgement | Uncertain revocation and unresolved token |
| Confirmed provider revocation | That known token is reconciled; an unrelated unknown mint remains unresolved |

A report with no reconciliation work still restores no authority. Reports do not contact GitHub, infer that a token is expired from the current clock, remove history or create grants. An issued token is intentionally absent after restart, so real provider reconciliation/revocation would require a separately authenticated protected mechanism. The experiment demonstrates retained facts and safe refusal; it does not implement that mechanism.

UTC/elapsed clock regressions remain handled by the GitHub runtime. The durable ordering is by sequence, not wall time. A previously unknown outcome cannot be replaced by a clock error; fresh-process inspection does not grant anything based on a reset or advanced clock. Old fixture epochs are records, never resumed sessions.

## Strict decoding and its limits

The reader bounds the whole file at 512 KiB, each line including LF at 8 KiB, events at 512 and reservations at 32. It rejects unsupported schema, missing header, malformed JSON, unknown/duplicate fields, invalid fixed enrollment, wrong approval/epoch, duplicate IDs, repeated/skipped sequence numbers, impossible transitions, unknown issuance references, invalid validated expiry, blank lines and partial final records. It validates the entire input before returning any report. Terminal records carry a sticky blocked state; unknown outcomes and unvalidated quarantined receipts cannot be followed by new reservations. No tolerant tail repair is available.

A complete valid prefix ending at a record boundary is indistinguishable from an ordinary crash at that point. It is inspected conservatively. Removal of whole records, replacement with another internally valid history, deletion/recreation, or rollback to an earlier valid file cannot be detected under this prototype's trusted-storage assumption. There is no checksum, MAC or signature and no claim of tamper-proof storage. Encrypting a file alone would not establish authorized-writer provenance or rollback resistance either. Protected storage and an external trust anchor remain separate live-use gates.

## Fault and process tests

Deterministic tests cover failures before writing, after a partial write, after a full write before sync, and after sync with a lost acknowledgement at each reservation/effect/terminal boundary. They assert exact mock call counts and prevent fresh request IDs from bypassing the stopped writer. Partial records are rejected; complete prefixes retain consumed state.

Fresh subprocesses exit without Rust cleanup at nine points: before mint intent, before/after issuance, before/after metadata read, after read terminal, before/after revocation and after revoke terminal. A fresh parent inspection verifies retained counts, unchanged files, no restored authority and no provider replay. Separate mock-effect markers are test-only evidence and contain no credentials.

Additional tests cover duplicate/conflicting IDs, single-flight concurrency and revocation order, cached/overlapping issuance references, byte/schema/corruption bounds, unknown outcomes with clock changes, file-lock ownership and static path protections. These are process-exit and injected-I/O tests on the recorded cloud filesystem. They do not emulate arbitrary storage-device power loss, prove hardware flush honesty or establish portable filesystem durability.

## Remaining work

Safe code-only preparation can continue with versioned broker operation/approval contracts, a protected-storage abstraction and recovery protocol, broader deterministic fault modeling, and provider transport tests using only fixtures. Real use still requires separate deployment decisions and authorization for service identities/confinement, protected binary/configuration/journal locations, an independently authenticated human channel and private key provisioning. A maintained RS256 library/sign-only provider is required when signing is introduced; no cryptography was added here.

See [GitHub integration milestones](github-app.md#milestones), [application delivery](application-delivery.md) and [verification](verification.md). The Rust [File locking and synchronization APIs](https://doc.rust-lang.org/std/fs/struct.File.html) provide the primitives; the tests and stated trust assumptions determine this experiment's evidence, not a generic durability promise from calling `sync_all`.

## Broker-bound schema 2

[ADR 0010](adr/0010-versioned-synthetic-github-broker.md) adds schema 2 for the main broker path. Its header/intent use the exact reviewed broker operation ID and record actual principal/session/review/grant bounds and before/after budget, with no restored authority. Standalone schema 1 retains its original spelling/shape and remains inspectable. Mixed schemas are rejected. Full details and historical-validation limits are in [the broker integration contract](github-broker.md#journal-schema-2).
