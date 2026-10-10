# Synthetic protected-entry and import groundwork

**Fixed canary only. Real credentials, protected human input, and live deployment remain unavailable.** This increment extends the [operator-entry metadata ceremony](operator-entry-contract.md) with a private bounded reader and a ciphertext-only fixture transaction. The term “protected entry” names the intended boundary being developed, not a demonstrated protected display, human identity, key custody, or host-isolation guarantee.

The only public operation is `vault::entry::protected_entry::run_synthetic_protected_entry_drill(new_destination: &Path)`. It accepts one new absolute fixture destination. It has no credential, reader, input descriptor, identity, custody provider, configuration, readiness flag, or imported review argument. It reads only a compiled-in disposable canary, using an in-memory cursor. The private import also checks exact equality with that canary before encryption. No agent/admin protocol action or live vault constructor is added. `require_live_deployment()` still returns `unsupported_deployment` unconditionally.

The change adds synthetic persistence and private input handling to the reviewed code surface. It does not change broker authority, operational credential custody, the live gate, or platform support. It uses the existing optional `vault-spike` dependencies, including maintained age encryption and zeroize; it introduces no cryptographic algorithm or dependency.

## Bounded input and frozen review

The private input format is eight bytes of fixed magic, a four-byte big-endian payload length, exactly that many bytes, and EOF. Empty values, malformed magic, declared lengths above 4096, every truncation, concatenated frames, and even one trailing byte are rejected. Bytes are opaque; the reader performs no UTF-8 conversion. The initialized header, fixed 4096-byte input array, and one-byte EOF probe use `Zeroizing`. Short reads are supported. Read attempts, including interrupted calls, are capped at 8256. Cancellation, exact review equality, expiry, and clock monotonicity are checked before and after each read.

This attempt bound cannot interrupt a blocking `Read`. The only public path uses a finite in-memory fixture, so no public caller can supply a blocking terminal, pipe, or network stream. A future real input adapter needs its own protected I/O and deadline contract.

The import review contains the complete existing `FrozenReview`: ceremony instance, all exact deployment/role bindings, all five prerequisite receipts, earliest expiry, and one-use limit. It additionally freezes the destination, ephemeral age public recipient, input-format revision, and reader limit. Equality covers the entire structure. Changed metadata, expired review, or observed clock regression latches failure; restoring the old values cannot revive it. Operator approval and cancellation compare the exact fixture operator binding. These typed comparisons simulate authorization; they do not authenticate a person or prove that anyone saw a review.

Approval consumes the existing ceremony's sole reservation into a private non-cloneable permit. Import takes that permit before reading any bytes or touching the destination. Failed reads, wrong identity or canary, cancellation, panic, publication failure, and dropping approval cannot refund it. Concurrent imports have at most one winner. There is no serialization, restoration, or cross-process authority import.

## Plaintext and encryption bounds

Only the existing ephemeral age identity can decrypt the output during the drill. It is never written to disk or returned. The encrypted envelope contains a fixed magic, length-delimited JSON of the complete frozen import review, and the length-delimited canary, with no trailing content. The drill decrypts the fixture privately and checks exact metadata/value equality before reporting success.

Metadata has a 15 KiB cap. Checked arithmetic enforces metadata plus 16 framing bytes plus payload at or below the existing crypto module's 16 KiB plaintext cap before allocating/extending the plaintext envelope. Its owned `PrivateBytes` allocation has fixed capacity and a zeroizing drop. The encrypted output retains the existing 64 KiB crypto cap. The public report distinguishes the private reader's maximum payload size from the fixed canary's actual import size; it does not advertise arbitrary 4096-byte credential import.

Input and plaintext buffers provide no `Debug`, `Display`, `Clone`, serialization, public callback, or plaintext-return API. Errors are fixed `ErrorCode` values; reader diagnostics are discarded. The report contains only counts, booleans, and fixed error codes. It includes no path, recipient, receipt body, identity, or canary. Tests check reports, debug text, and every retained transaction file for the canary marker.

Zeroizing owned buffers is not proof that compiler/library temporaries, copies, swap, process dumps, or a privileged debugger cannot retain or inspect plaintext. The test fixture itself is public source data. No secure-erasure or agent-blind memory guarantee is claimed.

## New-destination transaction

The destination must be absolute, at most 1024 path bytes, normalized without `.`/`..`, duplicate separators or a trailing separator, and contain no existing symlink component. Creation refuses every existing destination, including an empty directory. A new private-mode directory contains a `create_new`, no-follow staging file. Only encrypted bytes reach that file.

The transaction syncs the parent after directory creation, writes and syncs the staging ciphertext, and syncs the new directory. Publication makes a no-replace hard link from `record.pending` to `record.age`, removes the staging name, and syncs the directory again. An existing committed name is never overwritten. Cancellation and final publication share one mutex: cancellation winning prevents publication; publication winning leaves committed or uncertain state that cancellation cannot undo.

Before publication, failures attempt cleanup of only the owned staging object and then nonrecursive removal of the new directory. Device/inode comparisons detect simple object replacement before cleanup. Foreign files and replaced staging objects are retained, with `reconciliation_required` returned when cleanup cannot be established. Dropping an unpublished transaction makes the same best-effort nonrecursive cleanup attempt. A failure after the committed link is created retains ciphertext and reports `reconciliation_required`; it cannot refund the permit or trigger an automatic retry. Retained ciphertext may be unrecoverable after the ephemeral fixture identity is dropped.

These are trusted-local-namespace fixture semantics. Path validation and identity comparisons are separate from later path-based filesystem calls, so they are not descriptor-relative, race-free defenses against a same-user attacker, parent substitution, mount changes, or hard-link manipulation. Filesystem sync calls and injected I/O faults do not demonstrate device-power-loss durability. There is no operational entry journal, protected anchor, restart reconciliation, or recovery-key custody. Existing destinations cannot be reused after a restart, but deleting a fixture and creating a new drill does not represent a durable budget or rollback defense.

## Verification

Run from the repository with its pinned Rust 1.96.1 toolchain:

```sh
cargo test --locked --offline --features vault-spike vault::entry:: --lib
cargo test --locked --offline --all-features --doc
sh scripts/check.sh
```

A disposable example accepts only a fresh absolute destination beneath trusted temporary storage:

```sh
cargo run --locked --offline --features vault-spike --example protected_entry -- /tmp/new-aegis-entry-fixture
```

Functional tests cover the complete public drill and exact encrypted metadata; maximum-size opaque input with short/interrupted reads; all truncations and strict EOF; metadata and envelope bounds/overflow; wrong approval, identity, review, and canary; cancellation and clock failure; consumed read failures and panics; concurrent import/cancel outcomes; partial writes and failures before/after publication; no-clobber behavior; nonrecursive cleanup; replaced objects; drop behavior; safe report shape; and persistent live-deployment refusal. Compile-fail examples keep private session construction and caller-supplied value input unavailable.

These are implementation checks, not an independent security assessment. The previously stopped independent review remains incomplete. Protected display/input, independently verified human identity, operational custody, real recipient isolation, a race-safe storage backend, durable entry recovery, and operator-owned deployment evidence remain open.
