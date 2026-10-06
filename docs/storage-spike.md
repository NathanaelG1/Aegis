# Synthetic age recovery feasibility spike

This optional experiment uses `age = 0.11.1` with default features disabled to answer a narrow question: can a fixed synthetic snapshot be saved to standard age recipients and recovered in a fresh process using only an independently saved key? It does not initialize an operational vault, accept credential values, unlock a broker, or satisfy the real-secret release gate. The [revised design](design-provenance.md) remains the source of future requirements.

The feature is disabled by default. The current package declares Rust 1.96; the experiment was tested with Rust 1.96.1 on macOS 26.6.2 arm64. The selected dependency graph has not had a complete security/advisory/license review. The [`age` 0.11.1 documentation](https://docs.rs/age/0.11.1/age/) labels releases before 1.0 as beta.

## What the code does

`src/storage.rs` encrypts one fixed fixture to independently generated local and recovery X25519 recipients through the established age implementation. Both recipients can decrypt it. No caller can supply plaintext or an arbitrary credential record to the shipped API. `SyntheticKey` has no `Debug`, `Clone`, serialization, or raw-value accessor; serialized recovery material is exposed internally only when writing the new private synthetic kit.

The setup process saves `snapshot.age` in one new directory and the standard age key in `recovery-key.txt` in a separate new directory. It saves no local identity, performs no recovery verification, and drops its keys on exit. Recovery reads only those saved files in a separate process, authenticates and parses the full snapshot, validates every fixed field and binding, then writes a new encrypted snapshot with the grant disabled and sessions empty. The new local recipient is transient; only the saved recovery key remains usable afterward. There is no passphrase-protected `identity.age` implementation here.

The fixture has one credential canary, one exact-version profile, one grant, and at most one synthetic session. Its schema, vault identity, generation, record IDs, versions, resource, operation contract, output contract, and use count must match the fixed synthetic fixture. Unexpected/duplicate fields, additional records, arbitrary values, different bindings, or unsupported versions fail. The only successful return is a small non-sensitive `RecoverySummary`; no credential/profile/grant object becomes broker authority.

All imported grants are disabled in the persisted restore output, and no session is retained. This does not implement restoration of active counters or durable budgets. Restoring an older snapshot is not rollback protection; age encryption does not authenticate a trusted policy writer.

## Running the two-process drill

Use absolute paths whose parents already exist. Every destination must be new. On macOS, `/tmp` and `/var` can be symlinks; resolve the parent path first because the experiment rejects symlink path components. Do not use operational vault locations or supply real credential material.

```sh
cargo +1.96.1 run --locked --features storage-spike --example recovery_spike -- \
  create /absolute/new-snapshot-directory /absolute/new-recovery-kit-directory
# The setup process has now exited; its local/recovery identities are gone.
cargo +1.96.1 run --locked --features storage-spike --example recovery_spike -- \
  recover /absolute/new-snapshot-directory /absolute/new-recovery-kit-directory \
  /absolute/new-restored-directory
```

Successful setup says that the files were saved and that verification remains incomplete. Successful recovery prints only validation counts, disabled authority counts, and experimental status. It never prints key material, canaries, parser details, or native errors. A fresh process demonstrates that the saved kit is sufficient; two folders on one host do not establish independently protected custody.

The unit/integration command is:

```sh
cargo +1.96.1 test --locked --offline --features storage-spike --test storage
```

## Verified evidence

On the tested macOS host, all 14 integration tests passed. One test launches a setup child process, waits for it to exit, and launches a distinct recovery child process with only the saved file paths. The separate example `create` and `recover` commands also completed successfully in two processes, and their temporary synthetic kit/snapshots were removed afterward.

| Test area | Observed result |
| --- | --- |
| Independent local and recovery recipients | Both validate the same saved fixture; reusing one key for both recipients is rejected |
| Wrong key, truncation, corrupted payload/header | Rejected; no successful restore summary |
| Ciphertext/plaintext limits | Rejected before snapshot authorization or restore destination creation |
| Scrypt/passphrase input | Rejected without invoking scrypt decryption |
| Unsupported schema, unknown/duplicate fields, malformed shape | Rejected before destination creation |
| Credential/profile/grant/resource/output bindings and counts | Every tested changed binding and extra/missing record rejected |
| Restore authority | Actual persisted output has `enabled=false` and `sessions=[]`; recovery again preserves disabled authority |
| Existing destination | Files and permission bits preserved; no success or replacement |
| Relative paths, symlink paths/kit, nonregular input | Rejected before restore destination creation; a directory substituted for the saved key is rejected |
| New Unix directories/files | Observed directory mode `0700` and file mode `0600` on this host |
| Process output | Fresh-process test captures stdout/stderr and finds no canary or private-key prefix |

The executable bounds are 16 KiB ciphertext, 4 KiB plaintext, and 256 bytes for a single standard X25519 recovery key. These are intentionally small fixture bounds, not proposed production limits. JSON uses typed, unknown-field-denying deserialization and the parser's default recursion limit; the successful fixed schema has only shallow nesting. The age parser's internal allocations/chunk buffers and every malformed header shape have not been resource-profiled. No compression, plugin identity, SSH identity, or passphrase recovery input is supported by this fixture.

## Filesystem and verification limits

The file drill supports Unix only and returns `unsupported_platform` on other systems. Windows ACL/reparse behavior and Linux permission/durability behavior have not been tested. No cross-platform support or containment claim follows from portable in-memory Rust/age code.

Creation uses new directories, `create_new` files, restrictive creation modes, non-following leaf opens, bounded regular-file reads, file sync, and directory sync. No existing permission is modified. Ancestor symlinks are rejected before opening, but this is not an atomic directory-handle traversal; a hostile concurrent same-user writer can race ancestor path resolution. Restrictive permissions do not exclude code running as the same account.

Setup and restore are multi-step experiments, not transactions. If an IO failure occurs after creating a directory or file, a partial new artifact can remain; the operation reports failure and does not overwrite or clean up another destination. Parent-directory entry durability, power-loss behavior, crash recovery, concurrent writers, optimistic generation checks, ordinary commits, multi-file rekey, recipient changes, and real-secret recovery verification remain unimplemented. No saved state is marked `ready`.

The private-byte buffer and completed canary record are zeroized on drop through age's secrecy/zeroize dependency. This reduces accidental retention; it is not proof that every parser temporary, allocator copy, swap page, crash dump, or compiled constant is wiped. The fixture is synthetic specifically because those wider guarantees have not been established.

Standard age compatibility is the documented contract of [`age` 0.11.1](https://docs.rs/age/0.11.1/age/), based on the [age format specification](https://c2sp.org/age@v1.1.0). Aegis has exercised the Rust implementation against itself. Independent `age`/`rage` CLI interoperability and fresh recovery on Linux/Windows remain pending; no reference CLI was installed on the tested Mac. Whole dependency review, fuzzing, independent security review, and a protected approval/containment deployment are separate gates.
