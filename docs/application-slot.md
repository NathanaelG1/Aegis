# Fixed-canary application-file slot

**Implemented canary-only mechanism, 10 October 2026. Focused functional checks
passed; live use remains NO-GO.** [ADR 0021](adr/0021-fixed-application-slot.md)
defines this bounded extension of the [process-owned broker service](process-service.md).
The implementation installs the actual imported public canary into one fixed
application file and verifies signed installation evidence.

## What installation means

The legacy recipient's encrypted `accepted.jws` record demonstrates acceptance
and supports its in-memory payload after reopen. It does not install an
application credential file. This increment adds an actual fixed plaintext
canary file with its own durable installation sequence and signed evidence.

That narrower installation result still does not establish protected or isolated
credential use. A same-UID agent or administrator can read or replace ordinary
fixture files, inspect processes, or control backups and the host. The canary
slot is expected to contain its public fixture value; plaintext absence checks
must therefore exclude that intentional file and describe which other surfaces
were observed. No real secret belongs in this drill.

## Fixed workflow and public surface

Run the fixed Unix drill or inspect an existing root:

```sh
cargo run --locked --offline --all-features --bin aegis-application-slot -- /tmp/aegis-slot-new
cargo run --locked --offline --all-features --bin aegis-application-slot -- inspect /tmp/aegis-slot-new
```

The optional `application-slot` feature includes `vault-spike` and the pinned
`rustix` 1.1.5 filesystem dependency. The destination must be absolute and new
for creation. A caller cannot select an input value, slot, target filename, application executable,
configuration, provider, transport endpoint, readiness declaration or fault.
Child modes and fault points must not become a generic public API.

The fixed layout beneath the disposable root is:

| Object | Fixed name | Meaning |
| --- | --- | --- |
| Application file | `application/provider-auth` | Intentional plaintext public canary in the fixed application slot |
| Staging file | `application/.provider-auth.stage` | New regular object prepared before the fixed replacement |
| Installation journal | `application/installation.jws` | Signed append-only installation intent and receipt evidence |

The legacy encrypted recipient acceptance record remains distinct. Persisted
receipt validation must prevent an acceptance-only acknowledgement from being
treated as completed file installation on reopen.

The broker's signed manifest selects the installation receipt contract, which
is then enforced on journal replay as well as live delivery. Capsule,
acknowledgement, status and response domains distinguish installation from
legacy acceptance. A copied legacy acceptance journal beside a canary file
cannot supply installation evidence. The installation profile freezes
`adapter_contract = 2` and `output_contract = 2` in import metadata before input
approval and encryption; the separate profile `revision` remains `1`. Import
consumption, reopen, delivery decryption and exact delivery approval revalidate
that profile against the selected manifest
contract. Legacy acceptance keeps adapter/output contract revisions `1/1`.
Installation mode changes the reviewed binding rather than being inferred from a constructor or
report. The broker consumes the same imported ciphertext; selecting the slot
contract does not regenerate its value.

The drill reuses the actual bounded encrypted import, signed manifest, inherited TLS role
channels, broker process, existing approval and durable reservation. The fixed
recipient is another supervised child. Agent/admin signing stays outside the
broker. TLS terminates at the broker's agent/admin endpoints; the recipient uses
the existing signed, encrypted capsule and signed response over inherited IPC.

Normal composition installs only version one of that actual import. The
two-version replacement fixture uses an in-process host and fixture key kit
through the existing broker authority. It does not import version two or extend
the normal TLS/process drill. Fixed bindings describe the fixture construction;
they do not measure the executing binary, dependencies,
host, human presence or protected configuration.

## Installation and failure contract

The broker consumes a use and synchronizes handoff intent before a possible
effect. The recipient validates all capsule bindings and expected generation,
then appends and synchronizes a signed installation intent before staging. It
creates a new regular staging file relative to the fixed directory handle,
verifies the used objects, writes and synchronizes the file, checks the expected
prior generation, performs the fixed replacement and verifies the resulting
name against the held staging descriptor. It synchronizes the application
directory before signing the installation receipt, appending the signed
completion record and synchronizing that journal. Only then can the broker
receive a success acknowledgement.

The receipt contains an acknowledgement under the installation-specific domain,
complete delivery profile, prior generation, fixed slot filename, actual
validated canary digest, application directory device/inode identity and the
fixed `file-sync-rename-directory-sync-v1` contract. The acknowledgement binds
the vault, request, recipient/slot/configuration, version, new generation and
capsule digest. The signed append-only journal also binds directory identity,
sequence and previous record. Existing broker receipt validation remains
required. Reopen and status validate the actual object and bounded contents
against the evidence without returning the canary or its digest in public
reports. The journal is capped at 512 KiB and five records: genesis plus two
intent/completion pairs. Canary file reads are capped at 4 KiB.

Filesystem traversal opens `/` once, then uses held directory descriptors for
each root component and the fixed application child, with no-follow directory
opens. The created application directory is mode `0700`; new files are mode
`0600`. Validation checks current effective-UID ownership, directory/file type,
absence of group/other and special mode bits, single-link files and agreement
between named and held objects. A renamed ancestor does not redirect operations
through the held root; replacing its fixed application child is rejected.
This is bounded object validation under serialized trusted fixture access.
It does not prevent a same-UID writer from racing changes in that namespace,
provide mount confinement or establish an operational ownership boundary.

An identical completed duplicate reuses its result without staging, replacing
or incrementing the generation again. Changed bindings and stale generations
are rejected. Concurrent slot writers must not both advance the generation.
Known rejection does not refund a reservation already consumed by the broker.

A failure after a possible effect retains consumed uncertainty. Missing,
partial, tampered or mismatched intent, file or receipt requires reconciliation.
An intact pending intent can be inspected with either its validated predecessor
or new canary file present. Inspection reports that incomplete installation
without advancing the completed generation. A partial journal/stage or
inconsistent object fails validation. Neither outcome permits restart to
install again, mint a receipt, clean up evidence, refund a use or restore a
session/approval. A successfully installed file may remain after a lost
acknowledgement. Atomic file replacement does not atomically commit the broker
journal or recipient receipt.

Inspection opens existing evidence for validation only. It must leave the
application file, staging/intent artifacts and journals unchanged, including
when validation fails. It cannot repair the fixture or authorize a retry.

The normal report shows one completed installation, version and generation one,
one consumed use, three remaining uses, no incomplete
installation, duplicate reuse and revocation retained after fresh authentication
and restart. The installed canary remains after that future-delivery revoke.

Read recovery fields independently:

| Field | Meaning |
| --- | --- |
| `installed_version` | Canary version actually observed in the fixed file; zero means no installed file in a valid initial/pending state |
| `recipient_generation` / `completed_installations` | Completed signed installation history, not merely the version currently visible in the file |
| `incomplete_installations` | An intact signed intent with no completed installation receipt |
| `consumed_uses`, `incomplete_deliveries`, `unknown_deliveries` | Existing broker reservation/outcome history, preserved even when installation evidence is available |
| `installation_receipt_verified` | A completed installation receipt was verified; it does not upgrade an unknown broker outcome or authorize a further delivery |

For example, after replacement but before signed completion, a valid inspection
may show `installed_version = 1`, `recipient_generation = 0` and
`incomplete_installations = 1`. After completion is synchronized but its reply
is lost, generation one may coexist with a consumed unknown broker delivery.
Neither observation is permission to repeat installation. The public reports
restore zero sessions, allow no automatic retry and retain `UNISOLATED` with
all human-presence, protected-custody/deployment and real-key claims false.
Construction fields such as `handle_relative_operations` describe the fixed
implementation; they are not independent host measurements.

## Focused functional evidence

These rows describe checks actually run on the source checkpoints below.
Historical process-service results do not supply new-slot evidence.

| Boundary | Observed check | Evidence scope |
| --- | --- | --- |
| Actual import to installation | The fixed file contains the compiled version-one canary; input and vault ciphertext bytes match; fresh inspection verifies the installation | Full composed CLI plus independent file observation |
| Authority and replay | Duplicate reuses its result; fresh restart requires authentication; revoke survives restart; a duplicate old capsule after replacement returns the retained receipt without rolling the file back | Normal composed drill plus focused recipient duplicate test |
| Replacement | Version two has a new inode; the held prior descriptor still reads version one; both signed receipts survive reopen and two uses remain consumed | In-process two-version fixture through existing broker authority; no version-two import/TLS process composition |
| Object validation | Wrong supported canary version, missing/corrupt evidence, symlink/hard-link/directory/FIFO leaves, replaced application child and invalid signed tuples fail closed | Public inspection negatives, six directory tests and focused receipt tests |
| Installation interruption | Actual child exit after intent sync, stage sync, rename, directory sync or completion sync retains one consumed use, unknown broker outcome and no cold redispatch | Five scenarios in the actual process-service crash test |
| Lost acknowledgement | After completion sync and before reply, file and signed generation one remain; broker reports unknown with no repeat/refund | Final actual recipient-exit scenario |
| Read-only inspection | Success and refusal preserve bytes, inode, mode and modification time; absent inspection creates nothing | Public artifact snapshots; crash test also checks unchanged journal and repeatable report |
| Fixed public interface | New absolute root, no overwrite, strict arguments, default/vault-only refusal and closed output | Public executable tests |
| Output surfaces | Captured output and tested non-slot files contain no canary marker; the intentional file contains it; Linux root-scoped child scan finds no surviving fixed fixture process | Bounded observation, not confidentiality, supervisor-crash cleanup or isolation proof |

The process crash test produced the following retained observations. Each row has
one consumed use, three remaining uses and one unknown broker delivery; exact
duplicate invocation returns the same unknown result, and cold runtime reopen
is denied.

| Child exits after | Completed generation | Observed installed version | Incomplete installations | Stage retained |
| --- | --- | --- | --- | --- |
| Installation intent synchronized | 0 | 0 | 1 | No |
| Staged file synchronized | 0 | 0 | 1 | Yes |
| Fixed rename | 0 | 1 | 1 | No |
| Application directory synchronized | 0 | 1 | 1 | No |
| Signed completion synchronized, before reply | 1 | 1 | 0 | No |

Focused runtime source `538b0b913f0af303100863c4e77856844938adbc` (integrated as
`ddc9883`) passed ten new slot/directory/crash tests, the nine-test process-service
and nine-test recipient suites, 25 protected-entry tests and 41 vault tests.
All-feature and vault-only Clippy passed with warnings denied. These are focused
checks, not the final aggregate run.

Public executable tests passed on source
`5c00144a2c3e54de16f2cb55c9d11ffaffd7c5fa`, tree
`d6ab4897b621f329172319552eb76cf7ab31b3a4`: default 3/3, `vault-spike` 3/3,
explicit `application-slot` 8/8 and all-features 8/8. The environment was Linux
x86_64 with Rust 1.96.1, locked/offline dependencies. Formatting, default and
all-feature all-target Clippy with warnings denied also passed. The integration test's JWS
payload decoding checks tuple metadata only; fresh runtime inspection supplies
cryptographic signature and installed-file validation. Final integrated
aggregate and hosted evidence remain pending in the [verification record](verification.md).

Fault injection is ordinary functional acceptance work. The five child exits
are not power cuts or a complete short-write, syscall-error or storage-device
failure matrix. These tests neither perform nor replace adversarial security
review, host-isolation testing or durability testing on an operator filesystem.

## Evidence and remaining operational work

The historical process-service checkpoint is PR #4, open draft stacked on
PR #3, at head `210a1b32d2986ce8d6673baeafcfe69399d0adb8`, tree
`fa4d89c07531d3333b36cbb8b52f3813d1e4362e` (local `7e64b81`). Its
[exact-head hosted run](https://github.com/NathanaelG1/Aegis/actions/runs/38008817405)
passed 174 default and 444 all-feature tests, including 317 all-feature library
tests; 1/28 doctests; all 21 Unix interface tests in each feature configuration;
and formatting, Clippy and rustdoc checks. No tests failed or were ignored.
The host was Ubuntu 24.04.5 LTS x86_64 with Rust 1.96.1. Those results precede
this slot increment; they cannot replace the separate slot evidence above.

This milestone advances [operator work package C5](operator-live-trial-plan.md#3-missing-code-work-with-acceptance-outputs).
It does not complete operational C5: enrolled immutable application identity,
protected recipient-only destination and full host/lifecycle fault evidence
remain necessary. Protected entry/custody, independently authenticated human
approval, deployed transport/trusted time, independent rollback anchor/fencing,
provider adapter and approved assurance also remain open. The operator must
choose the exact host, filesystem, identities, custody, human client and recovery
boundary before a separate deployment can be evaluated.

`require_live_deployment()` remains an unconditional refusal. All real-key and
protected-deployment fields must remain false. No listener, service/access or
security change, live credential/provider operation or Sprite action is part of
the drill. Revocation prevents future broker dispatch; it does not erase the
installed canary or revoke authority at a provider.
