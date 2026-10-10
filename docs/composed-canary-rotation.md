# Two-import composed canary rotation

**Closed canary-only contract, 10 October 2026. Live use remains NO-GO.**
[ADR 0022](adr/0022-composed-canary-rotation.md) extends the
[fixed application slot](application-slot.md) with two independently reviewed
and encrypted imports through the actual TLS broker process and recipient
child. This document specifies required behavior; it does not declare unrun
tests passed. Exact-source results belong in [verification](verification.md).
Focused runtime, public CLI and second-install fault checks for this increment
are pending at this documentation checkpoint.

The existing `aegis-application-slot` command still imports and installs only
version one. Its focused in-process replacement tests are separate evidence.
The new composition must establish the complete two-import chain before it may
report a successful replacement. It remains a disposable mechanism drill,
with no operational input or rotation service.

## Public command and fixed artifacts

On Unix with `application-slot` enabled:

```sh
cargo run --locked --offline --features application-slot --bin aegis-application-rotation -- /tmp/aegis-rotation-new
cargo run --locked --offline --features application-slot --bin aegis-application-rotation -- inspect /tmp/aegis-rotation-new
```

The matching library entry points are
`vault::application_rotation::run_synthetic_application_rotation_drill(&Path)`
and `vault::application_rotation::inspect_synthetic_application_rotation(&Path)`.

Creation accepts one new absolute root and refuses an existing destination.
Inspection accepts only an existing root. Default and `vault-spike`-only builds
must refuse this optional drill. There is no public version/fault selector,
real-value input, custom reader, private key, slot path, executable, provider,
endpoint, configuration or readiness argument.

| Artifact beneath the root | Required meaning |
| --- | --- |
| `input-1/record.age` | First independently approved committed encrypted import |
| `input-2/record.age` | Second independently approved committed encrypted import |
| `vault/secret-1.age`, `vault/secret-2.age` | Exact byte-for-byte retained ciphertexts of the respective imports |
| Signed vault manifest | Exact versions, ciphertext/import-metadata bindings and installation profiles |
| `application/provider-auth` | Actual final version-two public canary after a normal run |
| `application/.provider-auth.stage` | Fixed staging object, retained if interruption requires reconciliation |
| `application/installation.jws` | Signed genesis plus two installation intent/completion pairs after a normal run |

Dummy role material and broker/recipient journals remain fixture state under
the disposable root. The application file intentionally contains a public
plaintext canary. Marker absence claims must exclude that file and identify
the other surfaces observed. Neither the root nor the compiled code labels
are protected deployment measurements.

## Data and authority chain

Each import uses the existing [bounded reader and transaction](protected-entry.md)
with its own frozen input review and consumed one-shot permit. Version one and
version two have different exact import/profile bindings. Both profiles freeze
`adapter_contract = 2` and `output_contract = 2`; their profile revisions are
`1` and `2`. The full reviewed profile is inside each encrypted import metadata
binding before broker admission. Import, reopen, delivery approval and
decryption must agree on that binding. The legacy acceptance contract `1/1`
cannot supply installation evidence.

Both committed records must enter the same fixture vault's authenticated
manifest without rewriting or regenerating their ciphertexts. Missing, corrupt,
swapped, duplicate-version, foreign-instance or legacy-contract substitution
must fail validation. Ciphertext equality is necessary dataflow evidence;
it does not replace authenticated import metadata or exact delivery approval.

The independent fixture client authenticates agent/admin roles through the
existing inherited TLS connections to the broker child. For each exact version,
it proposes, reviews and approves the resolved installation through the same
main broker authority. A version-one approval never authorizes version two.
Each process freezes one version/profile: the second delivery uses a restarted
broker with a fresh epoch, authentication and approval. A further fresh process
and authentication exercise revoke. Persisted history cannot recreate the
prior process's session, approval or in-memory run handle.
Each delivery consumes one use and synchronizes handoff intent before decryption
and recipient effect. Import approval and delivery approval are distinct.

The broker sends each actual signed, recipient-encrypted capsule over inherited
IPC to the fixed supervised recipient child. TLS ends at the broker endpoints;
the signed capsule and signed reply authenticate the recipient hop. The child
uses the existing [slot protocol](application-slot.md#installation-and-failure-contract):
generation `0 -> 1` installs version one, then `1 -> 2` replaces it with version
two. Each intent precedes staging/replacement; staged-file synchronization,
fixed replacement and directory synchronization precede signed completion.

Both signed installation receipts must bind their request/capsule, complete
profile, exact version, recipient/configuration/slot and prior/new generation.
The broker must validate each receipt against its own retained reservation.
The old receipt remains historical evidence after replacement; it does not
claim the old version is still installed. Each live phase checks an exact
duplicate of its delivery and reuses its result without another installation
or generation. The version-two phase rejects a version-one request and leaves
the installed file unchanged. Cold inspection checks both durable outcomes;
it does not restore the earlier in-memory handle to replay its result. Changed
bindings and stale expected generations cannot inherit a completed result or
new authority.

## Normal report and read-only reopen

A normal completed drill must report two consumed uses, two remaining uses,
two completed installations, installed version two and recipient generation
two, with no incomplete or unknown delivery/installation. It verifies both
retained duplicate outcomes, fresh authentication after restart and durable
future-delivery revocation. Revoke leaves the installed canary in place.

The rotation report extends the slot report with these bounded checks:

| Field | Meaning |
| --- | --- |
| `imported_versions` | The exact validated imported versions, `[1, 2]` in the normal drill |
| `completed_installation_generations` | Verified completed installation generations, `[1, 2]` after both completions |
| `exact_import_ciphertexts_verified` | Both retained vault ciphertexts were checked against their corresponding committed imports |
| `distinct_import_bindings_verified` | The two exact reviewed import bindings were validated as distinct |
| `exact_approvals_verified` | Both deliveries were checked against their separate exact approved plans |
| `delivery_broker_phases` | Two separately authenticated broker process phases performed the two deliveries; the later revoke phase is separate |
| `fresh_authentication_between_versions` | The version-two broker required fresh authentication rather than restoring version-one authority |
| `retained_duplicate_outcomes` | Number of exact live duplicate outcomes checked across the two phases without a further effect; two normally |
| `old_version_rollback_prevented` | The checked version-one request was rejected in the version-two phase and the current file/generation stayed unchanged |

These report booleans must follow actual checks. They cannot be accepted as
readiness/admission input or upgraded into protection claims. Read
`installed_version` independently from completed generation and signed receipts:
the file may show an effect whose acknowledgement is missing. Broker
`consumed_uses`, `unknown_deliveries` and `incomplete_deliveries` retain their own
meaning even when recipient installation evidence exists.

Fresh inspection verifies both retained imports, the manifest and journal
bindings, signed recipient evidence and the actual fixed file. Inspection is
read-only: success or rejection must leave file contents, names, inodes, modes
and modification times unchanged; absent inspection must create nothing. It
cannot clean a stage, finish an intent, mint a receipt, repeat delivery, refund
a use or restore an old session/approval. It is not a guarantee of read-only
OS credentials or absence of private in-memory verification.

## Second-install interruption contract

The following are required expected observations, not a record of checks
already run. Start with version one durably completed. Exit the actual
recipient child during the second installation at each boundary below. Each
case must retain the first completion, two consumed uses, two remaining uses,
and the second delivery as unknown after acknowledgement loss. A duplicate
returns its retained unknown outcome; cold runtime open cannot redispatch it.

| Second-install child exits after | Completed generation | Observed file version | Incomplete installations | Stage retained |
| --- | --- | --- | --- | --- |
| Intent synchronized | 1 | 1 | 1 | No |
| Staged file synchronized | 1 | 1 | 1 | Yes |
| Fixed rename | 1 | 2 | 1 | No |
| Application directory synchronized | 1 | 2 | 1 | No |
| Signed completion synchronized, before reply | 2 | 2 | 0 | No |

An intact pending intent may coexist with the valid predecessor or successor
file. Report what is observed without promoting intent to completion. Partial,
tampered or inconsistent evidence requires reconciliation or inspection
refusal. The final row demonstrates why a completed recipient installation can
coexist with an unknown broker delivery. A local atomic rename is not an atomic
transaction across import, broker journal, recipient intent, file and receipt.

## Acceptance evidence and operational boundary

Required functional coverage includes both exact imported ciphertexts, frozen
version/profile metadata, both exact TLS approvals, both capsule/receipt tuples,
the actual final file, duplicate reuse without rollback, fresh read-only
inspection, durable revoke, and the second-install exits above. Public tests
must also cover missing/corrupt/mixed artifacts, wrong supported canary,
no-clobber and strict arguments, feature refusal, bounded reports, tested
non-slot output/file marker absence and owned-child cleanup.

Keep metadata decoding distinct from cryptographic validation. A test decoding
JWS payloads observes tuple fields; runtime inspection supplies signature,
encrypted-envelope and installed-object validation. Preserve existing default,
vault-only, one-import and legacy-acceptance behavior. Publish test results only
after executing them on the identified source; historical PR #5 checks do not
cover this increment. [Verification](verification.md) owns final aggregates and
any exact-head hosted evidence.

Process exits are not power cuts, a syscall/storage failure matrix or a proof
for an operator filesystem. All roles still run within one development UID and
control plane. `UNISOLATED`, false human-presence/custody/deployment/real-key
claims and unconditional `require_live_deployment()` refusal remain mandatory.
The stopped independent adversarial review remains unresolved; this functional
work neither resumes nor replaces it.

The next step is to answer the [operator decisions](operator-decisions.md) and
select actual protected-entry, custody and recipient adapters. Two public
canaries do not establish operational credential rotation, provider revocation,
independent recovery or immutable installation. No deployment, listener,
security/access change, real secret, provider operation or Sprite action is
authorized by this contract.
