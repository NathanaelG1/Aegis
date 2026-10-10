# Fixed-canary application-file slot

**Acceptance contract, 10 October 2026. Implementation evidence pending; live
use remains NO-GO.** [ADR 0021](adr/0021-fixed-application-slot.md) defines this
bounded extension of the [process-owned broker service](process-service.md).
The completed implementation must install the actual imported public canary
into one fixed application file and verify signed installation evidence.

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

The intended public interface is:

```sh
cargo run --locked --offline --all-features --bin aegis-application-slot -- /tmp/aegis-slot-new
cargo run --locked --offline --all-features --bin aegis-application-slot -- inspect /tmp/aegis-slot-new
```

Commands are the proposed acceptance interface until the implementation is
integrated. The optional `application-slot` feature includes `vault-spike` and
the pinned `rustix` 1.1.5 filesystem dependency. The destination must be absolute
and new for creation. A caller
cannot select an input value, slot, target filename, application executable,
configuration, provider, transport endpoint, readiness declaration or fault.
Child modes and fault points must not become a generic public API.

The fixed layout beneath the disposable root is:

| Object | Fixed name | Meaning |
| --- | --- | --- |
| Application file | `application/provider-auth` | Intentional plaintext public canary consumed by the fixed recipient |
| Staging file | `application/.provider-auth.stage` | New regular object prepared before the fixed replacement |
| Installation journal | `application/installation.jws` | Signed append-only installation intent and receipt evidence |

The legacy encrypted recipient acceptance record remains distinct. Persisted
receipt validation must prevent an acceptance-only acknowledgement from being
treated as completed file installation on reopen.

Reuse the actual bounded encrypted import, signed manifest, inherited TLS role
channels, broker process, existing approval and durable reservation. The fixed
recipient is another supervised child. Agent/admin signing stays outside the
broker. TLS terminates at the broker's agent/admin endpoints; the recipient uses
the existing signed, encrypted capsule and signed response over inherited IPC.

Normal composition may install only version one of that actual import. Any
two-version replacement fixture is separate focused evidence until the complete
import/process composition actually exercises it. Fixed bindings describe the
fixture construction; they do not measure the executing binary, dependencies,
host, human presence or protected configuration.

## Installation and failure contract

The broker consumes a use and synchronizes handoff intent before a possible
effect. The recipient validates all capsule bindings and expected generation,
then persists installation intent before staging. It creates a new regular
staging file relative to the fixed directory handle, verifies the used objects,
writes and synchronizes the file, checks the expected prior generation, performs
the fixed replacement and synchronizes the directory. Durable signed
installation evidence must precede a success acknowledgement.

Evidence must correlate the installed generation/version, exact request and
capsule, fixed recipient/slot/configuration and the expected predecessor.
Existing broker receipt validation remains required. Signing an assertion alone
does not demonstrate that the application file matches it: reopen and status
must validate the actual object and its bounded contents against the retained
evidence without returning the canary or a credential fingerprint to the agent.

An identical completed duplicate reuses its result without staging, replacing
or incrementing the generation again. Changed bindings and stale generations
are rejected. Concurrent slot writers must not both advance the generation.
Known rejection does not refund a reservation already consumed by the broker.

A failure after a possible effect retains consumed uncertainty. Missing,
partial, tampered or mismatched intent, file or receipt requires reconciliation;
restart must not infer permission to install again, mint a receipt, clean up
evidence, refund a use or restore a session/approval. A successfully installed
file may remain after a lost acknowledgement. Atomic file replacement does not
atomically commit the broker journal or recipient receipt.

Inspection opens existing evidence for validation only. It must leave the
application file, staging/intent artifacts and journals unchanged, including
when validation fails. It cannot repair the fixture or authorize a retry.

## Functional acceptance matrix

Every result below is pending at contract publication. Update observations from
the integrated source; historical process-service results cannot fill these rows.

| Boundary | Required observation | Evidence scope |
| --- | --- | --- |
| Actual import to installation | The fixed file contains the bounded imported canary and generation one has valid signed installation evidence | Full composed CLI plus independent file observation |
| Authority and replay | Reservation precedes handoff; duplicate leaves object/generation unchanged; fresh restart requires authentication; revoke survives restart | Full composed path where exercised |
| Replacement | A valid next generation replaces the prior version once; old object is not modified through an existing alias; stale generation fails | Focused two-version fixture unless composition is extended |
| Object validation | Missing/corrupt/substituted file, invalid mode/type/link state and stale/mismatched signed evidence fail closed | Focused tests and public inspection negatives |
| Installation interruption | Intent, stage, sync, replacement and receipt boundaries leave one validated install or reconciliation-required state | Identify each injected boundary and whether it is a component fault or process termination |
| Lost acknowledgement | Installed data may remain; broker use stays consumed and outcome unknown; no automatic repeat/refund | Composed transport fault or explicitly scoped component test |
| Read-only inspection | Success and failure leave existing artifacts unchanged and restore no authority | Independent artifact snapshot comparison |
| Fixed public interface | New absolute root, no overwrite, strict arguments, default-feature refusal and closed output | Public executable tests |
| Output surfaces | No canary/private material in captured reports or non-slot artifacts covered by the test; intentional canary file is present | Bounded observation, not a confidentiality or isolation proof |

Fault injection is ordinary functional acceptance work. It neither performs nor
replaces adversarial security review, host-isolation testing or power-loss
testing on a supported operator filesystem.

## Evidence and remaining operational work

The historical process-service checkpoint is PR #4, open draft stacked on
PR #3, at head `210a1b32d2986ce8d6673baeafcfe69399d0adb8`, tree
`fa4d89c07531d3333b36cbb8b52f3813d1e4362e` (local `7e64b81`). Its
[exact-head hosted run](https://github.com/NathanaelG1/Aegis/actions/runs/38008817405)
passed 174 default and 444 all-feature tests, including 317 all-feature library
tests; 1/28 doctests; all 21 Unix interface tests in each feature configuration;
and formatting, Clippy and rustdoc checks. No tests failed or were ignored.
The host was Ubuntu 24.04.5 LTS x86_64 with Rust 1.96.1. Those results precede
this slot increment. New-slot exact-source and hosted evidence are pending.

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
