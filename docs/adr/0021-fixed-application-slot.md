# ADR 0021: Fixed application-file installation

Status: implemented for canary-only use, 10 October 2026; focused functional
checks passed. Final integrated aggregate and hosted evidence are recorded
separately. Operational deployment remains unavailable.

## Context

The process-owned broker service in [ADR 0020](0020-process-owned-dummy-broker-service.md)
joins actual encrypted import, authenticated TLS role channels, durable broker
reservation and a separate recipient process. Its recipient stores an encrypted
acceptance record and recovers the accepted payload into memory. That record is
not an application credential file, and acceptance does not prove installation.

## Decision

Add one fixed compiled canary recipient that installs the imported fixture value
into one fixed application-file slot. Reuse the actual import, existing TLS
process service and main broker reservation path. Do not add another approval
engine, substitute independently generated data for the imported record, or
relabel the legacy encrypted acceptance record as application installation.

The public drill accepts a new absolute disposable root; read-only inspection
accepts an existing root. It cannot accept arbitrary input, slot, filename,
executable, configuration, provider, readiness assertion or fault control.
Internal child dispatch and test-only faults remain implementation plumbing.
The normal composition uses the one imported version; focused two-version
replacement tests are separate from that composed path.

Gate the increment behind the optional `application-slot` feature, which
includes `vault-spike` and pinned `rustix` 1.1.5 filesystem support. The fixed
target is `application/provider-auth`, the stage is
`application/.provider-auth.stage`, and signed append-only installation evidence
is stored in `application/installation.jws` beneath the disposable root.

The new recipient must validate the writer-signed capsule, its exact recipient,
configuration, slot, version and expected generation. Installation evidence must
bind the delivery/request and capsule to the installed version and generation.
Installation mode must be part of the immutable reviewed profile as well as the
persisted broker and recipient contract; a constructor or report flag cannot
change the effect of an acceptance-only approval.
Use adapter/output revisions `adapter_contract = 2` and `output_contract = 2`, frozen
before input approval/encryption and revalidated at import, reopen, delivery
approval and decryption. The separate profile `revision` remains `1`; legacy
acceptance retains adapter/output contract revisions `1/1`. Distinct
installation capsule/status/response/acknowledgement domains and the full
signed profile prevent treating a legacy acceptance receipt as installation.
The existing broker receipt correlation remains mandatory. An encrypted
acceptance acknowledgement alone cannot claim the file installation succeeded.

## Ordering and recovery contract

1. Commit the broker's consumed reservation and handoff intent before a possible
   recipient effect. The recipient records its own durable installation intent
   before staging or replacing the application file.
2. Anchor slot operations to opened directory handles. Stage a new regular file
   within the fixed directory, verify the objects actually used and the fixed
   ownership/mode/link requirements, write the bounded canary and synchronize
   the staged file. Do not modify the prior installed file through an alias.
3. Replace only the expected generation under exclusive recipient ownership.
   Synchronize directory state after the replacement before recording success.
   Bind and durably retain signed installation evidence before returning an
   acknowledgement that the broker may record as completed.
4. On reopen, validate the intent, installed object, signed installation evidence
   and broker receipt correlation. Missing, partial, mismatched or uncertain
   evidence requires reconciliation. Never manufacture a successful receipt,
   replay an installation, refund a consumed use or restore session/approval
   authority to resolve ambiguity.
   An intact pending intent may be observed with the old or new canary file;
   inspection reports it as incomplete without promoting it to a completion.
5. An exact completed duplicate returns existing evidence without another file
   effect. Changed bindings or stale generations fail closed. Inspection reads
   and validates existing evidence; it performs no repair, cleanup or replay.

An atomic rename is one namespace transition, not a transaction spanning broker
journal, recipient intent, application file and receipt. A crash after possible
installation but before durable acknowledgement may leave the canary present
with an unknown broker outcome. Retaining uncertainty is the required result.
Fail-closed handling does not promise that an installed value was removed.

Use the optional filesystem dependency for directory-relative safe APIs while
preserving the repository's forbidden-unsafe-code policy and default dependency
boundary. Maintainer documentation for
[`rustix::fs::openat`](https://docs.rs/rustix/1.1.5/rustix/fs/fn.openat.html)
specifies a safe directory-relative API returning an owned file descriptor;
[`renameat`](https://docs.rs/rustix/1.1.5/rustix/fs/fn.renameat.html) accepts the
source and destination directory handles. These APIs permit handle-relative
operations; they do not themselves establish protected ownership, reject every
alias or mount substitution, or prove the full durability protocol.
The [crate documentation](https://docs.rs/rustix/1.1.5/rustix/) explicitly leaves
ambient authority, sandboxing and significant platform differences to callers.
Using these wrappers does not establish confinement.

## Functional evidence and its limits

The [application-slot contract](../application-slot.md) records focused results
and identifies their exact source. Public executable checks observe the actual
imported canary file, receipt metadata and read-only reopen; runtime inspection
performs signature and object validation. Focused two-version replacement uses
an in-process fixture through the existing broker authority. Real recipient
child exits exercise five boundaries after intent sync, stage sync, rename,
directory sync and completion sync. All retain consumed broker uncertainty and
deny cold redispatch; valid inspection distinguishes observed file version from
completed installation generation.

Directory/object, changed signed tuple, legacy-contract substitution and public
negative tests cover their stated functional cases. These results do not prove
power-loss durability, arbitrary syscall/storage failure handling, namespace
confinement or a supported deployed filesystem. The
[verification record](../verification.md) owns final integrated aggregate and
hosted results; historical PR #4 CI does not cover this slot implementation.
Functional implementation and tests do not resume or replace the previously
stopped independent adversarial review.

## Operational boundary retained

The application slot intentionally contains a public fixture canary. All
processes and disposable custody remain under one development UID. Handle-based
filesystem code, signed receipts and separate processes do not prove protected
installation, application confinement or independently authenticated human consent.
Same-UID, administrator, process-debug, filesystem, backup or control-plane
access invalidates a real-key boundary. The fixed code/configuration identifiers
are fixture bindings, not attestation of an immutable runtime closure.

Protected custody and entry, genuine human enrollment, trusted operational time,
an independent anchor/fencing authority, lifecycle and provider support, host
assurance and exact operator choices remain open. `require_live_deployment()`
stays an unconditional refusal. No listener, deployment, service installation,
access/security change, real credential, provider operation or Sprite use is
authorized by this milestone.
