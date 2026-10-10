# ADR 0021: Fixed application-file installation

Status: accepted for canary-only implementation, 10 October 2026; implementation
and acceptance evidence pending. Operational deployment remains unavailable.

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
The normal composition may use the one imported version; focused two-version
replacement tests must be identified separately from that composed path.

Gate the increment behind the optional `application-slot` feature, which
includes `vault-spike` and pinned `rustix` 1.1.5 filesystem support. The fixed
target is `application/provider-auth`, the stage is
`application/.provider-auth.stage`, and signed append-only installation evidence
is stored in `application/installation.jws` beneath the disposable root.

The new recipient must validate the writer-signed capsule, its exact recipient,
configuration, slot, version and expected generation. Installation evidence must
bind the delivery/request and capsule to the installed version and generation.
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
5. An exact completed duplicate returns existing evidence without another file
   effect. Changed bindings or stale generations fail closed. Inspection reads
   and validates existing evidence; it performs no repair, cleanup or replay.

An atomic rename is one namespace transition, not a transaction spanning broker
journal, recipient intent, application file and receipt. A crash after possible
installation but before durable acknowledgement may leave the canary present
with an unknown broker outcome. Retaining uncertainty is the required result.
Fail-closed handling does not promise that an installed value was removed.

Directory-relative safe APIs may be supplied by an optional filesystem
dependency. Its selection must preserve the repository's forbidden-unsafe-code
policy and default dependency boundary. Maintainer documentation for
[`rustix::fs::openat`](https://docs.rs/rustix/1.1.5/rustix/fs/fn.openat.html)
specifies a safe directory-relative API returning an owned file descriptor;
[`renameat`](https://docs.rs/rustix/1.1.5/rustix/fs/fn.renameat.html) accepts the
source and destination directory handles. These APIs permit handle-relative
operations; they do not themselves establish protected ownership, reject every
alias or mount substitution, or prove the full durability protocol.
The [crate documentation](https://docs.rs/rustix/1.1.5/rustix/) explicitly leaves
ambient authority, sandboxing and significant platform differences to callers.
Using these wrappers does not establish confinement.

## Required functional evidence

The [application-slot contract](../application-slot.md) records the acceptance
matrix and, when completed, exact-source results. Cover positive installation
of the actual imported canary, independent file-content observation, unchanged
duplicate installation, signed receipt/generation validation and read-only
reopen. Exercise focused replacement and failures at intent, staging, file-sync,
replacement, directory-sync, receipt and acknowledgement boundaries. Missing or
substituted files, links and stale/invalid receipts must not silently continue.
Identify component simulations separately from real child termination and
composed execution. Preserve default-feature refusal and existing drills.

At acceptance-contract publication, this milestone has no recorded test pass.
Historical PR #4 process-service CI does not cover the new slot implementation.
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
