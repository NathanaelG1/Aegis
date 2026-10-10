# ADR 0020: Process-owned dummy broker service

Status: accepted for fixed-canary implementation; operational deployment remains unavailable.

## Context

ADR 0019 composes the actual encrypted import, authenticated approval and durable
recipient delivery. Its agent/admin TLS peers and actor signers still execute
inside one parent fixture. Encrypted records moving through memory do not test
actual blocked I/O, peer disconnects or broker-process termination.

## Decision

Add a fixed dummy broker process with two inherited Unix socketpairs: one
agent role and one administrator role. Each connection owns its own Rustls
client or server state and uses the existing TLS 1.3 peer validation,
role-specific ALPN, exact certificate pins, exporter binding and bounded frames.
There is no listener, address selector or new network exposure.

The broker owns its store, protocol and existing core authority. Actor signing
stays outside that process. Broker runtime loading must not require agent or
administrator private signing keys or TLS client private keys. Disposable
bootstrap may temporarily control all fixture material; this is not independent
provisioning or protected custody.

A fixed supervisor owns both broker and recipient child handles. The broker
receives the existing recipient IPC connection, while the supervisor retains
the ability to terminate and reap both children after normal or abnormal
closure. No arbitrary executable, shell, environment or endpoint selector is
introduced. The child descriptor roles are immutable startup bindings, not
fields supplied in an agent protocol request.

Use the actual bounded import and existing signed manifest, durable reservation,
capsule and receipt path. Do not introduce another approval engine or regenerate
the standalone fixture store. Preserve consumed uncertainty after an ambiguous
effect, exact duplicate handling, fresh authentication on restart and durable
revoke. The initial version remains one fixed imported canary.

Socket reads and writes require absolute deadlines and bounded work/bytes.
Short I/O, interruption, final-byte expiry, EOF, process exit and protocol errors
must close the owning connection without automatic retransmission. Finite
transport checks do not promise preemption of native crypto or filesystem calls.
Two fixed inherited channels bound admission for this increment; a deployed
connection acceptor remains separate work.

## Evidence required

Test the actual TLS socket driver, fixed broker process and existing recipient
transport. Distinguish failures before reservation from uncertain effects after
reservation. Exercise process cleanup, partial/stalled I/O, disconnect and lost
responses. Record whether each fault traverses the full composition or only a
focused component. Preserve the standalone and composed regression suites.

The public interface accepts only disposable fixture destinations and returns
closed reports. It cannot accept a real value, private key, executable, generic
transport configuration, readiness claim or public fault-control API.

## Unchanged deployment boundary

All processes share the development account and host control plane. Separate
processes, authenticated IPC and signer ownership do not establish human
presence, same-UID confinement, immutable installation or protected recovery.
Operational input/custody, independent human enrollment, deployed transport and
time, actual application installation, external anchor/fencing, lifecycle/audit
and the live GitHub adapter remain unfinished.

`require_live_deployment()` stays an unconditional refusal. No real credential,
grant, listener, service installation, security/network change, provider call or
Sprite wake is part of this increment. The stopped independent adversarial
review remains unresolved; these implementation tests do not resume or replace it.
