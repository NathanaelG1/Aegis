# ADR 0007: Required protected application delivery

**Status:** Accepted product requirement; design only, enforcement and implementation pending. **Date:** 2026-10-06.

## Context

Developers need an agent to arrange configuration of two systems while never reading or being able to read the token delivered to the recipient application. Reviewed broker operations alone do not satisfy that requirement. Earlier references to an optional trusted-consumer runner did not define the needed OS boundary or immutable delivery approval.

## Decision

Require a typed secret-reference-only proposal, separate authenticated human approval, direct broker-to-enrolled-application delivery, safe scoped status and explicit revocation workflow. Bind approval to the agent principal/session, exact credential version, service/executable/build/dependencies, protected configuration revision, destination slot/mechanism, provider endpoint/scope and lifetime/use limits. The recipient must not load mutable security-relevant code or configuration from the agent workspace.

The credential may reach only the approved recipient's protected file, descriptor/handle or credential store. No generic export, shell execution, arbitrary endpoint or plaintext-return route is introduced. Separate service identities or actual agent confinement must protect files, process memory, handles and independent human authority. Unrestricted same-UID access, mutable recipient inputs and agent-controlled container/debug interfaces invalidate the guarantee; unsupported boundaries fail closed. Peer UID checks, mode `0600` and redaction are insufficient.

Retain uncertain handoffs without automatic retry. Revoking future broker delivery does not erase delivered plaintext; report local cleanup, recipient termination and provider revocation separately. File installation must address symlink/hardlink, parent/mount/object races, atomic installation and crash recovery in enrolled protected directories.

The full proposed [delivery contract and adversarial gates](../application-delivery.md) are authoritative for this requirement. Linux, macOS and Windows arrangements are proposals only. No real-secret use, permission changes or service installation is authorized by this ADR.

## Consequences and supersession

The implemented operation-first synthetic foundation remains useful and unchanged. This ADR supersedes the optional consumer-delivery direction in ADR 0001 and adds required application delivery to its product scope; it does not replace its synthetic-only implementation decision. It extends ADR 0002's human/host boundary requirements and ADR 0003's reservation/retry principles to a future durable delivery protocol.

Existing tests do not establish agent-blind delivery. Freeze schemas and implement adapters only after boundary/approval and protected-destination spikes, then complete the synthetic adversarial and platform fault matrix before any delivery guarantee. The project's current description is: experimental capability broker; protected agent-blind application delivery is required but not yet implemented or verified.
