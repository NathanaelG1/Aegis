# Security policy — experimental draft

Aegis is a synthetic-only local prototype, not a supported secrets product or an independently reviewed release. There is no supported production version. Private reporting, response targets, a release maintenance policy, and a disclosure coordinator have not been established. Public source availability does not create a security-supported release.

## Current use boundary

Use only synthetic fixtures. No persistent real-secret setup, live provider adapter, credential migration, unattended unlock, or production use is available in this checkpoint. The embedding process is trusted with the control capability and any credential material it owns. Separate Rust handles, foreground terminal control, the Unix agent socket, and a thin MCP bridge demonstrate workflow/API separation. Current-UID checks and terminal inspection do not prove human presence or contain arbitrary same-user code. The explicit synthetic control-pipe flag is a test facility.

The optional age feature saves and restores only a fixed synthetic fixture in separate processes. It cannot initialize an operational vault or restore broker authority, and never establishes real-secret readiness. See [the spike evidence and limits](docs/storage-spike.md).

The authoritative guarantees and limitations are in [contracts](docs/contracts.md), [threat model](docs/threat-model.md), and [verification](docs/verification.md). Do not infer containment from the absence of a `get_secret` endpoint.

## Reporting experimental concerns

Use GitHub issues only for non-sensitive synthetic reproductions. Do not publish real credentials, private operational data, or exploit details affecting a production system. This repository does not establish a monitored private security inbox or a response-time guarantee. For a safe synthetic report, provide:

- The local revision and tested platform/toolchain.
- A minimal synthetic reproduction and the affected trust boundary.
- Expected and observed authorization or disclosure behavior.
- Whether an external effect might have occurred and whether retry is safe.

Exclude real tokens, recovery material, raw vault contents, and operational private data. If a prototype appears to dispatch an unauthorized request or disclose a synthetic canary, stop that test harness and preserve the minimal reproduction. Do not probe a production system to demonstrate the issue.

## Before a reviewed release

Select a private reporting route and disclosure policy, name patch ownership, define maintained versions, and commission independent composition review. Review must include approvals, agent/host boundaries, adapters, output contracts, concurrency, storage/recovery, and each supported platform. Record reviewed commits and remediations. A dependency scan or encryption interoperability test alone cannot establish these guarantees.

New security-sensitive behavior requires an updated threat model, tests, and ADR. Release claims must match demonstrated enforcement on the named host, OS, architecture, feature set, and filesystem.
