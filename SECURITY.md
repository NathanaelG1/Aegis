# Security policy — experimental draft

Aegis is an experimental capability broker with an opt-in real-secret HTTP injection proxy. It is not an independently reviewed release. There is no security-supported production version. Private reporting, response targets, a release maintenance policy, and a disclosure coordinator have not been established. Public source availability does not create a security-supported release.

## Current use boundary

The guided terminal console is an owner-local interface to the same proxy APIs.
It never displays stored provider keys or service-token values. Anyone with the
owner's terminal/account access can administer the vault; the UI is not another
authentication or isolation boundary. Proxy processes started by the console are
stopped on normal confirmed exit; uncertain in-flight outcomes remain subject to
the durable request journal.

The Unix `proxy` feature accepts operational credentials through owner-local hidden input or bounded stdin, encrypts them with age, and injects them only into configured HTTPS operations for authenticated services. It has no secret-export or remote owner API. The host owner, administrator, installed code, configured upstream and selected response contract are trusted. Service tokens grant API operation authority, not arbitrary secret access. A compromised authorized service can exercise every operation it is granted. Generic header injection does not enforce provider-specific business rules or implement request signing. See [the complete boundary, backup and response limitations](docs/secret-proxy.md) and [ADR 0020](docs/adr/0020-service-scoped-secret-injection.md).

The optional owner-controlled [Sprite fake-secret workflow](docs/sprite-demo.md) adds distinct role authentication over loopback HTTP and requires an owner-managed protected transport for remote clients. Its fake fixture is plaintext on owner-controlled disk; there is no real-secret input. Owner-token possession is not physical human presence. The reproducible evidence harness checks the exercised API/MCP and captures, not deployed administrator/filesystem/memory isolation. Do not expose the loopback API through an unprotected/public forwarding route, give agents Sprite administration, or infer confidentiality from model vendor selection. See [ADR 0019](docs/adr/0019-owner-controlled-sprite-demo.md).

Use only synthetic fixtures for the existing demo/spike commands and automated tests. They retain their original gates and do not accept operational credentials. The embedding process is trusted with the control capability and any credential material it owns. Separate Rust handles, foreground terminal control, the Unix agent socket, and a thin MCP bridge demonstrate workflow/API separation. Current-UID checks and terminal inspection do not prove human presence or contain arbitrary same-user code. The explicit synthetic control-pipe flag is a test facility.

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
