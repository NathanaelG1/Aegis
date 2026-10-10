# Aegis

An experimental local capability broker for developer and agent workflows.

**Experimental capability broker; protected agent-blind application delivery is required but not yet implemented or verified.**

Aegis mediates between a human, an agent, and an application. A human privately provisions credentials and approves bounded authority. An agent can request a reviewed operation or propose configuring two systems using secret references. The intended broker either uses the credential for the approved operation or delivers it directly to an approved isolated application's protected file, descriptor, or credential store. The agent receives only validated results or safe delivery status and must be unable to read the delivered token. Keeping a token out of a model's context and preventing agent-executed code from reading it are separate responsibilities.

The primary intended workflow is episodic project setup and secret delivery/rotation, with a [wake-on-request-compatible broker lifecycle](docs/application-delivery.md#request-driven-lifecycle). After protected delivery, the recipient can use its provider directly while Aegis is idle. Per-call broker mediation is a separate optional mode; protected delivery and wake lifecycle remain unimplemented.

**Current stage: synthetic foundation.** This repository implements an in-memory Rust broker, a fake provider, an explicitly started Unix foreground broker, and a thin stdio MCP client. An optional age experiment saves and restores only a fixed synthetic fixture in separate processes. There is no real credential input, live provider connection, operational vault, or production setup path. It is not independently audited. A same-user process is not an operating-system containment boundary.

## Try the synthetic demo

Clone this repository, then run from its directory with Rust and Cargo installed:

```sh
git clone https://github.com/NathanaelG1/Aegis.git
cd Aegis
```

```sh
cargo run --locked --offline -- demo
cargo test --locked --offline
```

The checkout pins Rust 1.96.1; its manifest declares Rust 1.96 and edition 2021. The demo exercises the library's separate control and agent handles with synthetic fixture data. Offline commands require the locked dependencies to be available in Cargo's local cache.

For a separate human terminal and agent client, use `aegis synthetic-broker --socket-dir <new-absolute-directory>` and `aegis mcp --socket <directory>/agent.sock`. The [developer quickstart](docs/developer-quickstart.md) explains the terminal workflow; the [agent quickstart](docs/agent-quickstart.md) gives the MCP messages. Terminal and same-account peer checks demonstrate workflow separation, with no proof of genuine human presence or containment.

## GitHub App preparation

The first provider has a [fixed synthetic GitHub App exercise](docs/github-app.md): personal selected-repository binding, metadata-only token scope, mock JWT/exchange, bounded metadata results, expiry/refresh and explicit revocation tests. Run `cargo run --locked --offline --example github_app_spike`. It accepts no keys or live configuration. The subsequent [main-broker integration](docs/github-broker.md) adds an explicit synthetic V2 operation while preserving the legacy interface. A separate [synthetic intent journal](docs/github-intent-journal.md) tests sync-before-effect recording and read-only restart inspection with no restored authority. An optional [disposable-key signing experiment](docs/signing-spike.md) separately tests maintained-library RS256 and private sign-only leases; it accepts no keys. An explicit optional [approval-bound composition](docs/github-signed-composition.md) connects it to the synthetic broker while retaining the default mock path. Real-key custody and live use remain unavailable.

## Integrated synthetic vault milestone

The optional [vault-to-recipient exercise](docs/vault-delivery-spike.md) now joins authenticated test principals, exact ACLs, separate signed approval, age-encrypted records, typed delivery/rotation and durable restart/revocation through the main broker. It accepts only fixed canaries and reports real-key readiness as false. Operator-owned entry, production adapters and the [verified deployment ceremony](docs/operator-owned-deployment.md) remain required.

## Access-control direction

The planned network API uses [vendor-neutral application authentication and exact ACLs](docs/access-control.md), with independent human control. Operators may add their own private networking; network membership or an IP allowlist never grants application access. A [TLS 1.3 fixture](docs/tls-transport.md) now carries the existing vault protocol over mutually authenticated encrypted records. It has no network listener, operational enrollment or independent human identity. The deployed network API and configurable operational ACLs remain unavailable.

## Protected mechanism milestone

The optional vault feature now includes three executable mechanisms:

- [Mutually authenticated TLS](docs/tls-transport.md) with exact fixture peer/role binding and exporter-bound frames, carrying a reviewed canary delivery through the existing protocol.
- [Bounded encrypted import](docs/protected-entry.md), using zeroizing input buffers, frozen review metadata and ciphertext-only no-clobber publication. The only accepted value is a built-in disposable canary.
- [Separate recipient execution](docs/recipient-process.md), using a fixed child executable, recipient-only runtime custody, bounded inherited IPC and the existing durable reservation/receipt path.

The standalone drills remain available. A [composed canary flow](docs/composed-canary-flow.md)
also consumes the actual encrypted import, authenticates agent/admin approval
and invocation through TLS, and delivers the signed age capsule to the fixed
child over inherited local IPC. It exercises one imported version, duplicate
reuse, fresh authentication and durable revoke. TLS terminates at the parent
fixture's control endpoints; the recipient child does not terminate TLS.

```sh
cargo run --locked --offline --all-features --bin aegis-composed-canary -- /tmp/aegis-composed-new
cargo run --locked --offline --all-features --bin aegis-composed-canary -- inspect /tmp/aegis-composed-new
```

The destination must be new and absolute. This accepts only a built-in canary
and reports fixture evidence. The child shares the development UID and host
control plane and is explicitly UNISOLATED. Protected human interaction,
operational custody/recovery, an independent rollback anchor and observed
operator-host protection remain open; real-key entry is unconditionally refused.
See [ADR 0018](docs/adr/0018-protected-mechanism-development.md),
[ADR 0019](docs/adr/0019-composed-canary-delivery.md), and the
[operator trial plan](docs/operator-live-trial-plan.md).

## Broker process service milestone

The [fixed-canary process service](docs/process-service.md) moves the broker and
both TLS server endpoints into a child process. Separate simulated clients drive
actual bounded Unix socket I/O; a supervisor owns and reaps the broker and fixed
recipient children. The broker runtime loads neither client signing/TLS private
keys nor recipient private keys. Duplicate, cold authentication, revoke and
lost-response behavior retain the existing durable policy outcomes.

```sh
cargo run --locked --offline --all-features --bin aegis-process-service -- /tmp/aegis-service-new
cargo run --locked --offline --all-features --bin aegis-process-service -- inspect /tmp/aegis-service-new
```

All processes still share the development UID and control plane. Bootstrap
briefly owns all disposable keys, approvals remain simulated, and journal time
remains fixed fixture time. There is no listener or protected operational entry;
all live-key gates remain false. See [ADR 0020](docs/adr/0020-process-owned-dummy-broker-service.md).

## Fixed application-slot milestone

The optional [application-slot drill](docs/application-slot.md) extends the
process service by installing the actual imported canary into the fixed
`application/provider-auth` file. Directory-relative operations use held handles;
a signed intent precedes staging, and a signed installation receipt follows
file sync, replacement and directory sync. Import, review and delivery bind
adapter/output contracts 2/2, separate from legacy encrypted acceptance.

```sh
cargo run --locked --offline --features application-slot --bin aegis-application-slot -- /tmp/aegis-slot-new
cargo run --locked --offline --features application-slot --bin aegis-application-slot -- inspect /tmp/aegis-slot-new
```

The application file intentionally contains the public canary. A valid pending
intent can be inspected without completing or replaying installation; an
uncertain broker outcome stays consumed. The normal composed drill installs
one imported version, while focused tests exercise two-version replacement.
This is a same-UID fixture, with no operational protected application, real-key
entry or live provider. See [ADR 0021](docs/adr/0021-fixed-application-slot.md)
and the remaining [operator decisions](docs/operator-live-trial-plan.md).

## What is being built

The current bounded operation interface uses exact resource and credential bindings, explicit control approval, volatile foreground sessions, a fixed synthetic status adapter, and a thin stdio MCP client that shares the broker's policy engine. Protected application delivery is an essential additional product requirement, not an optional plaintext-export convenience. Its [design contract](docs/application-delivery.md) specifies reference-only proposals, immutable human approval, recipient enrollment, safe status, revocation limits, and adversarial acceptance gates. The optional vault feature exercises delivery interfaces using fixed fixtures; production entry, external recipient integration and OS protections remain unimplemented or unverified. A useful live provider operation and an operational portable `age` backend also remain release work.

The synthetic foundation focuses on deterministic policy and request state: prepare, request approval, invoke, and inspect a result. Grant-use reservation and revocation share a broker-owned serialization point. Retrying a request ID must return existing state or explicit uncertainty; it must not silently repeat an unknown external effect.

The agent surface has no raw-secret method, arbitrary execution method, approval boolean, arbitrary URL proxy, or credential-input prompt. Planned delivery sends plaintext only between the trusted broker and an enrolled recipient. It requires separate service identities or an actually confined agent, protected recipient code/dependencies/configuration and process resources, and independently authenticated human control. An unrestricted same-UID agent, agent-writable recipient code or security-relevant configuration, or agent-controlled container/debug interface invalidates the guarantee. File mode `0600`, peer UID checks, and redaction alone are insufficient; unsupported delivery boundaries must fail closed.

## Read the contracts

| Document | Purpose |
| --- | --- |
| [Product and policy contracts](docs/contracts.md) | Authority objects, exact bindings, lifecycle, concurrency, retry, and error behavior |
| [Architecture](docs/architecture.md) | Component boundaries and current versus planned interfaces |
| [Integrated synthetic vault](docs/vault-delivery-spike.md) | Encrypted canary delivery/rotation through authenticated core policy and durable recovery |
| [Composed fixed-canary flow](docs/composed-canary-flow.md) | Actual encrypted import through TLS approval, durable broker and fixed child receipt; retained NO-GO gates |
| [Fixed-canary broker process service](docs/process-service.md) | Owned broker/client TLS I/O, supervised children and real response-loss regressions |
| [Fixed application-file installation](docs/application-slot.md) | Actual canary file replacement, signed installation evidence and read-only uncertainty inspection |
| [Operator-owned deployment](docs/operator-owned-deployment.md) | Required privilege separation, canary verification and later user key-entry ceremony |
| [Application authentication and ACLs](docs/access-control.md) | Vendor-neutral identity/policy, optional private networking, proxy trust and acceptance gates |
| [Readiness and deployment choices](docs/readiness-checklist.md) | Consolidated missing end-to-end gates, required permissions, verification plan and effort estimate |
| [Approval-bound signing](docs/github-signed-composition.md) | Optional reviewed synthetic broker/signing composition and retained failure semantics |
| [GitHub broker integration](docs/github-broker.md) | Main policy engine, reviewed approval, V2 protocol/MCP and broker-bound journals |
| [Synthetic GitHub journal](docs/github-intent-journal.md) | Pre-effect records, crash inspection, strict decoding and trusted-storage limits |
| [GitHub App preparation](docs/github-app.md) | Synthetic provider-boundary implementation, setup guidance and remaining deployment gates |
| [Protected application delivery](docs/application-delivery.md) | Required agent-blind configuration workflow, immutable approval, OS boundary, and implementation gates; design only |
| [Threat model](docs/threat-model.md) | Assets, adversaries, workflow limits, and evidence required for stronger modes |
| [Standalone binary](docs/standalone-binary.md) | Local release artifact, broker/client executable layout, runtime requirements and Mac-only evidence |
| [Developer quickstart](docs/developer-quickstart.md) | Build, test, change, and debug safely |
| [Agent quickstart](docs/agent-quickstart.md) | Invoke bounded operations without supplying credentials or manufacturing approval |
| [Experimental protocol](docs/protocol.md) | JSON-lines version 1 methods, bounds, and result shapes |
| [Optional signing spike](docs/signing-spike.md) | Disposable RSA keys, strict JWT policy, private key-source lifecycle and optional native dependency costs |
| [Synthetic age spike](docs/storage-spike.md) | Optional two-process saved-fixture recovery experiment and its limits |
| [Verification](docs/verification.md) | Required scenarios, platform evidence, and unverified claims |
| [Independent review remediation](docs/review-checkpoint.md) | Reproduced defects, fixes, added regressions and interpretation limits |
| [Project status](docs/project-status.md) | Implemented deliverables, verification results, and remaining release work |
| [Roadmap](docs/roadmap.md) | Exit gates for storage, recovery, host integration, and a reviewed release |
| [Architecture decisions](docs/adr/README.md) | Frozen decisions and experiments still required |
| [Design provenance](docs/design-provenance.md) | Superseding input and primary documentation references |

## Platform and release status

The original full checkpoint was tested on macOS 26.6.2 arm64 with Rust 1.96.1. Later exact-source hosted Linux checks include all Unix interface tests; the development workspace still denies 14 listener-dependent cases. See [verification](docs/verification.md) for each source, result and platform limit. A private Linux synthetic pilot also passed its baseline tests and actual GitHub foreground/MCP v2 workflow on source `e353a6b`; this is workflow evidence, not protection from its agent administrative access. Windows transport support is absent. Protected application delivery, independent human authentication, desktop lifecycle handling, protected headless approval, operational storage durability, and OS isolation remain unimplemented or unverified. Linux, macOS, and Windows delivery arrangements are proposals requiring separate platform tests.

Aegis source and documentation are available under the [MIT license](LICENSE). Third-party dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the dependency inventory. Public source availability does not establish a reviewed production release. The [security policy](SECURITY.md) is a draft for this experimental project. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).

The optional vault milestone also has [separate agent/admin protocol handlers](docs/vault-protocol.md) with role-specific runtime key ownership. These are bounded library connection handlers for fixed-canary fixtures; no HTTP listener, real-secret entry or production enrollment is enabled.

## Adapter foundation milestone

Three fixed-fixture modules exercise [operator-entry state](docs/operator-entry-contract.md), [recipient handoff](docs/recipient-adapter-contract.md), and [peer-bound transport framing](docs/vault-transport-contract.md). These are executable adapter contracts, not production implementations. The recipient fixture remains separate from the durable runtime; no live entry, TLS listener, protected custody, external anchor or independently authenticated human interface is enabled. See [ADR 0017](docs/adr/0017-synthetic-adapter-foundations.md) and [source recovery provenance](docs/source-recovery-2026-10-07.md).

Run all three safe report drills with `cargo run --locked --offline --all-features --example adapter_foundations -- /tmp/aegis-adapter-demo-new`. The destination must not already exist; it contains disposable fixture state.

## Operator-controlled trial work

The next fixed-fixture milestone loads broker, recipient, agent and administrator
material from separate role documents and uses the existing durable protocol.
The report-only deployment prerequisites remain NO-GO and do not inspect a host
or issue authority. See [separate custody](docs/custody-spike.md),
[deployment prerequisites](docs/deployment-admission.md) and the
[operator-controlled GitHub App trial plan](docs/operator-live-trial-plan.md).
The first use case remains selected personal repositories, with no organization
access. Real key entry and live GitHub calls remain disabled.
