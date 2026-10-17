# Aegis

An experimental local capability broker for developer and agent workflows.

**Experimental capability broker; protected agent-blind application delivery is required but not yet implemented or verified.**

Aegis mediates between a human, an agent, and an application. A human privately provisions credentials and approves bounded authority. An agent can request a reviewed operation or propose configuring two systems using secret references. The intended broker either uses the credential for the approved operation or delivers it directly to an approved isolated application's protected file, descriptor, or credential store. The agent receives only validated results or safe delivery status and must be unable to read the delivered token. Keeping a token out of a model's context and preventing agent-executed code from reading it are separate responsibilities.

**Current stage: synthetic foundation.** This repository implements an in-memory Rust broker, a fake provider, an explicitly started Unix foreground broker, and a thin stdio MCP client. The opt-in [owner-controlled Sprite experiment](docs/sprite-demo.md) adds a loopback HTTP service, separate owner/agent authentication, exact owner review receipts, a generated fake key and an HTTP-backed stdio MCP client. An optional age experiment saves and restores only a fixed synthetic fixture in separate processes. There is no real credential input, live provider connection, operational vault, or production setup path. It is not independently audited. A same-user process is not an operating-system containment boundary.

## Owner-controlled Sprite experiment

Build with `cargo build --locked --features sprite-demo`, then use `aegis sprite-demo-init --state-dir <new-absolute-directory>` and `aegis sprite-demo-serve --state-dir <directory> --listen 127.0.0.1:7979`. The owner privately retains Sprite administration and `owner.key`; the agent receives only `agent.key` and uses bounded operations. The generated fake provider key remains inside the trusted broker. Provisioning, deployment and the remote TLS gateway/tunnel are owner-managed.

Run `python3 scripts/sprite_evidence.py --binary target/debug/aegis --output-dir Evidence/sprite-demo-local` to produce a fresh-key report, agent transcript and sanitized service log. The verifier checks successful use, role separation, exact approval, retries, revocation and restart behavior, then scans captured outputs for key disclosure. This is bounded API evidence, not proof of deployed OS/admin isolation. Follow the [complete setup and evidence guide](docs/sprite-demo.md) before deployment; use generated fake fixtures only.

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

## What is being built

The current bounded operation interface uses exact resource and credential bindings, explicit control approval, volatile foreground sessions, a fixed synthetic status adapter, and a thin stdio MCP client that shares the broker's policy engine. Protected application delivery is an essential additional product requirement, not an optional plaintext-export convenience. Its [design contract](docs/application-delivery.md) specifies reference-only proposals, immutable human approval, recipient enrollment, safe status, revocation limits, and adversarial acceptance gates. None of those delivery interfaces or OS protections are implemented. A useful live provider operation and an operational portable `age` backend also remain release work.

The synthetic foundation focuses on deterministic policy and request state: prepare, request approval, invoke, and inspect a result. Grant-use reservation and revocation share a broker-owned serialization point. Retrying a request ID must return existing state or explicit uncertainty; it must not silently repeat an unknown external effect.

The agent surface has no raw-secret method, arbitrary execution method, approval boolean, arbitrary URL proxy, or credential-input prompt. Planned delivery sends plaintext only between the trusted broker and an enrolled recipient. It requires separate service identities or an actually confined agent, protected recipient code/dependencies/configuration and process resources, and independently authenticated human control. An unrestricted same-UID agent, agent-writable recipient code or security-relevant configuration, or agent-controlled container/debug interface invalidates the guarantee. File mode `0600`, peer UID checks, and redaction alone are insufficient; unsupported delivery boundaries must fail closed.

## Read the contracts

| Document | Purpose |
| --- | --- |
| [Product and policy contracts](docs/contracts.md) | Authority objects, exact bindings, lifecycle, concurrency, retry, and error behavior |
| [Architecture](docs/architecture.md) | Component boundaries and current versus planned interfaces |
| [Protected application delivery](docs/application-delivery.md) | Required agent-blind configuration workflow, immutable approval, OS boundary, and implementation gates; design only |
| [Threat model](docs/threat-model.md) | Assets, adversaries, workflow limits, and evidence required for stronger modes |
| [Standalone binary](docs/standalone-binary.md) | Local release artifact, broker/client executable layout, runtime requirements and Mac-only evidence |
| [Owner-controlled Sprite demo](docs/sprite-demo.md) | Optional fake-secret HTTP/MCP workflow, private role credentials, operator deployment handoff and disclosure evidence |
| [Developer quickstart](docs/developer-quickstart.md) | Build, test, change, and debug safely |
| [Agent quickstart](docs/agent-quickstart.md) | Invoke bounded operations without supplying credentials or manufacturing approval |
| [Experimental protocol](docs/protocol.md) | JSON-lines version 1 methods, bounds, and result shapes |
| [Synthetic age spike](docs/storage-spike.md) | Optional two-process saved-fixture recovery experiment and its limits |
| [Verification](docs/verification.md) | Required scenarios, platform evidence, and unverified claims |
| [Independent review remediation](docs/review-checkpoint.md) | Reproduced defects, fixes, added regressions and interpretation limits |
| [Project status](docs/project-status.md) | Implemented deliverables, verification results, and remaining release work |
| [Roadmap](docs/roadmap.md) | Exit gates for storage, recovery, host integration, and a reviewed release |
| [Architecture decisions](docs/adr/README.md) | Frozen decisions and experiments still required |
| [Design provenance](docs/design-provenance.md) | Superseding input and primary documentation references |

## Platform and release status

The initial tested local target was macOS 26.6.2 on arm64 with Rust 1.96.1. See [verification](docs/verification.md) for current checks and limits. Linux peer-check code exists but is untested; Windows transport support is absent. The Sprite experiment adds distinct role-credential authentication, not physical human-presence proof. Protected application delivery, desktop lifecycle handling, protected headless client custody, storage durability, and OS isolation remain unimplemented or unverified. Linux, macOS, and Windows delivery arrangements are proposals requiring separate platform tests.

Aegis source and documentation are available under the [MIT license](LICENSE). Third-party dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the dependency inventory. Public source availability does not establish a reviewed production release. The [security policy](SECURITY.md) is a draft for this experimental project. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).
