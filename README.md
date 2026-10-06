# Aegis

An experimental local capability broker for developer and agent workflows.

Aegis's intended contract is: a human privately provisions credentials and approves bounded authority; an agent invokes a reviewed operation; the broker uses the credential locally and returns only a validated result. Keeping a token out of a model's context and making an action safe are separate responsibilities.

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

## What is being built

The current bounded operation interface uses exact resource and credential bindings, explicit control approval, volatile foreground sessions, a fixed synthetic status adapter, and a thin stdio MCP client that shares the broker's policy engine. A useful live provider operation and an operational portable `age` backend remain release work.

The synthetic foundation focuses on deterministic policy and request state: prepare, request approval, invoke, and inspect a result. Grant-use reservation and revocation share a broker-owned serialization point. Retrying a request ID must return existing state or explicit uncertainty; it must not silently repeat an unknown external effect.

The agent surface has no raw-secret method, arbitrary execution method, approval boolean, arbitrary URL proxy, or credential-input prompt. The future trusted-consumer delivery path deliberately transfers plaintext and will require a separate contract and review.

## Read the contracts

| Document | Purpose |
| --- | --- |
| [Product and policy contracts](docs/contracts.md) | Authority objects, exact bindings, lifecycle, concurrency, retry, and error behavior |
| [Architecture](docs/architecture.md) | Component boundaries and current versus planned interfaces |
| [Threat model](docs/threat-model.md) | Assets, adversaries, workflow limits, and evidence required for stronger modes |
| [Standalone binary](docs/standalone-binary.md) | Local release artifact, broker/client executable layout, runtime requirements and Mac-only evidence |
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

The tested local target is macOS 26.6.2 on arm64 with Rust 1.96.1. See [verification](docs/verification.md) for checks and limits. Linux peer-check code exists but is untested; Windows transport support is absent. Desktop lifecycle handling, protected headless approval, storage durability, and stronger host isolation remain unverified.

Aegis source and documentation are available under the [MIT license](LICENSE). Third-party dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the dependency inventory. Public source availability does not establish a reviewed production release. The [security policy](SECURITY.md) is a draft for this experimental project. Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).
