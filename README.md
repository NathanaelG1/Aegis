# Aegis

An experimental Rust secret broker for developer tools and agent-managed applications.

Keep provider credentials on an owner-controlled host while applications run on hosts an agent can administer. Aegis supports several access patterns with different trust boundaries:

| Access pattern | How credentials are used | Current support |
| --- | --- | --- |
| **Service-scoped secret injection** | An authenticated service names secret references; Aegis injects them into an owner-approved HTTPS request. The service receives selected results. | Real encrypted storage, private provisioning/rotation, service ACLs and generic HTTP header injection on Linux/macOS (`proxy` feature). |
| **Broker-executed operations** | An agent requests a typed operation; a human reviews the exact plan and the broker performs it. | Synthetic provider workflows, owner approval and native HTTP/MCP clients. |
| **Protected application delivery** | The broker delivers a credential to a separately isolated application's protected channel or store. | Fixed-canary experiments and design contracts; operational delivery remains unimplemented. An agent-controlled recipient cannot keep a delivered key from that agent. |
| **Broker-held signing** | A private key stays in the broker while a constrained operation is signed. | Disposable-key signing experiments; no generic real-key signing endpoint. |

## Start with the secret-injection proxy

After publishing a release containing this feature:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/NathanaelG1/Aegis/main/install.sh | sh
```

The installer verifies the platform archive checksum and installs a native executable in `~/.local/bin`. No language runtime is needed. Older releases such as v0.0.3 do not contain the proxy; the installer refuses them. To use this checkout before its next release, run `cargo build --release --locked --features proxy --bin aegis`.

Then open the guided terminal interface on your private Aegis host:

```sh
aegis
```

If your shell does not include the installation folder in PATH, run
`~/.local/bin/aegis`; the installer prints the exact launch path.

The console opens with Aegis's ASCII shield logo and walks you through creating
a vault, adding a hidden API key, and connecting an application. Choose the
endpoint, HTTP method, secret bindings, permitted response fields and call
allowance through menus, then review and save. No policy JSON editing or setup
commands are required. The dashboard also handles secret replacement, service
pausing, token rotation, and starting/stopping a local proxy.

Use **arrow keys** to move, **Enter** to select, and **Esc** to go back.
Secrets stay hidden, policy drafts can be discarded, and saved changes survive
restart. A proxy started from this console runs until you stop it or exit;
unattended hosting uses your platform's service supervisor. See the
[terminal walkthrough](docs/secret-proxy.md#guided-terminal-setup).

### How applications call Aegis

An application's requests name the secret references to inject:

```json
{
  "request_id": "job-001",
  "operation": "create-message",
  "inject": ["service-api-key"],
  "body": {"message": "Hello"}
}
```

Aegis authenticates the service, checks its ACL and call allowance, attaches the key to the configured header, and calls the approved endpoint. Service credentials confer operation access; there is no raw-secret export API. Requests cannot supply arbitrary URLs or headers. TLS verification, response-field projection, rotation/revocation and durable replay protection enforce this boundary. See the [complete setup, service policy, API and recovery guide](docs/secret-proxy.md).

Run Aegis on its own owner-controlled Sprite or host, and the application on the agent-controlled host. Keep Aegis administration, snapshots, private state and TLS routing out of the agent's reach. The owner and configured upstream remain trusted. Generic injection supports HTTP header credentials; protocols requiring request signatures need a separate signing adapter. It does not impose application-specific business or financial limits. This experimental project has not been independently audited or verified with your live provider or deployed Sprite isolation.

## Owner-controlled Sprite experiment

For a prebuilt executable, see [downloadable binaries and installation](docs/releases.md). The tag-triggered release workflow builds Linux x64/arm64, macOS Intel/Apple Silicon and Windows x64 archives. Linux and macOS packages include the proxy, native Sprite client and `sprite-demo`; Windows currently provides only the synthetic CLI commands.

Build with `cargo build --locked --features proxy`, then use `aegis sprite-demo-init --state-dir <new-absolute-directory>` and `aegis sprite-demo-serve --state-dir <directory> --listen 127.0.0.1:7979`. The owner privately retains Sprite administration and `owner.key`; the agent receives only `agent.key` and uses bounded operations. The generated fake provider key remains inside the trusted broker. Provisioning, deployment and the remote TLS gateway/tunnel are owner-managed.

Run `cargo test --locked --features proxy --test sprite_workflow` for the native process/HTTP/MCP verifier. It checks successful use, role separation, exact approval, retries, revocation, restart behavior and key disclosure in captured client output. This is bounded API evidence, not proof of deployed OS/admin isolation. Follow the [complete setup and evidence guide](docs/sprite-demo.md); the Sprite demo uses generated fake fixtures only.

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

The first provider has a [fixed synthetic GitHub App exercise](docs/github-app.md): personal selected-repository binding, metadata-only token scope, mock JWT/exchange, bounded metadata results, expiry/refresh and explicit revocation tests. Run `cargo run --locked --offline --example github_app_spike`. It accepts no keys or live configuration. The subsequent [main-broker integration](docs/github-broker.md) adds an explicit synthetic V2 operation while preserving the legacy interface. A separate [synthetic intent journal](docs/github-intent-journal.md) tests sync-before-effect recording and read-only restart inspection with no restored authority. An optional [disposable-key signing experiment](docs/signing-spike.md) separately tests maintained-library RS256 and private sign-only leases; it accepts no keys. An explicit optional [approval-bound composition](docs/github-signed-composition.md) connects it to the synthetic broker while retaining the default mock path. Real-key custody and live use remain unavailable in that GitHub-specific experiment; the generic proxy is a separate access pattern.

## Integrated synthetic vault milestone

The optional [vault-to-recipient exercise](docs/vault-delivery-spike.md) now joins authenticated test principals, exact ACLs, separate signed approval, age-encrypted records, typed delivery/rotation and durable restart/revocation through the main broker. It accepts only fixed canaries and reports real-key readiness as false. Operator-owned entry, production adapters and the [verified deployment ceremony](docs/operator-owned-deployment.md) remain required.

## Access-control direction

The protected-delivery design uses [vendor-neutral application authentication and exact ACLs](docs/access-control.md), with independent human control. Operators may add their own private networking; network membership or an IP allowlist never grants application access. A [TLS 1.3 fixture](docs/tls-transport.md) carries the experimental vault protocol over mutually authenticated encrypted records. Operational enrollment and independent human identity remain unavailable for protected delivery. The separate secret proxy implements service-token authentication and configurable operation/secret ACLs.

## Protected mechanism milestone

The optional vault feature now includes three executable mechanisms:

- [Mutually authenticated TLS](docs/tls-transport.md) with exact fixture peer/role binding and exporter-bound frames, carrying a reviewed canary delivery through the existing protocol.
- [Bounded encrypted import](docs/protected-entry.md), using zeroizing input buffers, frozen review metadata and ciphertext-only no-clobber publication. The only accepted value is a built-in disposable canary.
- [Separate recipient execution](docs/recipient-process.md), using a fixed child executable, recipient-only runtime custody, bounded inherited IPC and the existing durable reservation/receipt path.

The import and transport/recipient drills remain separate experiments. They do
not form an operational human-entry-to-isolated-application service. The child
shares the development UID and host control plane and is explicitly reported as
UNISOLATED. Protected human interaction, operational custody/recovery, an
independent rollback anchor and operator-controlled host evidence remain open;
real-key entry is unconditionally refused. See [ADR 0018](docs/adr/0018-protected-mechanism-development.md)
and the [operator trial plan](docs/operator-live-trial-plan.md).

## What is being built

The current bounded operation interface uses exact resource and credential bindings, explicit control approval, volatile foreground sessions, a fixed synthetic status adapter, and a thin stdio MCP client that shares the broker's policy engine. Protected application delivery is an essential additional product requirement, not an optional plaintext-export convenience. Its [design contract](docs/application-delivery.md) specifies reference-only proposals, immutable human approval, recipient enrollment, safe status, revocation limits, and adversarial acceptance gates. The optional vault feature exercises delivery interfaces using fixed fixtures; production entry, external recipient integration and OS protections remain unimplemented or unverified. The separate secret proxy provides encrypted age storage and live HTTPS header injection; it does not complete protected application delivery.

The synthetic foundation focuses on deterministic policy and request state: prepare, request approval, invoke, and inspect a result. Grant-use reservation and revocation share a broker-owned serialization point. Retrying a request ID must return existing state or explicit uncertainty; it must not silently repeat an unknown external effect.

The agent surface has no raw-secret method, arbitrary execution method, approval boolean, arbitrary URL proxy, or credential-input prompt. Planned delivery sends plaintext only between the trusted broker and an enrolled recipient. It requires separate service identities or an actually confined agent, protected recipient code/dependencies/configuration and process resources, and independently authenticated human control. An unrestricted same-UID agent, agent-writable recipient code or security-relevant configuration, or agent-controlled container/debug interface invalidates the guarantee. File mode `0600`, peer UID checks, and redaction alone are insufficient; unsupported delivery boundaries must fail closed.

## Read the contracts

| Document | Purpose |
| --- | --- |
| [Product and policy contracts](docs/contracts.md) | Authority objects, exact bindings, lifecycle, concurrency, retry, and error behavior |
| [Architecture](docs/architecture.md) | Component boundaries and current versus planned interfaces |
| [Integrated synthetic vault](docs/vault-delivery-spike.md) | Encrypted canary delivery/rotation through authenticated core policy and durable recovery |
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
| [Secret-injection proxy](docs/secret-proxy.md) | Private provisioning, service ACLs, approved HTTPS headers and bounded results |
| [Owner-controlled Sprite demo](docs/sprite-demo.md) | Optional fake-secret HTTP/MCP workflow, private role credentials, operator deployment handoff and disclosure evidence |
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

The original full checkpoint was tested on macOS 26.6.2 arm64 with Rust 1.96.1. The subsequent GitHub synthetic slice and existing non-listener suites pass on Linux x86_64; 14 existing interface tests remain blocked there by denied Unix listener binding. See [verification](docs/verification.md) for exact checks and limits. A later private Linux synthetic pilot passed all baseline tests and actual GitHub foreground/MCP v2 workflow on source `e353a6b`; this is workflow evidence, not protection from its current agent administrative access. Windows transport support is absent. Protected application delivery, independent human authentication, desktop lifecycle handling, protected headless approval, durability for the original synthetic broker, and OS isolation remain unimplemented or unverified. Linux, macOS, and Windows delivery arrangements are proposals requiring separate platform tests. The Sprite experiment adds distinct role-credential authentication, not physical human-presence proof.

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
