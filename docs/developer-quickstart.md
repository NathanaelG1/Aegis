# Developer quickstart

This workflow exercises synthetic data in the dedicated Aegis checkout. It needs no account, token, password, provider, operational vault, or OS security change.

Protected agent-blind application delivery is required but not yet implemented or verified. Read its [design](application-delivery.md) and [implementation gates](roadmap.md#d--protected-application-delivery) before proposing any recipient integration. The current binary has no protected-file, descriptor or credential-store delivery path. These instructions do not enroll services, modify OS permissions or authorize real credential input.

## Build and inspect

The crate is `aegis-broker`; its Rust library is `aegis` and its executable is `aegis`. Package publication is disabled. `rust-toolchain.toml` pins Rust 1.96.1; the package declares Rust 1.96 and edition 2021. The resolved optional graph includes dependencies using newer editions, so the earlier core-only Rust 1.80.1 check is historical, not support for the current graph.

From this directory:

```sh
rustc --version
cargo --version
cargo run --locked --offline -- demo
cargo test --locked --offline
```

`--locked` verifies that Cargo can use the committed dependency resolution without changing it. `--offline` avoids dependency network access; it succeeds only when the locked packages are already cached. A missing cache entry is an environment blocker, not a reason to silently change versions or enable a live provider.

The scripted demo exercises trusted control and untrusted agent views in one process. Tests use synthetic fixtures and deterministic clocks/fake executors. A separate foreground process and agent MCP client are also implemented for the synthetic workflow below.

## Standalone executable

After `cargo build --release --locked --offline --bin aegis`, invoke the resulting `target/release/aegis` directly from another directory. A custom `CARGO_TARGET_DIR` changes that artifact path. Rust/Cargo and the checkout are build inputs; the tested default-feature commands run without them or configuration/assets at runtime. One executable supplies both foreground broker and MCP client modes, launched as separate processes. See [standalone verification](standalone-binary.md) for the exact tested artifact, empty-environment workflows, macOS system-library dependencies and platform limits.

## Human terminal and MCP client

Build once, then start the foreground broker from a human terminal in the repository. Use a short canonical temporary parent so a deeply nested checkout does not exceed the Unix socket path limit:

```sh
cargo build --locked --offline
demo_parent="$(mktemp -d /tmp/aegis-demo.XXXXXX)"
demo_parent="$(cd "$demo_parent" && pwd -P)"
session_dir="$demo_parent/session"
cargo run --locked --offline -- synthetic-broker --socket-dir "$session_dir"
```

The destination must be a new absolute directory whose parent already exists without symlink components. The complete socket path, including `/agent.sock`, must be at most 100 bytes; longer paths return `invalid_request` before creating the session directory. The broker prints `synthetic_broker_ready` and its socket path. Copy that path into the separately configured MCP client:

```sh
cargo run --locked --offline -- mcp --socket /absolute/new-session-directory/agent.sock
```

The broker retains synthetic credentials and control; the MCP process does not unlock or start it. The client requests the fixed status operation for repository `4242`, then requests approval. In the broker's terminal, use its returned prepared handle:

```text
inspect 1
approve 1
```

Review the displayed canonical resource, issue, revision, credential version, output contract, generation, expiry, limits, effects, and workflow mode. `approve` atomically compares the cached inspection against the current exact handle, plan, and remaining budget. If another request consumes a use, inspect again. The prepared request expires after 15 seconds; prepare a new ID and review again if it expires. A typed approval is a same-account workflow action, not proof against same-account automation.

The agent can now invoke the same prepared handle. To deny it, use `cancel 1` before dispatch. `revoke` blocks new dispatches for the grant; `stop` or terminal EOF invalidates the session. The broker also stops after 128 bounded control commands, 600 seconds without successful activity, or 1,800 seconds maximum lifetime. No terminal stream should be connected to an agent's control tool.

`--synthetic-control-pipe` is an explicit automation-test flag. The normal command refuses nonterminal stdin with `interaction_required`. The flag does not attest that a human is present.

After the broker stops and removes its session directory, run `rmdir "$demo_parent"` in the first terminal to remove the empty parent. Cargo commands above also work with a custom `CARGO_TARGET_DIR`; when configuring a host to launch the binary directly, use that build directory rather than assuming `target/debug/aegis`.

The [agent quickstart](agent-quickstart.md) supplies MCP message examples and the [protocol](protocol.md) defines exact tool arguments. Windows has no current broker/MCP socket implementation; Linux code is untested.

## Library entry point

Read [`src/lib.rs`](../src/lib.rs), [`src/types.rs`](../src/types.rs), and the broker module before embedding. Construct only the provided synthetic setup. Keep the control capability in a trusted host; provide an agent only its bounded client. Do not serialize, clone into a tool context, or otherwise transfer the control handle to the agent.

The intended sequence is:

```text
trusted host: create synthetic broker, retaining Control
agent client: discover -> prepare -> request approval
trusted host: inspect resolved plan -> approve_reviewed or deny exact request
agent client: invoke -> inspect scoped status/result
trusted host: revoke or stop when authority ends
```

For a pre-approved bounded session, the trusted host delegates exact profile authority before the agent prepares work. Per-request approval is a separate path. Use the implemented API/tests for exact method signatures; the public API is experimental.

Pair `inspect_approval(id)` with `approve_reviewed(id, &view)` when building a review UI. The comparison and approval share the broker lock. `approve(id)` is a lower-level trusted embedding capability and does not enforce that a displayed review is still current. A policy-generation change invalidates the frozen session grant even if profile fields are later restored; start a deliberately authorized new broker session.

## Edit and verify

Run the complete [quality script](../scripts/check.sh) from the repository root for both default and storage-feature tests, strict lints, and strict rustdoc:

```sh
sh scripts/check.sh
```

The subprocess tests need a local execution context that permits Unix sockets. See [verification](verification.md) for the tested Mac context, reproducible commands, and platform limits. The script uses the pinned toolchain and cached lockfile; it does not change OS permission settings.

For a focused default-feature development loop:

```sh
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
cargo run --locked --offline -- demo
```

For documentation of public Rust APIs:

```sh
cargo doc --locked --offline --no-deps
```

For the optional synthetic recovery experiment:

```sh
cargo test --locked --offline --features storage-spike --test storage
```

Read [storage-spike.md](storage-spike.md) before running its two-process example. It accepts only its fixed synthetic snapshot and separate new destinations; it does not provision an operational vault.

Record unavailable tools or failures instead of claiming a full check. The [verification record](verification.md) lists the observed checkpoint outcomes and gaps.

## Where changes belong

| Change | Primary home | Required evidence |
| --- | --- | --- |
| Identifier, limit, result, or error contract | `types` and `docs/contracts.md` | Boundary/serialization checks |
| Authority/lifecycle/reservation/revoke | `broker` | Expiry, stale binding, concurrent use, retry tests |
| Synthetic executor behavior | `fake` | Counted dispatch and hostile/unknown response fixtures |
| Agent message shape/bounds | `protocol` | Malformed/oversize/unknown-field rejection, no-control-wire test |
| MCP mapping or Unix transport | `mcp`, `ipc` | Initialization/tools, current UID, exact cached review, restart epoch, bounded I/O and process capture |
| New adapter or output projection | Reviewed operation specification | Fixed scope, disclosure, timeout, and reconciliation tests |
| Persistent backend | Separate storage/recovery spike | Fresh-process restore and platform fault matrix before real-secret use |

## Debug safely

Use fixture IDs, error codes, state transitions, and dispatch counters. Never add general-purpose `Debug`/serialization for credential material or dump raw provider responses. Protocol stdout must remain parseable messages; stderr is observable and should also contain no credential canary or private input.

If a test produces `outcome_unknown`, preserve the reservation and inspect state. Do not add an automatic retry to make the test pass. If a race is hard to reproduce, use barriers/latches in the fake executor and assert one reservation/dispatch rather than relying on timing sleeps.

This checkpoint does not install services, connect to an operational vault, or create an external repository. See [CONTRIBUTING](../CONTRIBUTING.md) for review and dependency rules.
