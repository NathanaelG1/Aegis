# Standalone local binary verification

**Result:** the default-feature Aegis release executable runs its synthetic workflows outside the source checkout on the tested macOS arm64 host. Rust, Cargo, the repository, its source files, configuration, and asset directories are not runtime requirements for these commands. It is one executable with several command modes; the foreground broker and stdio MCP client run as separate processes of that same executable.

Recorded October 6, 2026, approximately 16:15 UTC. This records local testing of the synthetic implementation, not a distribution or production release. Tested host: macOS 26.6.2, build 25G83, arm64. Existing Rust/Cargo 1.96.1 and cached dependencies were used only to build, with no downloads, installation, provider calls, or real credentials.

## Build and artifact

From the repository root, a normal local build is:

```sh
cargo build --release --locked --offline --bin aegis
```

Cargo writes `target/release/aegis` by default. If `CARGO_TARGET_DIR` is set, use `<CARGO_TARGET_DIR>/release/aegis` instead. Offline builds require the pinned toolchain and locked packages in the local cache.

The local optimized build passed with the pinned toolchain. It produced a 1,042,960-byte Mach-O 64-bit arm64 executable. No binary release is bundled with this source repository. The exact artifact is rebuilt locally from the source and committed lockfile.

## Outside-checkout checks

The test copied only the executable into a new temporary directory, launched children from an empty working directory and passed `env={}`. This excluded `HOME`, `PATH`, Cargo/Rust variables, `DYLD_*`, and inherited configuration. The temporary test directory was removed afterward. Python drove the test; Aegis did not invoke Python or an external program.

| Command | Observed behavior |
| --- | --- |
| No arguments, `--help`, `--version` | Exit zero; compiled usage/version without README or source |
| `demo` | Approval/resume, retained retry, ID conflict/resource denial; one dispatch and 19 remaining uses |
| `synthetic-agent` | Five JSON-lines messages: discovery, prepare, refusal, pending approval/status |
| `synthetic-broker --socket-dir <new-absolute-directory>` | Normal foreground command starts with terminal stdin |
| `mcp --socket <absolute-socket-path>` | Separate stdio process initializes, lists six tools, prepares, pauses and resumes after separate control approval |
| Nonterminal foreground startup | `interaction_required` before destination creation |
| MCP with an absent broker endpoint | Refusal; no broker startup or directory creation |

The foreground/MCP sequence also verified inspect-before-approve, duplicate invocation without repeating work, request-ID conflict, resource denial, cancellation, revocation, and graceful removal of the new session/socket. All captured streams lack the synthetic credential canary. The working directory remained empty. PTY control was automated local test input, not evidence that a human acted or a protected approval channel exists.

## Running the local binary

Set `aegis_bin` to the absolute executable path. These commands need no checkout as their working directory and no Cargo invocation:

```sh
/usr/bin/env -i "$aegis_bin" --help
/usr/bin/env -i "$aegis_bin" demo
/usr/bin/env -i "$aegis_bin" synthetic-agent
```

For the separate foreground/MCP workflow, use a short new canonical absolute session path as described in the [developer quickstart](developer-quickstart.md). In the human terminal:

```sh
/usr/bin/env -i "$aegis_bin" synthetic-broker --socket-dir "$session_dir"
```

In the separate stdio client, launch the same executable with `mcp --socket "$session_dir/agent.sock"`. The already running broker retains synthetic credentials and private control; MCP has no key custody, approval command, or broker auto-start. Direct broker/client invocations replace `cargo run` once the binary exists. Input/output pipes and the separately started foreground process are runtime interfaces, not additional executable files.

## Native and runtime requirements

`file` identified a Mach-O arm64 executable. `otool -L` listed only `/usr/lib/libiconv.2.dylib` and `/usr/lib/libSystem.B.dylib`. Its loader is `/usr/lib/dyld`; no third-party/Rust dynamic library or runtime search path was listed. It uses the host macOS system libraries rather than being a fully static binary. Cargo build-time procedural-macro dylibs are not linked runtime dependencies of this artifact.

The Mach-O load command records minimum macOS 11.0 and SDK 26.5. That declared loader minimum is not older-OS test coverage: execution was verified only on macOS 26.6.2 arm64. Intel, universal binaries, older macOS, Linux, and Windows were not built or run here.

The default commands need OS randomness, ordinary process/stdin/stdout facilities, and macOS system libraries. The foreground/client pair additionally needs allowed local Unix sockets, kernel peer-UID inspection, a writable new private session directory, a complete socket path of at most 100 bytes, and terminal stdin for normal control. Current state is memory-only. No configuration file, plugin, helper binary, installed service, network connection, or source asset is loaded by these command paths. No administrator privileges or OS security changes were used; the test runner used the authorized context permitting Unix socket binding.

The optional age recovery spike is a separate Cargo example, not a command exposed by `aegis`. Building the default `aegis` binary does not include that optional experiment; it cannot create or restore an operational vault. The broker remains synthetic-only, same-account workflow separation is not containment, and persistent setup/protected approval/live providers remain open gates. No distribution-signing/notarization workflow, packaging for distribution or packaged binary release was performed. First-party source is licensed under MIT.
