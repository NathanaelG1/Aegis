# Clean-copy quickstart verification

The documented synthetic workflows were exercised from a clean source copy on macOS 26.6.2 arm64 with existing Rust/Cargo 1.96.1 and cached locked dependencies. Build output used a fresh external Cargo target directory. Source hashes were unchanged afterward.

The developer startup block used a short canonical temporary parent and a new private session directory. A separately launched MCP client exchanged the six documented messages; a separate synthetic control channel inspected and approved the request. Invocation returned only repository ID `4242`, issue `7` and status `open`. Broker/client shutdown and empty-parent cleanup passed; captured output lacked the synthetic credential canary.

The five documented JSON-lines messages also passed: discovery, prepare, preapproval refusal, pending approval and status. An overlong socket path rejected before creation; EOF without LF rejected without executing a frame.

These checks exposed and resolved assumptions about a default Cargo target directory and a deeply nested Unix socket path. Cargo launch commands work with a custom `CARGO_TARGET_DIR`; a complete socket path must be at most 100 bytes. Run the [developer quickstart](developer-quickstart.md), [agent quickstart](agent-quickstart.md) and [quality script](../scripts/check.sh) to reproduce the synthetic behavior.

Approval automation is test evidence, not proof of human presence or containment. Actual agent hosts, fresh-machine installation, protected control and other operating systems remain unverified. Raw machine-specific logs and private development records are not distributed.
