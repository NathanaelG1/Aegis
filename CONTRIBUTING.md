# Contributing to Aegis

Aegis is available under the [MIT license](LICENSE). Contributions should focus on the synthetic prototype, clear contracts, reproducible tests, and documented limitations.

## Before changing behavior

Read [contracts](docs/contracts.md), the [threat model](docs/threat-model.md), and the relevant [ADR](docs/adr/README.md). State whether a change alters authority, credential custody, result disclosure, persistence, or platform claims. A new operation or adapter is a change to the trusted computing base.

Keep edits inside this dedicated project. Tests and demos must use synthetic fixtures and temporary destinations. Do not read or modify operational vaults, import existing credentials, call live providers, migrate data, change OS permissions, or make release/publication changes as part of routine prototype work.

## Development loop

The full checkpoint check is [scripts/check.sh](scripts/check.sh):

```sh
sh scripts/check.sh
```

It verifies default and optional-storage targets with the pinned local toolchain, then treats Clippy and rustdoc warnings as errors. Its subprocess tests require local Unix socket binding. See [verification](docs/verification.md) for the actual execution context and saved results.

For a focused default-feature loop:

```sh
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
cargo run --locked --offline -- demo
```

Run checks supported by the installed toolchain and record failures or unavailable tools. If an intentional change modifies behavior, update the contract, tests, and error documentation together. Test observable guarantees and adversarial boundaries rather than copying private implementation details into assertions.

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), with focused messages such as `feat: add a reviewed operation`, `fix: preserve an unknown outcome`, or `docs: clarify a runtime requirement`. Explain the concrete problem and resulting behavior. Report the tested OS, architecture, compiler, dependency lockfile, and feature combination. Do not label a change secure, audited, portable, or production-ready based on a successful build.

## Review checklist

- Can an agent-supplied field broaden a resource, operation, credential binding, output, or limit?
- Are authorization, remaining-use reservation, and revoke decisions serialized together?
- Can a retry repeat an effect after dispatch, failure, panic, or uncertainty?
- Does a profile/credential/result revision change force rejection or reapproval?
- Do errors, `Debug`, traces, provider responses, and protocol streams exclude credential material?
- Is every new allocation, pending request, result, and execution lifetime bounded?
- Does a stronger guarantee have a corresponding test on the claimed platform and host?

Keep raw provider content out of ordinary error messages. Avoid custom cryptography and runtime plugins. Introduce dependencies for a specific reviewed purpose, pin the resolved graph, and record feature and target effects. Dependency review, advisory results, SBOM, provenance, signed packaging, and first-install verification are release work; the current lockfile is not an audit.

## Adding an operation

Specify the fixed provider/resource, accepted input shape, exact credential version, effect classification, result projection, bounds, timeout, and retry/reconciliation behavior before adding dispatch code. Supply fake-provider tests for denial before dispatch, hostile outputs, duplicate IDs, version changes, and unknown outcomes. Live provider tests require separate authorization and least-privilege disposable credentials.

## Reporting concerns

Use the draft [security policy](SECURITY.md). Share a minimal synthetic reproduction and expected versus observed behavior. Do not include a real credential, vault snapshot, recovery key, or operational system data in a report.
