# Verification and evidence

**Checkpoint:** 2026-10-06. The tested scope is a synthetic in-memory broker/fake provider, separate Unix foreground and MCP subprocesses, and an optional fixed-fixture age recovery experiment. Passing these tests establishes only their exercised behavior on the recorded build; it does not establish production readiness, real credential custody, genuine human presence, or OS containment.

Protected agent-blind application delivery is required but not yet implemented or verified. Its [contract](application-delivery.md) and [ADR](adr/0007-protected-application-delivery.md) are documentation-only additions. They add no Rust code or tests; the recorded 85/99 counts cover the existing synthetic implementation, not delivery enforcement. No protected file installation, descriptor/store handoff, application enrollment, independently authenticated human control or OS confinement gate has been exercised.

## Environment

| Item | Initial evidence / limit |
| --- | --- |
| Host | macOS 26.6.2, arm64, local development task |
| Toolchain | Rust 1.96.1 / Cargo 1.96.1 pinned by `rust-toolchain.toml`; package MSRV 1.96, edition 2021 |
| Package | `aegis-broker` / library `aegis` / binary `aegis`; experimental, `publish = false` |
| Dependencies | Exact pins: serde 1.0.228, serde_json 1.0.145, getrandom 0.2.17, Unix nix 0.29.0; optional age 0.11.1 `storage-spike`; review `Cargo.lock` for resolved transitives |
| Storage | Broker state is in memory; optional fixed-fixture age recovery spike is separate and does not initialize an operational vault |
| Provider | Synthetic fake executor only; no live connection |
| Windows / Linux | Not tested; no supported-mode claim |
| Filesystems | New-directory/file permissions and no-overwrite/path fixtures tested on this Mac; operational durability, rekey, hostile races, and other platforms unverified |
| Host integration | Rust embedding, terminal-control foreground broker, Unix agent socket, thin stdio MCP2025-11-25; protected approval and containment unverified |

The declared Rust minimum is not a cross-platform support matrix. Each future release must name OS version, architecture, desktop/headless context, feature combination, and filesystem. A successful build is insufficient evidence of secure deployment.

## Checkpoint commands

The [quality script](../scripts/check.sh) completed with exit code zero on the named Mac host. Counts below exclude zero-test unit/doc/example targets. Machine-specific raw logs and private development history are not distributed; use these commands to reproduce the synthetic checks.

| Check | Command | Status |
| --- | --- | --- |
| Format | `cargo fmt --all -- --check` | Passed |
| Lints | `cargo clippy --locked --offline --all-targets --all-features -- -D warnings` | Passed |
| Default tests | `cargo test --locked --offline --all-targets` | Passed: 85 = 37 policy + 12 protocol/MCP + 21 interfaces + 9 review lifecycle/approval + 6 framing/parser regressions |
| All-feature tests | `cargo test --locked --offline --all-features --all-targets` | Passed: 99 = default 85 + 14 synthetic age/recovery tests |
| Synthetic age tests | `cargo test --locked --offline --features storage-spike --test storage` | 14 passed; detailed evidence in [storage-spike.md](storage-spike.md) |
| Scripted synthetic flow | `cargo run --locked --offline -- demo` | Passed: approval/resume, one dispatch, unchanged retry, ID conflict and resource denial |
| Public API documentation | `RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline --all-features --no-deps` | Passed |
| Quickstart wire examples | `aegis synthetic-agent` with documented JSON lines | Passed: exact five documented JSON-lines and six MCP messages from a clean disposable build; see [quickstart evidence](quickstart-verification.md) |
| Documentation links | Local Markdown target existence check | Passed: zero missing local targets |

The pinned 1.96.1 dependency cache is available for the observed default checks. Full graph advisory/license review, platform expansion, and independent security composition review remain outstanding. Separate reviewers completed focused correctness and maintainability reviews of the first checkpoint and its fixes; see [review remediation](review-checkpoint.md). The earlier Rust 1.80.1 core-only check is historical; it does not establish compatibility of the current dependency graph.

The [dependency inventory](dependency-inventory.json) records 19 third-party packages for the default `aarch64-apple-darwin` configuration and 128 with `storage-spike`, excluding the first-party crate. It records resolved versions, enabled features, declared licenses, and Rust versions; it is an inventory, not an advisory/license audit or a cross-target review. Its generator is [dependency_inventory.py](../scripts/dependency_inventory.py).

## Platform regression and execution context

The subprocess/interface suite exposed a macOS socket issue: accepted streams inherited the listener's nonblocking mode, causing premature reads/closed connections. The implementation now explicitly switches accepted streams to blocking before setting timeouts, sending the epoch greeting, and serving protocol frames. The initial 15 interface tests and the complete quality script passed afterward; the reviewed interface suite now contains 21 passing tests. Apple's archived [accept(2) manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/accept.2.html) describes accepted sockets as having the listener's properties; the actual Mac regression test is the evidence for this implementation.

Socket-binding tests ran in a local execution context that permits Unix sockets. The task's restricted execution sandbox had returned `EPERM`; no OS permission configuration was changed to run these synthetic tests. No live provider connection or operational vault was used. Do not interpret a sandbox's inability to run this test as a portable broker guarantee.

## Required foundation scenarios

| Scenario | Observable assertion |
| --- | --- |
| Approved status operation | Exactly one fake dispatch; only reviewed projection returned |
| Different profile/resource | Deterministic denial before credential resolution/provider dispatch |
| Unapproved request | `approval_required`; requesting approval cannot self-approve |
| Approval and resume | Trusted control inspects exact resolved fields and approves; same agent request then completes |
| Unknown fields / forged approval / principal labels | Reject or ignore only as explicitly safe data; never establish authority |
| Profile revision changes | Old approval cannot dispatch against new revision |
| Credential binding or output contract changes | Old grant does not silently follow |
| Two distinct requests, one final use | At most one reservation and one provider dispatch |
| Same prepared request concurrently invoked | One run and one consumed use |
| Identical caller request ID/inputs | Existing prepared/run state and terminal result |
| Same ID with changed parameters | `request_id_conflict`; no dispatch |
| Revoke races dispatch | Revoke before serialized decision blocks dispatch; already dispatched work may finish |
| Cancel/expiry before dispatch | Zero dispatch; no activity-based lifetime extension |
| Polling and denial | Idle lifetime does not refresh |
| Maximum lifetime / backward clock | Session invalidates deterministically |
| Capacity / oversize / malformed input | Bounded rejection without state or output amplification |
| Hostile provider response | Wrong identifiers, state, schema, or contract not released |
| Known provider failure | Stable non-sensitive error; no transparent repeat |
| Unknown acceptance / executor panic | Consumed reservation retained; no blind repeat |
| Credential canary | Absent from agent protocol, result/error/debug fixture captures |
| Broker restart | Fresh session; no implicit restoration of old authority |

Each test should count dispatches and inspect the external result where appropriate. Timing alone is weak concurrency evidence; use controlled fake-executor barriers to force the race. A test that a forbidden API method is absent is only an API-surface check, not proof against same-user access.

## Deferred verification gates

| Gate | Evidence needed before claim |
| --- | --- |
| Genuine human approval | Protected host/OS channel; agent cannot synthesize approval or reach control |
| Protected application delivery | All [synthetic delivery acceptance gates](application-delivery.md#synthetic-adversarial-acceptance-gates), including file/env/memory/handle denial, immutable recipient/configuration/endpoint approval, forged consent, replay/restart, final-use/revoke races, path races, hostile plugins/proxies/outputs and refusal of missing confinement |
| Protected installation and revocation | Enrolled directory/object/store identity, atomic install and crash/acknowledgement reconciliation; retained unknown outcomes without retry; separate future-delivery, cleanup, process and provider revocation evidence |
| Restricted/isolated agent mode | Bypass attempts against binary/config, files, process memory, administrative API, and raw credentials |
| Real agent harness | Actual host transcript with success, deterministic denial, private approval, resume, and concurrent sessions |
| Broader MCP-host integration | Beyond the tested narrow adapter/subprocesses: actual agent hosts, version/lifecycle compatibility, protected approval/resume, and host capture behavior |
| Provider transport | Fixed endpoint, TLS/destination behavior, redirects, proxy/header rejection, byte/time/pagination bounds |
| Provider writes | Acceptance/receipt fault injection, provider idempotency or reconciliation, no unknown-outcome duplication |
| Age interoperability | Released pinned implementation, standard age CLI interoperability, truncation/corruption/resource-limit tests |
| Operational recovery | Extend the tested fixed-fixture fresh-process recovery to an operational snapshot, independently protected custody, supported platforms, and the real-secret readiness gate |
| Setup cancellation | No existing vault overwrite and no false success |
| Storage transactions | Ordinary write and multi-file rekey crash matrix; valid old/new pairs; serialized generation checking |
| Filesystem defense | Restrictive creation, path validation, symlink/reparse, lock/durability tests per OS/filesystem |
| Credential rotation | Old session version invalidated; broader account/authority requires approval |
| Native lifecycle | Suspend, screen lock, logout, headless unsupported interaction, and clock semantics per platform |
| Dependency/release review | Per-target graph/licenses/advisories, unsafe boundaries, SBOM/provenance, artifact trust, independent composition review |

## Interpretation limits

The embedding process may contain both trusted control and agent handles. The foreground command separates terminal control from the agent Unix socket, and the MCP process contains only the bridge. Both still trust the same OS account. Session counters are intentionally volatile; the separate age fixture cannot restore broker authority. Request expiry is a dispatch authorization limit; a provider execution timeout needs separate enforcement and tests.

Linux separate service identities/systemd credentials, macOS protected identities or confined-agent/hardened-recipient authenticated IPC, and Windows service identities/DACLs/AppContainer are delivery proposals only. None is a tested Aegis configuration. Mode `0600`, current-UID peer checks, a signed executable, container naming or redaction cannot substitute for demonstrated denial of agent reads and control. Recipient plaintext cannot be retracted by revoking a broker grant, and delivery-use counters cannot count later provider calls without separate enforcement.

Current source implements terminal inspection before exact approval, current-UID checks on both Unix peers, a new `0700` directory with no overwrite/symlink components, eight-connection and I/O bounds, and random broker-epoch continuity. Linux peer code is untested. These source properties do not establish genuine human presence, hostile same-account containment, atomic path traversal, or universal filesystem support.

The complete quality-script run supplies combined evidence; earlier individual/default runs were superseded by that successful check. Re-run the script when source or dependency changes require it, and record the named platform and tested feature combinations.

Synthetic fixture canary checks cover the captured paths, not every possible panic, allocator, crash report, telemetry integration, debugger, or compromised host. No real secrets are needed to expose API leak paths. Do not substitute operational credentials for adversarial fixtures.

Focused independent correctness review and remediation are recorded in [review-checkpoint.md](review-checkpoint.md). Comprehensive security review remains outstanding. Record reviewed versions, limitations, and remediation rather than converting a demo transcript into an audit claim.
