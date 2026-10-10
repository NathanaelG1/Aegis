# Verification and evidence

## Fixed application-slot checkpoint (2026-10-10)

Local tested runtime and acceptance-test source:
`a36dad47088234492c6659418ca83aa71b7f0d01`. The increment starts from verified
PR #4 head `210a1b32d2986ce8d6673baeafcfe69399d0adb8`, tree
`fa4d89c07531d3333b36cbb8b52f3813d1e4362e` (local equivalent `7e64b81`).
It is stacked on the process-service branch. This record captures local
validation before publication; exact-head hosted CI must be checked separately
on the associated draft PR. Historical green runs do not cover this source.

Environment: Debian 13.6 Linux x86_64 development workspace, official Rust/Cargo
1.96.1. Cargo.lock SHA-256 is
`b3f92fa557f916e1c29e56603012eae4931f3afca0090764b1ccefe06f4ce2bf`.
The optional `application-slot` feature adds pinned Rustix 1.1.5 and selects
linux-raw-sys 0.12.1 on Linux. The [inventory](dependency-inventory-linux-application-slot.json)
records 158 application-slot/all-feature packages; default/storage/signing/vault-only
selected graphs remain unchanged at 19/127/39/156. The lock also resolves errno
for other configurations. No toolchain, CI permission or deployment change occurs.

- All 328 all-feature library tests passed. The eleven new results comprise six
  directory-handle tests, three slot/receipt/import-contract tests, one actual
  process crash test with five exit boundaries, and the profile-version guard
  regression found during aggregate integration.
- Public CLI acceptance passed eight enabled tests. Default and vault-only
  refusal suites passed three each; explicit application-slot and all-feature
  runs passed eight each. Actual imported ciphertext is unchanged between input
  and vault, and the installed file contains the expected public version-one
  canary. Review/import/manifest/capsule/receipt bind adapter/output contracts
  2/2; the separate profile revision remains one. Legacy acceptance is refused
  as installation evidence.
- The normal process composition verifies one installation/use, generation and
  observed version one, three remaining uses, duplicate reuse, fresh
  authentication and durable revoke. Read-only inspection does not change
  retained bytes, inode, mode or modification time, repair data, or restore
  authority. Invalid/missing files, incorrect installed generation and legacy
  receipt substitution fail closed. Marker/output and Linux process-cleanup
  observations remain limited functional evidence.
- A separate two-version fixture uses the existing broker authority to exercise
  replacement. The new file has a new inode; a held prior descriptor still reads
  the prior canary. The exact old receipt can be replayed without rolling the
  installed file back. This is not version-two imported/TLS process composition.
- Actual recipient exits after intent sync, staged-file sync, rename, directory
  sync and signed-completion sync each retain one consumed unknown broker use,
  three remaining uses, exact duplicate reuse and cold-admission refusal. A
  fresh inspector reports observed file version separately from completed
  generation and pending intent. It never creates a completion receipt or
  retries an uncertain installation. The [slot contract](application-slot.md)
  records the five tuples and distinguishes process exits from power cuts or a
  full syscall/storage-error matrix.
- Initial aggregate integration caught a real regression: fixture construction
  preceded the version bound, so the existing invalid-version-zero test panicked.
  The guard now runs before arithmetic; the original case and added zero/three/
  maximum-version checks for both receipt contracts pass. No assertion was
  removed or relaxed. The final full rerun, not that failed initial run, supplies
  the results here.
- Full default/all-feature all-target runs with `--no-fail-fast` produced
  163/449 passes, each with exactly the same 14 locally denied listener cases
  and zero ignored tests. Failure names match the preceding checkpoint;
  permission errors remain present. Both local aggregate commands therefore
  fail, and the hosted Linux run must supply the full listener result.
- Default/all-feature doctests passed 1/28. Formatting, unrestricted
  all-target/all-feature Clippy and all-feature rustdoc with warnings denied
  passed. Focused default and vault-only Clippy also passed before integration.

The actual application file intentionally contains a public canary. Every
process, file and disposable key remains under the development UID/control
plane. Handle-relative operations and signed installation receipts do not prove
protected custody, immutable application code/configuration or independent
human approval. The policy clock remains fixed fixture time; only transport and
supervision use actual elapsed deadlines. Operational entry/custody, human
client/enrollment, deployed admission/time, independent rollback anchor,
lifecycle/provider integration and host assurance remain open. All live-key
and protected-deployment gates remain false. The stopped independent review
was not resumed or replaced by these ordinary implementation tests.

## Broker process service checkpoint (2026-10-10)

Local tested runtime and acceptance-test commit:
`77d4eaad98770bdaa776f6b9308077422e32aa28`, based on the tree of PR #3 head
`85516f171a89d325ecb98419aa2a43cf74c02c96` (local equivalent `4f0b692`).
This increment is stacked on the composed-canary branch. Its published head is
`210a1b32d2986ce8d6673baeafcfe69399d0adb8` in
[draft PR #4](https://github.com/NathanaelG1/Aegis/pull/4), tree
`fa4d89c07531d3333b36cbb8b52f3813d1e4362e`, identical to local final `7e64b81`.
The API-created commits preserve PR #3 ancestry; local/remote commits are mapped
by exact tree hashes.

Environment: Debian 13.6 Linux x86_64 development workspace, official Rust/Cargo
1.96.1. Cargo.lock remains byte-identical with SHA-256
`90e27be2374c74135cd31fe1285db74bdd264d62b64673b217080989ca9de55b`.
There are no dependency, toolchain, feature-graph or CI permission changes.

- All 317 all-feature library tests passed, including nine socket-driver tests
  and eight process-service results (seven scenarios and the child test helper).
  Existing TLS, import, recipient, composed and lifecycle regressions remain on.
- Independent CLI acceptance passed seven all-feature and two default tests.
  Actual imported ciphertext remains identical to the delivered stored version.
  The broker and recipient execute as separate children, with simulated actor
  and TLS client signers outside the broker. Normal and fresh-inspection reports
  retain one completed use, generation one, three remaining uses, no restored
  sessions, duplicate reuse, cold authentication and durable revoke.
- Private test builds exercise actual process response loss. A lost agent TLS
  reply retains completion and rejects cold request-ID reuse. A recipient exit
  after durable acceptance but before acknowledgement retains one consumed
  unknown, with no automatic retry/refund and cold admission refused. A fresh
  inspector can still read that evidence. These are ordinary functional tests;
  not every transport fault is composed with every durable effect boundary.
- Broker termination, client closure and supervisor timeout cases observe both
  owned children reaped before any use. The guarantee excludes killing the
  supervisor itself and interrupting arbitrary native calls. CLI tests inspect
  root-scoped Linux process records after completion/failure. Twelve retained
  artifact missing/corruption cases fail without changing the remaining state;
  restored artifacts permit inspection. Outputs are bounded and checked for
  selected canary/private markers. These checks are not OS protection evidence.
- Full default/all-feature all-target runs with `--no-fail-fast` produced
  160/430 passes, each with the same 14 locally denied listener cases and zero
  ignored tests. The names match the prior checkpoint; permission errors remain
  present. Both local aggregate commands therefore fail. No case was removed,
  skipped or relaxed; the hosted Linux run must supply the full listener result.
- Default/all-feature doctests passed 1/28. Formatting, unrestricted
  all-target/all-feature Clippy with warnings denied, and rustdoc with warnings
  denied passed. The worker also ran the production binary create/inspect path;
  the independent CLI tests cover that same public entry point.

The exact published head subsequently passed
[hosted CI run 38008817405](https://github.com/NathanaelG1/Aegis/actions/runs/38008817405)
on Ubuntu 24.04.5 LTS x86_64, runner image `20261004.327.1`, with Rust/Cargo
1.96.1. All 174 default and 444 all-feature all-target tests passed, including
all 21 Unix interface cases in both configurations, with zero failures or
ignored tests. Default/all-feature doctests passed 1/28; formatting, Clippy and
rustdoc passed. The job log records the exact source SHA and unchanged lockfile.
This evidence covers the process service, not later application-slot changes.

The policy/journal clock remains fixed fixture time, while actual I/O and
supervisor deadlines use Instant. An elapsed-first-phase test covers subsequent
cold revocation; it does not implement trusted UTC, suspend or restart policy.
All processes retain the same development UID/control plane. Bootstrap briefly
holds all disposable keys; human approval is simulated. Construction/scope
report flags cannot admit a deployment. The [service contract](process-service.md)
and [operator plan](operator-live-trial-plan.md) retain protected entry/custody,
independent human identity, immutable isolated application delivery, external
recovery anchor, operational time/lifecycle/audit, provider and assurance gaps.
`require_live_deployment()` still refuses unconditionally. The stopped
independent review has not been resumed or replaced.

## Composed canary checkpoint (2026-10-09)

Local tested runtime and acceptance-test commit:
`cbcfa1ea110bd62ec6ad17a5de5066fa294ea407`, based on PR #2 head
`0ab8a1ac9a385ed7d9fff4b6f5c6efa0727e3303`. This increment is stacked on the
protected-mechanism PR. Its published head is
`85516f171a89d325ecb98419aa2a43cf74c02c96` in
[draft PR #3](https://github.com/NathanaelG1/Aegis/pull/3), with tree
`29820cf8728ce04e1e41f65ed564a11570a6d233`, identical to local final `4f0b692`.

The development workspace is Debian 13.6 Linux x86_64 with official Rust/Cargo
1.96.1. Cargo.lock is byte-identical to the preceding checkpoint, SHA-256
`90e27be2374c74135cd31fe1285db74bdd264d62b64673b217080989ca9de55b`.
No dependency or feature-graph change is introduced.

- All 300 all-feature library tests passed, including seven new import-binding
  and composed-store tests. The original standalone TLS, entry, process,
  two-version store and durable lifecycle regressions remain enabled.
- Independent public-CLI acceptance passed 6 all-feature and 2 default tests.
  The actual imported `input/record.age` equals `vault/secret-1.age`; there is no
  regenerated version-two record. Two authenticated TLS protocol roles drive
  approval and invocation, and the fixed child receives the signed age capsule
  over inherited IPC. The result is one delivery/use, generation one, three
  remaining uses, duplicate reuse, fresh authentication and durable revoke.
- A fresh CLI process inspected the signed retained evidence without changing
  fixture files or restoring sessions. Missing/corrupt input or stored
  ciphertext was refused without altering the remaining files. Existing paths,
  repeated execution, malformed arguments and unavailable-feature execution
  refused. Linux root-scoped process observations found no surviving fixture
  child. Captured outputs and retained files contained none of the tested canary
  or input markers; this is a limited observation, not an isolation proof.
- Full default/all-feature all-target runs with `--no-fail-fast` produced
  158/406 passes, each with the same 14 named listener-dependent failures and
  zero ignored tests. The failure names match the preceding checkpoint;
  direct socket binds report `EPERM`, and broker startup reports unavailable.
  The local aggregate remains blocked. No test was removed or relaxed.
- Default/all-feature doctests passed 1/27. Formatting, all-target/all-feature
  Clippy with warnings denied and all-feature rustdoc with warnings denied
  passed. The composed executable and separate `inspect` invocation also
  passed an independent smoke.

The exact published head subsequently passed
[hosted CI run 38006465796](https://github.com/NathanaelG1/Aegis/actions/runs/38006465796)
on Ubuntu 24.04.5 LTS x86_64, runner image `20261004.327.1`, with Rust/Cargo
1.96.1 and the unchanged lockfile above. All 172 default and 420 all-feature
all-target tests passed, including all 21 Unix interface cases in both
configurations, with zero failures or ignored tests. Default/all-feature
doctests passed 1/27; formatting, Clippy and rustdoc passed. This covers the
composed source only, not the later process-owned broker service.

Failure evidence has distinct scopes. Private import tests reject changed
vault/storage/writer/recipient/receipt-key, reference/version, profile/slot,
generation, metadata and ciphertext bindings. A corrupt stored import detected
by storage-view validation is rejected **before reservation** with zero use and
no handoff. An imported-record test using the existing in-process recipient
fault after durable acceptance retains one consumed use, generation one and an
unknown outcome; cold runtime reconstruction refuses with
`ReconciliationRequired`. That unit test does not inject a lost response across
the full TLS/child-process composition. Existing TLS and process failure suites
remain separate regression evidence; complete cross-boundary crash/fault and
operator-host testing are outstanding.

The fixture's agent/admin TLS peers remain in the parent process. The recipient
is a same-UID child without a TLS endpoint. All actors remain controlled by the
development account, and the report remains UNISOLATED with custody,
human-presence, host-protection and real-key-readiness flags false. The
[composed contract](composed-canary-flow.md) and [operator plan](operator-live-trial-plan.md)
separate further CODE work, precise OPERATOR choices and the unresolved
independent assurance gate. These functional checks do not resume or replace
the previously stopped independent review.

## Protected mechanism checkpoint (2026-10-09)

Local tested runtime/tooling commit:
`5d77e58d1a42834bec411bb57196128d7c973092`, based on merged main `90c6d928`.
Environment: Debian 13.6 Linux x86_64 development workspace, official
Rust/Cargo 1.96.1. Cargo.lock SHA-256:
`90e27be2374c74135cd31fe1285db74bdd264d62b64673b217080989ca9de55b`.

- All 293 all-feature library tests passed: 252 baseline plus 10 TLS, 22 import
  and nine recipient-process tests. The separate real-child integration tests
  also passed. No operator host, live provider or real credential was used.
- Full default/all-feature all-target runs with `--no-fail-fast` produced
  156/393 passes respectively, each with 14 failures and zero ignored tests.
  The failed names exactly match the freshly rerun baseline's Unix-listener
  cases blocked by `EPERM`. Neither aggregate nor the local check script is a
  pass. The later exact-head hosted run below supplies full listener coverage;
  its success does not change the local restriction.
- Default/all-feature doctests passed 1/26 tests. Formatting, all-feature and
  all-target Clippy with warnings denied, and rustdoc with warnings denied passed.
- `tls_spike` completed actual TLS 1.3 mutual authentication, signed agent/admin
  protocol authentication, reviewed canary delivery, durable inspection and
  revocation. Its wrong-peer/role/CA/name/ALPN and replay/tamper controls denied.
- `protected_entry` privately verified a ciphertext-only canary import with
  exact frozen metadata, then reported repeated-use, cancellation and trailing
  input denial. The storage identity is ephemeral; operational recovery is absent.
- The fixed `aegis-recipient-process` executable completed two deliveries with
  recipient-only private custody in the child, duplicate reuse, fresh cold
  authentication, rotation and durable revocation. It reported two consumed
  uses, generation two, zero restored sessions and no automatic retry.
- The existing default `cargo run -- demo` still worked after adding the second
  binary. The default, storage-only and signing-only dependency graphs are
  unchanged when both sources use the corrected Cargo-tree inventory method;
  the all-feature graph adds 12 package identities (144 to 156).

The published source `0ab8a1ac9a385ed7d9fff4b6f5c6efa0727e3303` subsequently
passed [hosted CI run 38002090476](https://github.com/NathanaelG1/Aegis/actions/runs/38002090476)
on Ubuntu 24.04.5 LTS x86_64, runner image `20261004.327.1`, with Rust/Cargo
1.96.1 and the lockfile above. All 170 default and 407 all-feature all-target
tests passed, including all 21 Unix interface cases in each configuration,
with zero failed or ignored tests. Default/all-feature doctests passed 1/26;
formatting, Clippy and rustdoc passed. This is the separate-mechanism checkpoint,
not evidence for the later composed import path.

The three mechanisms are separate fixed-fixture experiments. The import is not
connected to an operational vault, the TLS fixture's recipient remains local,
and the separate recipient uses inherited local IPC rather than TLS. Their
composition does not implement a protected human-to-external-application
service. The child shares the development UID and remains explicitly
UNISOLATED. All custody/human-presence/host-protection/real-key flags remain
false. Native/OS blocking cannot be preempted by fixture deadline checks.
See their [contracts](adr/0018-protected-mechanism-development.md) and the
[operator plan](operator-live-trial-plan.md) for remaining gates. The stopped
independent adversarial review was not resumed or replaced.

## Hosted source and merged-main checkpoint (2026-10-09)

PR #1 was merged by the operator into
`90c6d928b54d9edf0f2f610b5fa3f0bd3ff0be43`. Its exact-head
[push CI run](https://github.com/NathanaelG1/Aegis/actions/runs/37985459603)
passed on Ubuntu 24.04.5 LTS x86_64, runner image `20261004.327.1`, with
Rust/Cargo 1.96.1: 169 default and 364 all-feature all-target tests, including all
21 Unix interface cases in each configuration, zero failed or ignored tests,
1/21 default/all-feature doctests, formatting, Clippy and rustdoc. The feature
branch had separately passed the same checks in
[run 37808429239](https://github.com/NathanaelG1/Aegis/actions/runs/37808429239)
for exact head `5e168aa2c9c77ad0449403de1091cc7d86d983c2`.

This covers the separated-custody runtime below on hosted Linux. It does not
cover changes after the recorded source. A fresh 9 October development-workspace
baseline still produced 350 all-feature passes and the same 14 Unix listener
failures from restricted binding, with no ignored tests. Neither local aggregate
nor the quality script is therefore a local pass. No permission change or
listener bypass was used. Tests exercise dummy fixtures; real-key readiness and
the stopped independent assurance gate remain unresolved.

The sections below retain the earlier exact-source records and their original
platform limits.

**Original Mac checkpoint:** 2026-10-06. The tested scope is a synthetic in-memory broker/fake provider, separate Unix foreground and MCP subprocesses, and an optional fixed-fixture age recovery experiment. Passing these tests establishes only their exercised behavior on the recorded build; it does not establish production readiness, real credential custody, genuine human presence, or OS containment.

Protected agent-blind application delivery is required but not yet implemented or verified. Its [contract](application-delivery.md) and [ADR](adr/0007-protected-application-delivery.md) are documentation-only additions. They add no Rust code or tests; the recorded 85/99 counts cover the existing synthetic implementation, not delivery enforcement. No protected file installation, descriptor/store handoff, application enrollment, independently authenticated human control or OS confinement gate has been exercised.

The later [Linux GitHub preparation checkpoint](#linux-github-preparation-checkpoint-2026-10-06) below records this increment separately; the original Mac success does not cover it.

## Original Mac environment

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

Current source implements terminal inspection before exact approval, current-UID checks on both Unix peers, a new `0700` directory with no overwrite/symlink components, eight-connection and I/O bounds, and random broker-epoch continuity. The original checkpoint did not test Linux peer code. The later Linux run passed the same-UID socket-pair check but could not bind listener sockets, as recorded below. These source properties do not establish genuine human presence, hostile same-account containment, atomic path traversal, or universal filesystem support.

The original Mac complete quality-script run supplied combined evidence for that earlier source checkpoint; its earlier individual/default runs were superseded by that successful check. It does not supersede the later Linux results or cover the new GitHub code. Re-run the script when source or dependency changes require it, and record the named platform and tested feature combinations.

Synthetic fixture canary checks cover the captured paths, not every possible panic, allocator, crash report, telemetry integration, debugger, or compromised host. No real secrets are needed to expose API leak paths. Do not substitute operational credentials for adversarial fixtures.

Focused independent correctness review and remediation are recorded in [review-checkpoint.md](review-checkpoint.md). Comprehensive security review remains outstanding. Record reviewed versions, limitations, and remediation rather than converting a demo transcript into an audit claim.

## Linux GitHub preparation checkpoint (2026-10-06)

Scope: [ADR 0008](adr/0008-github-app-synthetic-preparation.md), the private fixed-fixture GitHub adapter, its example and updated contracts. The existing broker/MCP operation remains unchanged. This is a synthetic code checkpoint, not a supported isolated deployment, real-key installation or live GitHub connection.

Environment: Debian GNU/Linux 13.6 (trixie), Linux 6.18.44, x86_64, overlay filesystem, dot cloud workspace. Rust 1.96.1 (`31fca3adb`, LLVM 22.1.2) and Cargo 1.96.1 were installed from the official Rust distribution into workspace-local tooling with no OS/profile/security changes. Locked crates were fetched from the normal registry before offline verification. `Cargo.toml` and `Cargo.lock` are unchanged; lockfile SHA-256 is `bab93163c4d4b3bd78a8bc78d7328b2523360c1646d76d5cac385c2a8e178f98`. The existing dependency inventory remains the historical Mac target inventory, not a Linux dependency audit.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo test --locked --offline --lib` | All 31 new GitHub tests passed |
| `cargo test --locked --offline --all-targets --no-fail-fast` | 102 passed, 14 existing interface tests failed because Unix listener binding returned `EPERM`; aggregate exit 101 |
| `cargo test --locked --offline --all-features --all-targets --no-fail-fast` | 116 passed, same 14 interface failures; aggregate exit 101 |
| Existing non-interface suites | All 37 policy, 12 protocol/MCP, 6 framing/parser, 9 lifecycle/approval and 14 optional storage tests passed |
| Existing interface suite | 7 passed, including kernel same-UID socket-pair authentication; 14 could not complete in this context because listener bind was denied |
| `cargo clippy --locked --offline --all-features --all-targets -- -D warnings` | Passed |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline --all-features --no-deps` | Passed |
| `cargo test --locked --offline --all-features --doc` | One compile-fail API visibility test passed |
| Existing `demo` and new `--example github_app_spike` | Passed; new report showed two exchanges, two metadata requests, duplicate reuse, confirmed mock revocation, later denial and live availability false |
| Clean source copy, empty target directory | Offline all-feature/all-target build, 31 GitHub unit tests and synthetic GitHub example passed; no existing target artifacts reused |
| Independent focused re-review | Four lifecycle/clock findings fixed; reviewer reran all 31 GitHub tests successfully with no remaining blocking finding in this synthetic scope |

`sh scripts/check.sh` stops at the existing default-feature interface failure, so **the aggregate quality script did not pass in this Linux environment**. A supported elevated execution attempt returned the same `EPERM`; no permission changes or workarounds bypassed that restriction. Remaining checks were run explicitly as listed. This verifies portable synthetic logic and selected Linux tests, not the full Linux foreground transport. The new code has not been run on macOS or Windows.

The adversarial GitHub suite covers owner/type/selection/permission denial before calls, exact signer/installation/binding/epoch scope, explicit metadata-only narrowing, route injection rejection, byte-bounded hostile output, token shape/scope/expiry, duplicate/conflicting IDs, bounded state, single-flight/revoke races, cached use/refresh, unknown mint/read/revocation receipts, overlapping-token bookkeeping, sequential-clock regression, stalled-wall-clock expiry, and panic-safe receipt retention. Unknown receipt replay remains available as a closed error even when the fixture's clock/session later invalidates; this creates no new effect or data release.

The focused review is not a security audit. In-memory mocks do not establish authenticated human authority, protected key custody, valid cryptographic signing, live HTTP enforcement, durable mint/revocation recovery or agent-blind Git/application delivery. Those gates remain open in [the integration plan](github-app.md#milestones).

## Linux synthetic intent-journal checkpoint (2026-10-06)

This subsequent source increment adds [ADR 0009](adr/0009-synthetic-durable-github-intents.md) and the [synthetic journal](github-intent-journal.md). The environment/toolchain/lockfile match the Linux checkpoint above; no dependencies or security settings changed. The earlier 31-test GitHub record is historical for the adapter-only commit.

| Check | Result |
| --- | --- |
| Focused `cargo test --locked --offline --lib` | All 56 GitHub tests passed: original 31 plus 25 journal/parser/runtime/fault tests (including the subprocess worker) |
| Default all-target, no-fail-fast | 127 passed, 14 existing listener-dependent interface tests failed with `EPERM`; exit 101 |
| All-feature/all-target, no-fail-fast | 141 passed, same 14 interface failures; exit 101 |
| Format, all-feature/all-target Clippy with warnings denied | Passed |
| All-feature rustdoc with warnings denied and visibility doctest | Passed; one doctest |
| Existing synthetic demo and GitHub adapter example | Passed |
| Journal create then inspect in separate processes | Passed; one consumed reservation, confirmed mock revocation, zero restored grants/sessions and no retry allowed |
| Clean source copy and empty target directory | All-feature/all-target offline build, 56 unit tests, and separate journal create/inspect processes passed |
| Independent focused review | Reviewer reran all 56 tests; four reported failure-reporting/parsing/replay issues fixed with regressions; no remaining blocker in the stated synthetic scope |

The added tests exercise 36 injected write/sync boundary combinations and nine actual subprocess exit points before/after minting, reading and revocation. They also cover exact persisted bindings, duplicate IDs, strict event transitions, unknown/duplicate fields, malformed/partial input, bounded decoding, cached/overlapping mint references, unknown outcomes with clock regression, single-flight/revoke ordering and cooperative file locks. A parallel process-launch test exposed a temporary inherited-file-description lock lifetime; explicit owner unlock and a dedicated regression cover it.

The aggregate quality script still cannot pass on this host because Unix listener binding remains denied. No tests were disabled or converted to skips. The journal itself uses ordinary local files and file locks, which worked in this context. Actual power loss, hostile same-UID/namespace modification, writer authenticity, rollback protection, operational key custody and macOS/Windows execution remain unverified or unimplemented. The public recovery path only inspects fixed synthetic evidence and restores no authority.

## Linux versioned core-integration checkpoint (2026-10-06)

This increment adds [ADR 0010](adr/0010-versioned-synthetic-github-broker.md), the [versioned core operation](github-broker.md), schema-2 broker context and explicit V2 protocol/MCP wiring. It uses the same Debian/Linux x86_64 workspace, Rust/Cargo 1.96.1 and unchanged manifest/lockfile recorded above.

| Check | Result |
| --- | --- |
| Library tests | 71 passed: prior 56 plus 15 core GitHub policy/integration regressions |
| New GitHub/V2 protocol integration suite | 9 passed |
| Existing policy/protocol/review/framing suites | All 64 passed |
| Default all-target aggregate, no-fail-fast | 151 passed, 14 existing Unix-listener interface failures with `EPERM`; exit 101 |
| All-feature/all-target aggregate, no-fail-fast | 165 passed, same 14 interface failures; includes all 14 optional storage tests |
| Format, all-target/all-feature Clippy with warnings denied | Passed |
| All-feature rustdoc with warnings denied and visibility doctest | Passed; one doctest |
| Clean source copy, empty target directory | All-feature/all-target build, library/V2/legacy focused suites and broker/schema-1 examples passed |
| Independent focused review | Confirmed operation-ID and unknown-receipt corrections; reviewed final code/docs and passing changed/legacy suites. Minor legacy error-precedence cleanup was regression-tested too |

The new regressions cover V1 rejection of GitHub handles before mutation, unavailable unchecked/bounded approval, exact review across IDs/principals/instances/limits, stale bindings, cross-operation/result substitution, consumed budgets after persistence failure, one-shot execution, last-use/revoke ordering, static unknown receipts after invalidation, actual reviewed versus consumed budgets, schema-1 compatibility, schema-2 context tampering/mixed versions, duplicate fields and V2 JSON/MCP framing. V1's unsupported-version test now uses version 3 because version 2 is explicitly supported; no test was disabled.

The new foreground and `mcp-v2` socket commands compile, and their headless refusal is subprocess-tested. They have not completed an end-to-end Unix listener workflow here. The existing 14 listener-dependent tests remain unsuccessful, so neither the aggregate quality script nor full foreground compatibility is claimed. The unchanged default issue-status behavior is evidenced by the runnable legacy suites, not by treating blocked IPC tests as passed.

Schema 2 records declared core idle limits but has insufficient timing history to independently validate every historic idle decision. All stored authority context remains synthetic, unauthenticated metadata under the trusted-storage assumption. Core policy integration does not establish human presence, protected key custody, live transport, rollback protection or OS isolation, and live readiness remains false.

## Linux optional signing checkpoint (2026-10-06)

[ADR 0011](adr/0011-optional-disposable-signing-source.md) adds a separate opt-in disposable-key experiment. This checkpoint uses the same Debian 13.6/Linux x86_64 workspace and Rust/Cargo 1.96.1; existing GCC 14.2.0 builds non-FIPS AWS-LC, with no CMake executable or OS tooling installation. The default and storage-only dependency graphs retain their prior versions/features. See [the signing contract](signing-spike.md) and [Linux dependency inventory](dependency-inventory-linux-signing.json) for pins, maintenance, native-build, size and memory limitations.

| Check | Result |
| --- | --- |
| Focused optional signing tests | 23 passed; disposable in-memory RSA keys only |
| Default all-target aggregate, no-fail-fast | 151 passed, unchanged 14 listener-dependent interface failures; exit 101 |
| Signing-only all-target aggregate, no-fail-fast | 174 passed, same 14 interface failures; exit 101 |
| All-feature/all-target aggregate, no-fail-fast | 188 passed, same 14 interface failures; includes 94 library tests and 14 storage tests |
| Format and all-target/all-feature Clippy with warnings denied | Passed |
| All-feature rustdoc with warnings denied, compile-fail visibility doctests | Passed; two doctests |
| No-input signing example | Passed: one verified signature, lock/stale/revoke denials, existing JWT still valid, protected storage unavailable, live readiness false |
| Clean source copy and empty target directory | All-feature/all-target build, 181 non-listener tests and no-input signing example passed |
| Independent focused review | 23 signing tests, both doctests, inventory and artifact/documentation consistency independently checked; no blocking findings after two lifecycle-cleanup improvements |

The new tests cover exact key/version/issuer/algorithm references, generated RSA signatures, signature corruption and wrong keys, HS/RSA type confusion, bounded canonical compact shapes, duplicate/unknown/wrong-type header and claims, zero-leeway expiry, future `iat`, maximum claim interval, arithmetic failure, 30/600-second lease boundaries, sticky UTC/elapsed regression, final signing-use concurrency, deterministic sign/lock ordering, rotation, revoke versus already issued JWTs, owner drop, generation exhaustion, concurrent demos and preinitialized process-global provider refusal in a fresh process. A visibility doctest ensures private key sources are not exported; it is not an isolation proof.

The aggregate quality script still stops at the unchanged Unix listener failures. Tests were not disabled. macOS/Windows compilation, FFI/unsafe review, full advisory/license review and end-to-end live composition remain unverified. No key file, OS security configuration, real credential, service authentication or network provider is involved. The existing broker still uses synthetic mock signing even when this feature is compiled.

## Linux approval-bound signing checkpoint (2026-10-06)

[ADR 0012](adr/0012-approval-bound-synthetic-signing.md) connects the optional signer to an explicit reviewed synthetic broker constructor. No dependency or lockfile change is made; all four Linux inventories still match. The environment remains Debian/Linux x86_64 with Rust/Cargo 1.96.1 and the existing native compiler. No OS security changes, credentials or live transport are involved.

| Check | Result |
| --- | --- |
| All-feature library tests | 116 passed: prior 94 plus 22 composition/source/timing/crash tests |
| Default all-target aggregate, no-fail-fast | 151 passed, same 14 listener-dependent `EPERM` failures; exit 101 |
| Signing-only all-target aggregate, no-fail-fast | 196 passed, same 14 failures; exit 101 |
| All-feature/all-target aggregate, no-fail-fast | 210 passed, same 14 failures; exit 101 |
| Format, all-target/all-feature Clippy, rustdoc with warnings denied | Passed |
| Compile-fail visibility doctests | Five passed, including separate source/permit/envelope non-export assertions |
| Signed broker example | Passed: approved safe result, unchanged replay, confirmed mock revocation and zero restored authority after journal inspection |
| Clean source copy and empty target directory | All-feature/all-target build, 203 non-listener tests and signed broker example passed |
| Independent focused review | 116 library tests and five doctests independently passed; final contracts and readiness checklist reviewed with no remaining blockers |

The 22 new tests exercise full source/review/permit/envelope binding, key/profile/owner/scope substitution, actual versus reviewed budget, stale/unapproved/expired requests, cached use without fresh source authority, duplicate/revoke races, 18 reservation/mint/receipt/read/terminal write/sync failures, known lease failures, pre/post-sign panics and two actual process exits, provider-initialization failure/header-only residue, exact source clock sampling, sticky regression/reservation floor, delayed signing, and current-time expiry/rollback after mint-intent sync. No real key, JWT byte export or live request is tested or enabled.

A focused review identified an extra pre-sign clock observation that was not latched into source state. Signing now takes one checked sample under the source mutex, verifies the reservation floor before crypto and returns its exact stamp. A separate adapter-owned observation after durable mint intent establishes current exchange time. The tests distinguish that current time from issuance time and retain known pre-provider denial without inventing an unresolved effect. Default/mock lifecycle, panic and journal tests remain in the regression run.

The aggregate quality script still cannot pass because the 14 existing listener tests remain denied. Tests were not skipped. This composed library example does not verify foreground IPC, a real agent/human host, live GitHub behavior, production clock/TTL semantics, protected custody or OS isolation. The [readiness checklist](readiness-checklist.md) consolidates the minimum missing components and required deployment decisions; implementation pauses at that checkpoint.

The first clean-build attempt exhausted the temporary filesystem because earlier disposable build directories occupied it. Only generated build outputs were removed; a fresh source copy and empty build directory on the workspace filesystem then passed. This was an environment-capacity failure, not a hidden test skip or OS permission change. The final optimized, unstripped signed-broker example measured 4,462,560 bytes on this host; this is a local artifact observation, not a portable size promise.

## Vendor-neutral access-contract checkpoint (2026-10-07)

[ADR 0013](adr/0013-vendor-neutral-authentication-and-acl.md) and the [access-control contract](access-control.md) define the future authenticated API/ACL boundary without changing runtime source or dependencies. Four new tests in `tests/access_contract.rs` run against the existing typed V1/V2 protocol, MCP adapter and broker policy. They reject claimed principal/IP/network/proxy/ACL authority before mutation, show accepted MCP display/capability metadata cannot change the host-bound principal or approve, and require exact reviewed principal/credential/resource/context with revocation.

| Check | Result |
| --- | --- |
| New access-contract suite | Four passed |
| Fresh empty target directory | The four-test default-feature suite compiled and passed independently of the existing build cache |
| Independent read-only review | Four tests rerun successfully; architecture/test scope, proxy trust, credential separation and standards references reviewed with no blocking findings |
| Default all-target aggregate, no-fail-fast | 155 passed; unchanged 14 listener-dependent `EPERM` failures; exit 101 |
| All-feature/all-target aggregate, no-fail-fast | 214 passed; same 14 failures; exit 101 |
| Format, all-target/all-feature Clippy and all-feature rustdoc with warnings denied | Passed |
| Existing visibility doctests | Five passed |

These tests do not exercise HTTP headers, a real authenticator, configured ACL loading/evaluation, remote bootstrap/admin, reverse proxies, a private network or public-exposure prevention. Those remain explicit future cases in the acceptance matrix. The current trusted constructor still creates one synthetic grant/principal/session. No runtime behavior, credential, networking configuration, dependency or live gate changed. The full quality script remains unsuccessful on this host because of the known listener restriction; no test was disabled or treated as passed.

## Private Sprite baseline checkpoint (2026-10-07)

A separately operated, budget-approved private synthetic pilot tested immutable source `e353a6bde14418a7591c79da91cba97014a14e07` on Linux x86_64 with Rust/Cargo 1.96.1. Its source archive SHA-256 was `666f00875168d83c12b1231e3b339b05cb5f839d0f698dee47dc9dc235b01602`. The operator's saved quality-script log records **169 default tests and 228 all-feature tests passed**, including all 21 Unix interface tests in both configurations. Formatting, all-feature/all-target Clippy and rustdoc with warnings denied, plus five visibility doctests, passed.

A bounded external smoke also exercised the actual synthetic GitHub foreground command and MCP v2: approval-required denial, forged-approval denial, canonical review, safe result/replay, mock provider revocation and endpoint cleanup passed. This supersedes the earlier host's listener restriction only for that tested pilot/source. The dot development workspace still denies the same 14 listener tests; no sandbox was bypassed or reconfigured.

Negative-boundary tests remain decisive: same-UID software could read a mode-0600 synthetic recovery kit/decrypt its fixture, and could automate ordinary terminal inspection/approval without the test-pipe flag. These are expected limits, not new security promises. Agent administrative/exec/filesystem/restore access to the pilot remains unsuitable for real keys. No HTTP, protected human presence, real application delivery or OS-isolation claim follows from the baseline pass.

## Integrated synthetic vault candidate (2026-10-07)

[ADR 0015](adr/0015-integrated-synthetic-vault-delivery.md) adds the optional main-core canary delivery path. Initial focused validation passes 41 tests covering actual assertion signatures, role/context/expiry/replay denial, opaque client-handle binding, exact/empty ACLs, bare-control approval denial, encrypted delivery/rotation, durable use/revocation, malformed or changed state, in-flight behavior and recipient uncertainty. Eleven actual subprocess exits cover approval, reservation, handoff, completion and revocation; fault matrices exercise failed writes/syncs/anchor updates and recipient acknowledgements. Three added visibility doctests keep the new private principal/host/plaintext types outside the public API.

The code still reports human presence, protected deployment/anchor and real-key readiness as false. A separate fixture kit is not protection against a same-UID/administrator attacker or coherent rollback of all state. Active-writer integrity checks detect tested file changes before another append but are not an atomic namespace-confinement proof. Independent review and immutable pilot verification of this new increment are tracked separately from the earlier Sprite baseline.

Initial local candidate checks: 155 default and 255 all-feature tests passed, each with the unchanged 14 listener failures in the dot workspace. All-feature library total is 157 (116 earlier + 41 vault tests). Formatting, all-target/all-feature Clippy, rustdoc with warnings denied, eight visibility doctests, a fresh empty-target run of all 41 vault tests, and separate example create/inspect processes passed. Dependency metadata matches all four previous package/version/feature inventories; `vault-spike` only combines existing optional features. This is the pre-review local checkpoint, not independent approval or pilot verification of the new code.

Immutable candidate `99c7074f28b268caff2b93e933cf01ca8a78445c` subsequently passed the private Linux pilot's 169 default and 269 all-feature tests, all 41 focused vault tests, eight doctests, formatting, Clippy, rustdoc, the GitHub foreground/MCP regression and separate-process vault create/inspect. Those passes did not clear the candidate: independent local reproductions found inconsistent recipient inspection, acknowledgement after damage to an open recipient file, and restoration of a use after a reservation failed before its first journal write. The reviewer completed the focused suite and reproductions but stopped before a final independent review conclusion; that review is incomplete.

Corrective regression coverage now requires exact journal/recipient agreement, active recipient file/history revalidation, and a durable pre-transition guard for reservation and revocation. Guards preserve fail-closed cold-start behavior even when a subsequent journal write fails before any bytes are written. The same repair covers failed revocation persistence. Focused checks and later immutable-source validation are recorded against the corrected commit separately; the earlier pilot pass is not evidence for untested changes.

The correction's local checks passed 48 focused vault tests (seven added cases), all 164 all-feature library tests, eight doctests, formatting, all-feature/all-target Clippy and rustdoc with warnings denied. New cases also retain an unknown receipt's exact authenticated-capability requirement and preserve the result/revocation ordering when an already-reserved delivery is paused. Independent final review remains incomplete; these are developer regression results.

## Corrected vault and separated protocol checkpoint (2026-10-07)

Corrected immutable commit `c9f982f50c0cceed479af9bc3efd88c19fac2081` passed the private Linux pilot's seven corrective regression cases, all 48 vault tests, 169 default tests, 276 all-feature tests, eight doctests, formatting, Clippy and rustdoc. Separate-process vault inspection, GitHub foreground/MCP regression and actual pilot cold-wake inspection passed. Source files matched the immutable archive. These are ordinary platform/regression results; the stopped independent security review remains incomplete.

The following [ADR 0016](adr/0016-separated-vault-protocol-roles.md) increment separates runtime key ownership and adds typed agent/admin connection handlers. Its new in-process protocol tests exercise serialized delivery/rotation/revoke, fresh cold authentication, role/review/epoch substitution denial, closed parser/output bounds, expired admin session inside the approval hook, signer ownership, empty ACL, duplicate in-flight invocation and retained uncertainty. Current-source final command evidence is recorded after the new candidate is frozen; earlier immutable passes do not validate later code automatically.

Local protocol-increment checks passed all 13 new protocol tests and all 177 all-feature library tests (61 vault tests in total). Default all-target results were 155 passed plus the same 14 listener failures; all-feature results were 275 passed plus those same 14 failures, with zero ignored tests. Formatting, all-feature/all-target Clippy, rustdoc with warnings denied and eight visibility doctests passed. The exact failed listener names match the earlier cloud checkpoint. Clean-build and immutable pilot validation are recorded separately when completed.

## Recovered adapter foundation checkpoint (2026-10-07)

Tested runtime `ce287cda3fdfff4a18a62ddb27fe5d40cb0ae308` integrates three separately developed fixed-fixture modules. [Source recovery](source-recovery-2026-10-07.md) records how runtime `4979ae3` was recovered; the original unpublished history and documentation-only `0a0efe1` were not recovered.

Environment: Linux x86_64, Rust/Cargo 1.96.1. Cargo.toml and Cargo.lock are unchanged from the recovered runtime. Archive SHA-256: `146d4ee9ca649c73d09e40deef8e474045b1193a3651eb29181dedec6c2513cf`.

- All 225 all-feature library tests passed, including 48 new tests (entry 21, recipient 15, transport 12).
- Full default/all-feature all-target runs with `--no-fail-fast` produced 155/323 passes respectively, each with 14 failures and zero ignored tests. The failed test names exactly match the 14 listener tests in a fresh baseline run. Socket binding remains restricted on this workspace, so neither full aggregate nor `scripts/check.sh` is a local pass.
- All 16 visibility/API doctests passed. Formatting, all-feature/all-target Clippy and rustdoc with warnings denied passed.
- The `adapter_foundations` example executed all three reports. It observed one metadata-only entry reservation, two dummy recipient generations and one authenticated framed canary delivery/revocation. Production entry remains `unsupported_deployment`; independent peer authentication, confidentiality, human presence, protected recipient and real-key readiness remain false.
- Validation logs/reports contain neither of the two fixed canary values nor private-key block markers. A known-credential-marker/filename check of reachable Git blobs found no matches. These are limited output/publication checks, not a secrecy proof or independent security review.

The approved private Linux pilot verified this exact immutable runtime on 7 October 2026. `scripts/check.sh` passed: all 169 default and 337 all-feature tests passed, including all 21 Unix interface cases in both configurations; all 16 doctests, formatting, Clippy and rustdoc with warnings denied passed. The adapter example and a separate-process inspection passed, preserving one consumed use, recipient generation one, revocation and zero restored sessions. All 112 source files still matched the archive; five output files passed the limited fixed-canary/private-key-marker check. The bounded batch exited zero at 22:39:37 UTC. No cold-wake test was added for this increment. Afterward, the pilot had no services or active exec sessions.

The stopped independent review remains incomplete and has not been resumed or replaced. The new recipient fixture has no durable state and is not wired into the existing durable runtime; operator entry receipts and channel bindings are simulated. Production adapters, operator-owned isolation, external anchor/custody and final assurance remain open.

## Separated custody and report-only deployment checkpoint (2026-10-08)

Tested runtime `1e606c462f14d13e85e5df34e241a6e602bd39c7`, Linux x86_64, Rust/Cargo 1.96.1. The exact runtime archive SHA-256 is `c743d290dd04afed5e8247b5b43e9ee285d4b5d4bd73536c157402fc7446701a`. Cargo.toml and Cargo.lock are unchanged from the prior milestone.

- All 252 all-feature library tests passed, including 10 new custody tests and 17 new deployment-model tests. The aggregate default/all-feature all-target runs with `--no-fail-fast` produced 155/350 passes and the same 14 socket-listener failures each, with no ignored tests. Failure names exactly match the prior local checkpoint; neither full local aggregate nor `scripts/check.sh` is a pass.
- All 21 doctests, formatting, all-feature/all-target Clippy and rustdoc with warnings denied passed.
- The `custody_spike` example completed separate-role loading, signed exact approval, two fixed-canary deliveries including cold rotation, duplicate reuse and durable revocation. A separate `inspect` process verified two consumed uses, recipient generation two, revocation and zero restored sessions. No combined role kit was created.
- `deployment_preflight` reported `no_go` with `no_host_observations` and unsupported real observations. Simulated evidence does not issue a production capability or change `require_live_deployment()`.
- Thirteen saved log/report files contained neither fixed canary value nor private-key block marker. This limited output check is not a secrecy proof or independent review.

This runtime has not been tested on the external pilot, macOS or Windows; the 7 October pilot pass applies only to its earlier immutable source. No Sprite wake, real GitHub exchange, credential provisioning, deployment/access change or independent-review restart occurred for this increment. The custody files and recipient still share the trusted test process/UID and rollback domain; protected human identity, operating-system isolation, encrypted production transport, external anchor and operational provider/recipient adapters remain open gates.
