# Composed fixed-canary delivery milestone

**9 October 2026 — implemented fixed-canary composition. Live use remains
NO-GO.** This milestone joins the bounded canary import,
mutually authenticated TLS protocol and separate recipient process in one
executable flow. It delivers the bytes from the committed import through the
existing durable broker. The exact-source evidence below distinguishes the
observed composed path, focused failure tests and remaining deployment gaps.

The input remains a compiled-in disposable canary. No real value, GitHub App key,
installation token, endpoint, recipient executable, credential reader or
deployment-readiness claim may be supplied. No host installation, access or
network change, provider call, credential creation or live entry is authorized
by this milestone. The [operator trial plan](operator-live-trial-plan.md) remains
the live-use gate.

## One composed path

The interface is the Unix `vault-spike` function
`vault::composed::run_synthetic_composed_drill(&Path)` and the fixed
`aegis-composed-canary <new-absolute-root>` binary. The root is disposable fixture
storage, with `custody`, `input`, `vault` and `recipient` children; it is not an
arbitrary application installation destination. Every stage must use the same
enrolled fixture instance and imported record.

1. **Provision separate dummy roles.** A fixed bootstrap child creates the
   broker, recipient and simulated actor material without an all-role kit.
   The broker loads its own storage/signing material and public recipient
   enrollment. After bootstrap, only the recipient child loads the recipient's
   private decryption and receipt keys. The bootstrap child temporarily holds
   every dummy provisioning key. The simulated approval/TLS setup still controls
   fixture identities and does not establish independent human custody.
2. **Consume the bounded import.** The private reader consumes the existing
   exact frozen review and one-shot import permit before input or filesystem
   effects. It checks the fixed version-one canary, encrypts it to the actual
   broker storage identity, and publishes one no-clobber committed ciphertext.
   The [entry contract](protected-entry.md) still supplies the reader limits,
   cancellation, uncertainty and trusted-namespace limitations.
3. **Bind the actual import to the store.** The broker retains that exact
   committed ciphertext and authenticates its reviewed metadata. There must be
   no fallback to `Store::create` generating an equivalent canary record, no
   ignored import result, and no parallel delivery policy engine. Missing,
   changed or wrong-instance input cannot become a fresh fixture success.
4. **Authenticate and approve through TLS.** Distinct enrolled agent and admin
   TLS roles carry the existing signed challenge/proof protocol, reference-only
   proposal and exact review approval. TLS peer authentication supplements the
   existing actor authentication and ACL; it cannot confer admin authority on
   the agent. The human approval remains simulated in trusted fixture code.
5. **Reserve before decryption or handoff.** The main broker commits its
   ordinary delivery reservation before decrypting the imported record and
   constructing the signed, recipient-encrypted capsule. Import consumption and
   delivery consumption are separate obligations; import approval must never
   substitute for delivery approval. The broker commits handoff intent before
   transport can reach the recipient.
6. **Carry the real capsule to the fixed child.** The composed recipient route
   must exchange that capsule and its signed response over the inherited Unix
   socketpair to the fixed child. Preserve the exact request, vault, recipient,
   slot/revisions, version, generation and capsule-digest checks from
   [recipient delivery](recipient-process.md). Running a separate child drill
   with a regenerated store is not evidence of this composition.
7. **Retain the outcome and close.** Require a verified durable receipt for
   success, retain consumed uncertainty after ambiguous handoff, and exercise
   duplicate handling, cold reopen, fresh authentication and durable revoke.
   A reopened process must not restore a session or executable approval.
   Emit only the bounded closed report and reap the owned recipient child.

Both peers of each agent/admin TLS channel live in the parent fixture process.
TLS terminates there. The recipient child has its own private decryption/receipt
material and receives the signed age capsule over inherited local IPC; it does
not own a TLS identity or terminate a recipient TLS connection. The signed
capsule and receipt authenticate that hop's contents. Neither hop establishes
independent endpoint custody: the development account controls both processes.
This composed milestone imports and delivers version one only; the earlier
standalone process drill's version-two rotation is separate evidence.

## Meaning and limits of a successful run

A passing composed CLI test establishes exercised dataflow, protocol
authorization and retained functional outcomes for one disposable input. A
protected human-to-application service remains unavailable. The development
recipient remains **UNISOLATED**: a separate process running under the same UID
and host control plane does not exclude memory, `/proc`, tracing, file,
descriptor, executable/configuration or recovery access by that account.

The fixture recipient validates a canary and retains ciphertext and signed
acceptance evidence. It is not a provider adapter or an operational application credential
slot. The imported canary is public source data. Marker-free reports and stored
ciphertext do not prove endpoint secrecy, secure erasure, race-safe filesystem
publication or power-loss durability.

The existing error rules remain part of acceptance:

- Failed or canceled import cannot refund its one-shot permit. Publication
  uncertainty retains ciphertext for reconciliation; no automatic import retry
  or rollback is implied.
- Delivery reservation precedes decryption and effect. Lost child/TLS response,
  malformed or mismatched receipt, or post-effect persistence failure retains
  the consumed use and unknown outcome. No second handoff or refund follows.
- Duplicate requests reuse their retained result; changed parameters cannot
  turn the same ID into another operation. Cold open restores facts, not grants.
- Broker revoke stops future delivery. Recipient cleanup and provider
  revocation/expiry are distinct, separately observable actions; neither is
  established by a broker revoke or deleting fixture files.

`require_live_deployment()` must remain unconditionally `UnsupportedDeployment`.
Human-presence, custody, host-isolation and real-key-readiness claims remain
false. No flag, source-generated receipt, successful handshake, digest string,
test count or caller-authored checklist can upgrade those claims to measured
deployment evidence.

## Remaining CODE work

These are implementation gaps even after a successful composed canary. The
operator cannot complete them by supplying names or toggling host settings.
The C1–C8 work packages in the [trial plan](operator-live-trial-plan.md#3-missing-code-work-with-acceptance-outputs)
remain the detailed acceptance contract.

| Gap | Required completion before the selected live trial |
| --- | --- |
| Deployment admission (C1) | Trusted observation/provenance for the effective installed artifact, dependency/configuration closure, identities, actual access boundary and current state; reject absent, stale or changed evidence at use. Fixture receipts and report-only preflight cannot admit a deployment. |
| Protected input and custody (C2) | A protected human input adapter; independent role provisioning/unlock/lock/rotation; race-safe encrypted import and durable restart reconciliation. The fixed in-memory reader and development role files do not supply these. |
| Independent approval and enrollment (C3) | Independent human client with trusted display and explicit action over the exact review; operational actor/peer enrollment, revocation and proof custody outside agent automation. |
| Actual connection and time (C4) | A supported transport service with connection admission, real socket cancellation/deadlines, protected trust/renewal/revocation, separate admin routing and verified exposure; trusted UTC/elapsed and suspend behavior. In-memory TLS records alone do not implement that service. |
| Bound application recipient (C5) | One operational recipient whose effective executable, dependencies, configuration and fixed slot are immutable to the agent; handle-based destination validation, protected staging/replacement, durability and generation checks. A fixed dispatcher name is not installed-code measurement. |
| Protected recovery and anchor (C6) | Durable state under the selected OS/filesystem; an independently authenticated generation/fencing authority outside the complete rollback domain; missing/stale-state denial and a specified ambiguous-handoff recovery procedure. |
| Lifecycle and audit (C7) | Actual crash, suspend, concurrent wake, shutdown and clock fault handling; bounded operator evidence without secret/proof leakage through logs, diagnostics, backups or recovery; explicit cleanup and revoke outcomes. |
| GitHub recipient and packaging (C8) | Protected sign-only root App-key use, actual narrow installation-token minting, fixed personal-repository metadata read, safe output, enforced token scope/expiry and provider revocation evidence; pinned release/dependency inventory and operator-owned update path. No live provider adapter exists in this canary milestone. |

## Remaining OPERATOR choices and actions

The next operator decision is the exact supported boundary, not real-key entry.
Record the following concrete choices before requesting installation or access
changes. Unknown entries remain blockers; no provider or host is selected here.

| Choice to settle | Required record and subsequent authorized action |
| --- | --- |
| Linux host and account | Exact operator-owned provider/account and host/VM identity, Linux x86_64 OS/kernel, filesystem/mount behavior and any cost. Confirm the provider can enforce the chosen controls before purchase or provisioning. |
| Independent human client | Exact device/client, approval signer custody, trusted display/input and enrollment/revocation route, outside the agent's terminal/browser automation and administration. |
| Broker and recipient custody | Named protected backend and separate service identities; precise readers/writers, unlock/rotation path and the fixed recipient artifact, dependencies, configuration, endpoint and destination binding. |
| Anchor and recovery | Exact independent authority/location, recovery key owner and permitted restore route; identify the full broker/recipient snapshot and backup rollback domain and prove the anchor is outside it. |
| Agent's remaining access | Enumerate the actual agent tools, accounts, tokens and sessions; approve removal of every effective file/process/debug/service/deploy/control-plane route and retain a separate operator recovery route. |
| Installed candidate | Exact source/build/lockfile and installed artifact/configuration identities, service/network changes, role enrollment and rollback/update process. Canary-only installation needs specific approval once these are known. |

Different UIDs are necessary for the proposed local service profile and
insufficient by themselves. The boundary inventory must cover supplementary
groups, capabilities, same-UID execution, `/proc` memory/environment/command line,
ptrace/debug/dumps, inherited and passed file descriptors, custody and staging
files, destination parents and mounts, code/dependency/configuration/plugin
replacement, service control, build/CI/deployment authority, logs/telemetry, swap,
backups/checkpoints, export/restore and account recovery. Include SSH, dashboards,
browser sessions, other connectors, container/control sockets, volume mounts and
network/proxy controls. Removing one access tool does not establish the boundary.

After those choices and the code gaps are resolved, the operator approves the
exact canary-only installation/access changes, installs the pinned candidate,
removes all privileged agent routes, and runs the
[deployment acceptance matrix](operator-live-trial-plan.md#5-synthetic-acceptance-matrix-for-the-final-candidate)
through the agent's actual remaining tools. Record observed denials and correct
recipient success, current recovery, stale restore, fault behavior and sanitized
evidence. Do not put live material on that host while the agent retains an
equivalent administrative, deployment or recovery route.

The first intended provider use remains a GitHub App installed on selected
**personal repositories only**, initially one exact personal repository and
`metadata: read`. Record the App/client/installation IDs, numeric personal
account/owner, selected repository ID, signer version and token scope/expiry.
The root App private key stays in protected broker/sign-only custody. The fixed
recipient receives only the narrowed short-lived installation token; the agent
receives neither. Organization access, all-repository grants and user tokens are
outside the first-use scope. The canary does not establish any live grant.

The previously stopped independent adversarial review remains incomplete. This
milestone does not resume it, request its restart or substitute another review.
A permissible assurance path remains a separate unresolved decision. Compilation,
functional tests and CI cannot discharge it. Only after implemented adapters,
observed deployment evidence, permissible assurance and the exact operator go
decision may the user perform live-key entry through the verified protected
interface.

## Exact-source evidence ledger

Starting source: `0ab8a1ac9a385ed7d9fff4b6f5c6efa0727e3303`, the separate-mechanism
checkpoint. The integrated runtime/tests are
`cbcfa1ea110bd62ec6ad17a5de5066fa294ea407`; subsequent documentation does not
change that tested code. The [verification record](verification.md) gives
commands, counts, platform limits and prior CI provenance. The new draft PR
records the exact published head and its hosted CI result.

| Evidence | Current state |
| --- | --- |
| Integrated runtime and API | Implemented; `run_synthetic_composed_drill(&Path)` and `inspect_synthetic_composed(&Path)` accept only fixture paths |
| Actual ciphertext and authority bindings | Passed focused library tests for exact committed bytes and vault/storage/writer/recipient/receipt-key, reference/version, profile/slot, generation and metadata binding; legacy store shape retained |
| Actual TLS-driven child delivery | Passed independent CLI test: two control roles, one delivery/use, generation one, three remaining uses, duplicate reuse and durable revoke |
| Safe report, no-clobber, arguments/default refusal and cleanup | 6 all-feature and 2 default CLI tests passed; bounded outputs, tested marker absence and Linux root-scoped child observations only |
| Cold state and missing/corrupt artifacts | Fresh-process inspect passed without file changes or restored sessions; missing/corrupt input/store ciphertext refused without mutation |
| Failure and uncertainty | Import failures retain their one-shot consumption; invalid stored bytes detected before reservation cause no use/handoff. Imported-record acknowledgement loss uses an in-process recipient fault and retains consumed uncertainty with cold `ReconciliationRequired`; full TLS/child fault injection remains untested |
| Aggregate tests and quality | 300 library tests, 1/27 doctests and quality checks passed. Full local default/all-feature runs: 158/406 passes plus the unchanged 14 restricted listener failures each, zero ignored |
| Hosted Linux CI | Reported for the exact published SHA on the accompanying draft PR; this ledger records pre-publication local checks and does not substitute earlier passes |
| Operator-owned deployment and independent assurance | Not established; live use remains NO-GO |

Acceptance commands are:

```sh
cargo test --locked --offline --test composed_canary
cargo test --locked --offline --all-features --test composed_canary
sh scripts/check.sh
cargo test --locked --offline --doc
cargo test --locked --offline --all-features --doc
```

The CLI and fresh-process inspection were also exercised directly. Reproduce
with a new absolute destination:

```sh
cargo run --locked --offline --all-features --bin aegis-composed-canary -- /tmp/aegis-composed-new
cargo run --locked --offline --all-features --bin aegis-composed-canary -- inspect /tmp/aegis-composed-new
```

Inspection starts a fresh recipient child to validate its journal and signed
nonce-bound status. It appends no records and restores no authority; this does
not claim read-only OS permissions or absence of private in-memory work. These
checks supply functional evidence only and make no host-assurance claim.
