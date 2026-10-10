# Operator-controlled Linux trial plan

**Updated 10 October 2026 — implementation plan; live use remains NO-GO.** This maps the
remaining source and deployment work to a bounded first trial. It authorizes no
host purchase, access change, deployment, credential creation/entry or provider
operation. The previously stopped independent review remains incomplete; this
plan neither resumes nor replaces it. There is no completion-date or security
assurance implied by this plan.

## 1. Starting evidence and its limits

Historical source baseline: `f5a3e1d`, whose documented immutable runtime is
`ce287cda3fdfff4a18a62ddb27fe5d40cb0ae308`. The
[verification record](verification.md#recovered-adapter-foundation-checkpoint-2026-10-07)
reports:

- Linux pilot: 169 default and 337 all-feature tests, 21 Unix interface cases in
  each configuration, 16 doctests, formatting, Clippy and rustdoc passed. The
  adapter example and separate-process inspection passed. All 112 archived
  source files matched. No cold-wake test was added for that checkpoint.
- Local workspace: 225 all-feature library tests and 16 doctests passed; full
  default/all-feature all-target runs had 155/323 passes and the same 14
  listener-binding failures (`EPERM`). The full local quality script is not a
  pass.
- At that baseline, entry receipts were simulated; transport was in-memory
  framing without peer authentication or confidentiality; the separate recipient
  adapter was not connected to the durable runtime. Role-limited Rust objects do not establish
  process isolation. The all-role fixture kit is development material.

The later [TLS](tls-transport.md), [bounded import](protected-entry.md) and
[recipient-process](recipient-process.md) increments added real mechanisms in
separate fixed-fixture drills. The [composed-canary milestone](composed-canary-flow.md)
then joined the actual imported ciphertext, TLS protocol and child recipient.
Its exact head `85516f171a89d325ecb98419aa2a43cf74c02c96` passed
[hosted CI](https://github.com/NathanaelG1/Aegis/actions/runs/38006465796):
172 default and 420 all-feature tests, 1/27 doctests and quality checks. This
is separate evidence from the original baseline and does not complete the
operational C1–C8 requirements below.

The later [process-service milestone](process-service.md) is PR #4, open draft
stacked on PR #3, head `210a1b32d2986ce8d6673baeafcfe69399d0adb8`, tree
`fa4d89c07531d3333b36cbb8b52f3813d1e4362e` (local `7e64b81`). Its
[exact-head hosted run](https://github.com/NathanaelG1/Aegis/actions/runs/38008817405)
passed 174 default and 444 all-feature tests, including 317 all-feature library
tests; 1/28 doctests; all 21 Unix interface tests in each feature configuration;
and formatting, Clippy and rustdoc checks, with zero failed or ignored tests.
The host was Ubuntu 24.04.5 LTS x86_64 with Rust 1.96.1. The new
[application-slot milestone](application-slot.md) starts from that checkpoint;
its focused functional checks have separate exact-source results. Final
integrated aggregate and hosted evidence belong in the verification record.

These are historical, exact-source functional results, not results for future
commits or evidence of a secret boundary. Re-run the final candidate. In
[`src/vault/mod.rs`](../src/vault/mod.rs), `require_live_deployment()` always
returns `UnsupportedDeployment`. Keep that refusal until an operational path
and its evidence exist; do not replace it with a caller-supplied readiness flag.

## 2. Recommended first target and trust boundary

The established first use case is a GitHub App owned by NathanaelG1 and installed
only on selected personal repositories. Organization installations/access are
out of scope. Keep the App private key in protected broker/sign-only custody;
the first enrolled GitHub recipient should receive only a narrowed installation
token for one exact personal repository and a fixed metadata-read operation. No
App private key, JWT or installation token is an agent-visible result. The
existing [GitHub contract](github-app.md) supplies the frozen App/installation,
numeric account/owner, selected repository, signer version and permission
bindings; those facts still need authenticated operational enrollment.

Use one explicitly approved, operator-owned **Linux x86_64 host or VM**, with a
named OS/kernel/filesystem and supported local IPC. Keep the agent on another
machine with only an authenticated, ACL-bounded application endpoint. Use one
small enrolled recipient, initially with one fixed protected-file credential
slot. The [canary application-slot contract](application-slot.md) develops the
file mechanism; it does not establish a protected operational destination.
No interchangeable destination paths, plugin systems or arbitrary shell should
be exposed. A same-host agent is a later deployment profile requiring its own
confinement evidence.

| Role | Permitted custody/control | Must not gain |
| --- | --- | --- |
| Trusted operator | Host/control plane, pinned installation, enrollment and recovery administration | An automatic route by which agent tools exercise these powers |
| Agent connector | One enrolled application identity and exact proposal/status/invoke scope | Human signer, broker/recipient private keys, host shell, file/debug access or administrative endpoint |
| Broker service UID | Its role-specific custody, policy, protected ledger and narrowly scoped anchor operations | Human/agent proof signers or recipient private keys |
| Recipient service UID, distinct from broker | Its enrolled decrypt/receipt material and fixed application slot | Broker custody, human approval authority or agent-writable effective code/configuration |
| Human approval client | Separate authenticated signer and trusted review display outside agent automation | Approval from a name, agent-controlled terminal, forwarded claim or signature automatically produced by fixture code |
| Recovery/anchor authority | Independently retained recovery material and authoritative current generation | Agent-accessible recovery or an anchor rolled back with the broker snapshot |

The operator and recipient join the trusted computing base. Compromised kernel,
host/cloud administrator, trusted signer or deliberately exporting recipient
are exclusions, not attacks this design claims to defeat. Record that boundary
in the approval view.

**Different UIDs are necessary in this proposed profile, not sufficient.**
Inventory supplementary groups, capabilities, debugging, descriptors, service
control and control-plane access. Unrestricted same-UID execution against a
secret-bearing process is unsupported. Linux's
[Yama documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html) describes
same-UID tracing under classic permissions and configuration-dependent tracing
restrictions; no single tracing setting establishes confinement. Test actual
process access, including the memory, environment, command-line and descriptor
interfaces described in the kernel's
[`/proc` documentation](https://docs.kernel.org/filesystems/proc.html), under the
selected kernel and effective identities.

Protect the full installation closure: binary, interpreter/libraries,
dependencies, plugins, service definition, startup environment, configuration,
policy, enrollment and parent directories. Agent-written source, CI artifacts,
mutable image tags or configuration must never auto-promote into this trusted
installation. Artifact changes require operator-controlled review/install and
invalidate old admission/approval evidence. A digest labels bytes; it does not
prevent replacement or prove the running configuration.

## 3. Missing CODE work, with acceptance outputs

These are source dependencies, not host checkboxes. Implement only the selected
Linux profile first, preserve the single main-broker authority path, and keep
all development input disposable until the later gates are satisfied.

| Work package | Existing seam | Required operational completion |
| --- | --- | --- |
| C1: Deployment admission | `vault::entry`; fixed metadata receipts | Trusted measurement/provenance for exact artifact, configuration, role enrollment and boundary evidence; freshness and invalidation on change; revalidation at use. Signed caller-authored claims alone cannot certify the host. Unsupported/missing evidence must deny before any secret read. |
| C2: Role-specific custody and operator entry | `vault::store::{Kit, BrokerMaterial, RecipientMaterial}`; private crypto types; [two independently reviewed canary imports](composed-canary-rotation.md) | Two fixed imports exercise exact version/profile bindings and one-shot import consumption; they do not implement protected user input or custody. Operational completion requires independently provisioned role stores/loaders, protected unlock/lock/version/rotation, bounded user entry and transactional import/recovery. Select the actual custody/unlock and independent human mechanisms through [operator decisions](operator-decisions.md). No all-role production kit, plaintext argv/environment/log input, general export API or agent-supplied private value; recovery must not grant agent custody. |
| C3: Human and connector identity | `vault::auth`; separate `AgentEndpoint`/`AdminEndpoint` | Operational enrollment/revocation and protected proof injection; genuine human interaction on an independent client bound to the exact displayed plan. Strict role/purpose/audience/epoch binding; no synthetic actor, header or local username may substitute for identity. |
| C4: Authenticated encrypted transport and time | `vault::tls::socket`, `vault::process_service`, framing and role-specific protocol handlers | The closed process service now has bounded actual inherited socket I/O and separate broker/client ownership. Operational accept/admission policy, independently owned admin routing, trust/enrollment renewal and exact deployment ACLs remain open. The journal/proof clock is still fixed fixture time; trusted UTC, reboot/suspend behavior and complete lifecycle evidence remain required. Two inherited channels do not implement a deployed connection service. |
| C5: Real recipient handoff | `vault::process_recipient`, durable `Store::Recipient`, runtime `Adapter::execute`, [fixed application slot](application-slot.md) and [composed rotation](composed-canary-rotation.md) | The one-import slot has focused functional evidence; the bounded two-import contract extends actual broker/TLS/child replacement to generations one and two with retained receipts and second-install crash semantics. Exact-source results belong in [verification](verification.md); a contract or expected result is not a passed test. Neither composition establishes operational rotation. Completion still requires the selected immutable application/dependency/configuration closure, recipient-only protected destination, measured namespace/identity protection, lifecycle/cleanup and deployment-specific fault evidence. |
| C6: Protected state and independent anchor | `vault::store` journal/guard/anchor | Operational backend with protected namespace, crash-safe transitions and independently authenticated compare/advance/fencing outside the broker/recipient restore domain. Detect coherent old-state restore or deletion; unavailable anchor denies. Specify recovery and ambiguous-handoff reconciliation without retry, refund or restored sessions/approval. |
| C7: Lifecycle, audit and incident controls | Core reserve/revoke and synthetic inspection | Fresh epochs and authentication on restart; durable budgets, revocation and uncertainty; concurrent-wake fencing; actual suspend/clock/kill behavior. Bounded operator audit records for exact versions/identities/decisions/outcomes; no secret, token fingerprint, raw proof or diagnostic payload in agent-facing status/logs. Distinguish future-delivery revoke, recipient cleanup and provider revoke. |
| C8: Narrow provider use and release packaging | Synthetic GitHub/signing paths; no live adapter | If the trial exercises a provider, implement only its selected read-only operation with fixed endpoint/resource/scope, validated encrypted transport, no redirect/proxy substitution, safe output and provider-side expiry/revoke evidence. Package a pinned build/dependency inventory and protected update path; test the actual connector and recipient, not just library calls. |

Splitting fixture material or adding a synthetic admission model can reduce
coupling and exercise failure cases. It does not complete C1/C2/C6. Likewise,
the existing synthetic GitHub metadata result does not implement application
credential delivery. [Entry](operator-entry-contract.md),
[recipient](recipient-adapter-contract.md),
[transport](vault-transport-contract.md) and
[delivery](application-delivery.md) contracts remain the detailed constraints.

## 4. Operator choices and later action approvals

First answer the six [operator design questions](operator-decisions.md). Keep
the established selected-personal-repository GitHub App use case. Naming a
host, custody candidate or client selects the implementation target; it does
not authorize actions on it. The protected-entry and isolated-recipient
adapters remain code work after the two-import mechanism composition.

The operator owns the later actions below. Writing code or approving synthetic
development does not authorize them. Bundle approval requests once exact
targets and consequences are known, using the
[existing ceremony](operator-owned-deployment.md).

1. **Approve exact provisioning when needed.** After the design choices are
   resolved, specify the host/account, OS/filesystem, fixed recipient build,
   custody backend, independent human client and anchor/recovery domain. Verify
   that the proposed controls can enforce separation, then seek approval for
   any actual provisioning, price/commitment or access changes. Resolve exact
   GitHub App/installation/repository IDs during separately approved enrollment.
   No provider, purchase or credential creation is selected by this document.
2. **Approve a canary-only installation.** Approve the precise host identities,
   service/configuration changes, transport/network exposure, enrollment and
   pinned artifact digest. Operator provisioning keeps each private role value
   outside the agent's tools. Production-style service credential facilities
   still require a reviewed adapter and measured isolation; they are not a
   substitute for C2/C5.
3. **Remove and verify all privileged routes.** List and remove agent access via
   SSH/CLI, browser/dashboard sessions, other connectors/accounts, sudo,
   privileged groups/capabilities, exec/debug, container/control sockets, volume
   mounts, service updates, CI/deploy credentials and proxy/network controls.
   Also cover log export, crash dumps, backups, checkpoint download/restore and
   account recovery. Removing one plugin is insufficient. Preserve a separate
   operator recovery route that the agent cannot invoke.
4. **Validate recovery and run canaries.** Operator-owned backups must have
   protected recovery keys and restore permissions. The authoritative anchor
   cannot be included in the same rollback set, even under another filename or
   volume. Test current recovery and stale restore without copying private
   material to development. Record log/telemetry, dump, swap, snapshot and backup
   retention and access policies; do not promise erasure from deletion.
5. **Seek a separate assurance/go decision.** The stopped independent review remains
   an unresolved assurance gate. This plan does not authorize continuing or
   replacing it; a permissible assurance path must be established separately.
   Functional acceptance below may proceed within authorized synthetic work,
   but cannot waive that gate. Only after approved assurance and a go
   decision should the operator approve the exact live credential, destination,
   permissions, expiry and revocation procedure and enter it directly through
   the verified protected interface. Private key entry is user-performed.

After live material exists, do not restore agent administrator access for
troubleshooting. The operator must first revoke real authority, remove sensitive
material through the approved recovery/cleanup procedure, and establish a
keyless environment before delegating privileged development again.

## 5. Synthetic acceptance matrix for the final candidate

Run using disposable canaries on the exact proposed deployment and the agent's
actual remaining tools. Save artifact/configuration digests, OS/tool versions,
role/access inventory, commands, expected versus observed results and sanitized
logs. Each row is **required and not yet established for that deployment**.

| Test | Required observation |
| --- | --- |
| Exact-source regression | Full default/all-feature all-target suites, all doctests and quality checks pass on the selected host; all listener cases run. A historical pass or skipped/blocked test is not a pass. |
| Actual privilege boundary | Agent attempts shell/control-plane/container/service, filesystem, environment, process memory/debug and descriptor access. Every secret/control route is denied; correct recipient still succeeds. Include the historical same-UID attack as an explicit unsupported negative configuration. |
| Immutable installation/destination | Agent cannot replace code, libraries, service/config/policy, slot/parents or mount/proxy/loader paths. Trusted test changes to any bound field invalidate admission and existing approval; reverting it does not revive authority. Exercise alias/link/path replacement at the actual file adapter. |
| Human and peer authentication | Wrong principal/role/audience, stolen fixture labels, forwarded headers, stale enrollment, replay and cross-channel proof fail. Agent cannot automate human consent. Lock/logout/cancel/expiry and exact-plan change tests fail closed. |
| Encrypted and bounded I/O | Untrusted endpoint/peer, interception, backend bypass and transport downgrade fail. Partial frames, trickle, oversize, disconnect, timeout, saturated connections and lost responses produce bounded failure or retained uncertainty, never plaintext or automatic re-dispatch. |
| Authority/concurrency | Race final use, cancel, revoke, duplicate and distinct request IDs across processes/wakes. At most the approved reservation succeeds; denial consumes no unauthorized effect, and reserved uncertainty never refunds a use. |
| Installation/rotation faults | Kill before/after reservation sync, handoff, installation and acknowledgement; inject storage failure and wrong receipt/recipient/generation. One exact installation or retained uncertainty; stale version cannot overwrite a newer generation. |
| Recovery/rollback | Fresh cold start, stop/wake, simultaneous writers, missing/corrupt state, anchor outage and coherent checkpoint rollback deny unsafe continuation. Valid recovery preserves consumed uses/revocation; no session/approval automatically resumes. |
| Time and shutdown | UTC/elapsed regression, expiry while suspended, unavailable trusted time and interrupted shutdown deny new authority. An already reserved effect has its documented retained result; sleep does not extend approval. |
| Leakage and revocation | Inspect operator-authorized agent outputs, logs, diagnostics, dumps/backups and recovery paths using canaries. Exercise local revoke, recipient cleanup and simulated provider revoke independently; report unknown/failure truthfully. Marker checks supplement access tests, never replace them. |

Run the repository regression commands plus doctests explicitly:

```sh
sh scripts/check.sh
cargo test --locked --offline --all-features --doc
```

The OS/transport/recipient tests above also need a separate cross-process canary
harness; these Cargo commands do not supply it. Tests and ordinary implementation
review are not independent security assurance. Changed bindings or behavior
require fresh evidence, not a carried-forward pass.

## 6. Minimal first live use, only after all gates

First-use scope: the approved personal-account GitHub App, one explicitly
selected personal repository, one enrolled fixed GitHub recipient and one
protected slot for a short-lived installation token. The request must name that
exact repository ID and only `metadata: read`; no organization, all-repository,
Contents, workflow, administration or user-token access belongs in this trial.
The operator provisions the App key directly into verified sign-only custody;
the recipient does not receive that root App key. One independently approved delivery attempt; no bulk
import, unattended renewal, generic execution or mutable plugin configuration.
The recipient performs one fixed harmless read and returns a closed status.
The App/client/installation IDs, numeric personal-account identity, selected
repository ID, protected signer version, provider-enforced token expiry and
revocation/cleanup steps must be verified before approval. The user plans to
create the App; no App key has been entered and no live grant has been verified.
There is no provider call, App/key/token creation or enrollment authorized now.

A broker delivery count limits handoffs, not later calls made with delivered
plaintext. If downstream one-use behavior is claimed, enforce and test it in the
recipient/provider; otherwise disclose the credential's residual authority and
revoke it after the trial. A read-only GitHub metadata broker trial from the
[readiness checklist](readiness-checklist.md) can be a separate narrow preflight,
but cannot substitute for this protected recipient delivery test.

End the trial after verified installation, the approved read, explicit local
revocation, recipient cleanup and provider-side revocation/expiry confirmation.
Retain safe audit evidence. Any unknown installation or revocation outcome stops
new work and goes to operator reconciliation. Real-secret rotation is a later
separately approved operation after its full canary matrix passes; do not expand
scope merely because initial delivery succeeds.

## 7. Hard NO-GO gates and completion criterion

No real value may enter while any of these is true:

- Any C1–C8 component needed by the selected trial is absent, synthetic-only or
  unverified; live entry still has no operational protected implementation.
- Agent retains equivalent access to broker/recipient/signer/custody through any
  UID, file, process, deployment, log, backup, recovery or control-plane route.
- Human consent or peer identity is simulated; effective code/configuration or
  destination can change after review; encrypted authenticated transport is
  absent or its trust can be redirected by the agent.
- State, current generation, time, receipt or recovery is missing, stale,
  inconsistent or uncertain; provider revocation cannot be verified.
- Required acceptance evidence is blocked/failing, the independent assurance
  gate remains incomplete, or the operator has not approved the exact live scope.

“Code ready for an operator trial” requires implemented operational adapters,
reproducible exact-build tests and a runnable canary procedure with explicit
unsupported configurations. “Go for this live trial” additionally requires the
measured operator-owned deployment, independent assurance and exact approval.
Neither removing admin access alone nor healthy unit tests establishes either
condition. The current decision is **continue authorized synthetic engineering;
do not request or enter live secrets**.

## 8. Subsequent fixed-fixture implementation

The [separated custody increment](custody-spike.md) adds independent role-document
loaders to the real synthetic vault/protocol composition without loading an
all-role key kit at runtime. The [deployment prerequisite model](deployment-admission.md)
adds bounded report-only evidence handling; actual host observations and
production admission remain unsupported. These increments advance C1/C2
interfaces but do not complete their operational requirements or enable any
live secret. Their exact-source test evidence belongs in the verification record.

## 9. Process service, application slot and the next operator decision

The [composed flow](composed-canary-flow.md) now uses the actual bounded import
as the broker's delivery source, preserves durable reservation before
decryption/handoff, and carries the exact capsule and verified receipt through
the fixed recipient route. Its evidence ledger distinguishes actual composed
execution from focused failure cases. The child remains UNISOLATED and
source-generated readiness or prerequisite claims cannot admit live use.

The [process service](process-service.md) now moves TLS I/O and the broker
runtime across actual process-owned sockets, with actor signing outside the
broker and fixed supervisor ownership of both children.
[ADR 0020](adr/0020-process-owned-dummy-broker-service.md) defines its acceptance
scope and section 1 identifies the exact-head hosted result. It uses inherited
socketpairs and disposable fixtures; a network listener and operational human
client remain separate work.

The bounded milestone in [ADR 0021](adr/0021-fixed-application-slot.md) now installs
the actual imported canary into one fixed application file. Its
[acceptance contract](application-slot.md) requires handle-relative staging and
replacement, durable intent before effects, file/directory synchronization and
signed installation receipts. Reopen must detect partial or inconsistent state
without repairing it, repeating effects, refunding consumed authority or
restoring approval. Focused new-slot checks pass on the sources recorded in that
contract; final integrated aggregate and hosted results are separate. The
historical process-service CI pass does not cover the new code. File installation
leaves the recipient UNISOLATED and all operational protection/real-key gates closed.

The next operator choices are the exact Linux host/account/OS/filesystem,
independent human client, protected broker/recipient custody, immutable recipient
installation/destination, independent anchor and recovery authority, and the
agent's actual remaining tools. These choices do not replace missing code or
authorize installation, access/network changes or real-key entry. After the
code gaps and exact choices are resolved, use sections 4–7 for specific approvals,
canary deployment evidence and the later go decision. The stopped independent
adversarial review and permissible assurance path remain unresolved separately;
the composed run and CI neither resume nor replace that review.
