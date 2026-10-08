# Report-only deployment admission foundation

**Synthetic implementation only. Every public result is `no_go`. No real secret
may be entered on the strength of this model, a fixture report, or removal of the
agent's administrator privileges.** This does not select, configure, observe or
approve a host.

`src/vault/deployment.rs` adds a small, bounded evidence gate behind the existing
Unix `vault-spike` feature. It changes neither broker authority nor credential
custody, persistence, result disclosure, transport or supported-platform claims.
The [operator-owned ceremony](operator-owned-deployment.md),
[readiness checkpoint](readiness-checklist.md), [contracts](contracts.md) and
[threat model](threat-model.md) still govern a later real-key decision.

## Public API and deliberate refusal

The integration hook is `pub mod deployment;` in `src/vault/mod.rs`.

- `deployment_prerequisites()` accepts no arguments and returns the fixed,
  machine-readable prerequisite inventory. Its evidence origin is
  `no_host_observations`; every prerequisite is `unsupported_observation`. This is
  an accurate statement of missing collectors, not a probe of the running host.
- `run_synthetic_deployment_preflight_drill()` accepts no arguments and exercises
  private fixed metadata fixtures. Its complete evidence report is explicitly
  `simulated_attestations`. It also reports exercised missing, unknown, same-UID,
  contradictory, stale, changed-binding and clock-regression outcomes, and the
  existing production entry refusal.
- `DeploymentDecision` has only `NoGo`. A report is diagnostic output; no code
  accepts it as authorization, a capability, enrollment or a live factory input.
  Reports are serializable but have no deserialization/import path here. Public
  report fields do not grant authority if a caller constructs or changes them.

There is no generic host/evidence/configuration constructor, configurable trust
flag, secret/credential parameter, key-entry endpoint, file or process collector,
network listener, provider call or operational admission token. Private fixture
receipts and the gate are not externally constructible; compile-fail examples
cover those boundaries. `vault::require_live_deployment()` continues to return
`UnsupportedDeployment`, including after every simulated prerequisite matches.

## Evidence domains

The closed `DeploymentPrerequisite` vocabulary describes the minimum evidence
that a future supported operator-owned deployment would need. Each domain gets
exactly one independent slot in the model; one observation cannot fill another.
The ten domains are grouped to keep the model bounded, not to claim comprehensive
host detection.

| Machine-readable prerequisite | Required real-world meaning, not implemented here |
| --- | --- |
| `distinct_service_identities` | Separate effective agent, broker and recipient identities; independently controlled operator, reviewer, recovery and anchor identities. Labels and absent sudo membership do not prove separation. |
| `agent_file_process_debug_denial` | Actual denials through the agent's remaining tools for secret-bearing files, staging, environment, memory, `/proc`, debugging/tracing, inherited handles and equivalent process interfaces. Same-UID access is not made safe by a non-admin label or `0600`. |
| `immutable_application_configuration_deployment` | Operator-reviewed artifact/dependencies/configuration/destination/endpoint, including recipient plugins/helpers, outside the agent's writable namespace; no agent-controlled update branch, CI runner or deployment substitution. |
| `protected_logs_backups_recovery` | Plaintext cannot reach agent-readable logs, dumps, diagnostics, exports, checkpoints, backups or recovery keys. Independent recovery custody and a tested fresh-process restore preserve disabled imported authority. |
| `operator_owned_control_plane` | No effective agent admin, shell/exec, service/container/supervisor, mount, secret-management, snapshot/restore, proxy/network or equivalent dashboard/SSH/connector access to protected services. Removing one route is insufficient. |
| `independently_authenticated_human` | Human approval/key-entry identity and protected channel outside agent control; canonical challenge, explicit human action, expiry, cancellation, replay and lock/logout semantics. Terminal automation and simulated signer labels do not qualify. |
| `authenticated_application_peers` | Cryptographically verified enrolled agent/recipient principals with issuer, audience, role and exact revision binding before default-deny ACL evaluation; no client identity strings, IP membership or untrusted proxy claims. |
| `confidential_authenticated_transport` | Supported authenticated confidential transport for the actual connection, protected backend/proxy trust, fixed destinations, exposure verification and denial of downgrade or bypass. |
| `external_anchor_and_concurrent_wake_fencing` | Protected generation anchor outside the state/checkpoint rollback domain, deletion/rollback detection, exclusive current wake ownership and fail-closed fencing across crash/restart/restore. |
| `durable_audit_and_revocation` | Protected reservation/approval/revoke evidence, no resurrected grants/budgets, concurrent revoke/dispatch ordering, consumed uncertainty and explicit local-versus-provider revocation/reconciliation behavior. |

Each domain would need independent review of its actual probes and evidence
source. A future real collector must document the named OS/host, tools, effective
permissions, attempted bypasses, protected identities and supported exclusions.
This model supplies none of those observations. In particular, a host with a
non-admin agent is still unsuitable if that agent shares a credential-bearing
service UID, can debug it, alter its next build, read its backups or reach its
control plane. Distinct numeric identities alone are also insufficient.

The report always lists missing code/review integrations separately: trusted host
observation and attestation verification; production identity/clock/transport;
protected custody/operator entry; independent anchor/fencing; isolated recipient
and durable recovery; independent security review; and a disabled live factory.
Completing any external checklist cannot bypass these implementation gaps.

## Private synthetic evidence contract

The private reusable gate is deliberately only a model. `FixtureReceipt` carries
a closed finding (`BoundaryHeld`, `BoundaryViolated`, `Unknown`, `Unsupported`),
the expected fixture reviewer's exact identity, the prerequisite, an observation
time and a full immutable copy of these bindings:

- Artifact, dependencies and configuration digests
- Host identity, boot epoch, host-policy revision and remaining agent-tools digest
- Agent, broker, recipient, operator, reviewer, recovery and anchor principal
  digests, enrollment revisions, verification-key digests, security domains and
  OS user identities
- ACL revision, recipient/recovery/anchor generations and endpoint digest
- A fresh model-instance identifier

These are dummy equality values. No digest is measured from installed code, no
UID is read from the OS, and no receipt signature or human action is verified.
The only origin constructible by the model is simulated evidence. There is no
`verified=true` field or caller-selectable actual-observation variant. Adding a
real observation path requires a reviewed collector/verifier and deployment
integration, rather than renaming fixture facts.

The model additionally rejects an agent sharing an execution identity (security
domain plus UID), principal or verification key with any protected fixture actor.
Even the strongest simulated no-admin/control-plane claim cannot override this
check. This encodes a necessary separation rule, not proof of containment or a
complete identity-provisioning policy.

## Fail-closed lifetime and contradiction behavior

All recording and inspection share one mutex. A fixed array holds ten slots;
each slot is empty, one boxed fixed-size receipt, or one latched rejection. There
is no unbounded queue, free-text evidence, receipt history or external execution.

- Missing, unknown, unsupported or negative findings remain explicit non-positive
  statuses. Simulated consistent findings still produce `no_go`.
- Wrong instance, deployment binding or observer is rejected and latched for that
  slot. A later matching receipt cannot repair the rejection.
- An exact duplicate is idempotent and does not change the observation time. Any
  non-identical receipt in an occupied slot latches `contradictory`, including a
  later positive receipt or apparent refresh. A new assessment instance is needed
  to investigate changed evidence; the old instance is not rehabilitated.
- The observation cannot predate the instance or lie in the future. Evidence has
  a fixed maximum age of 60 clock units (seconds in the fixture). Expiry is
  exclusive and checked again during inspection and duplicate submission.
  Timestamp addition overflow is invalid. No caller can extend the age policy.
- Any current artifact/host/identity/policy binding change invalidates the whole
  instance. Restoring the old binding does not clear that failure.
- Clock regression invalidates the whole instance, even if the clock later
  recovers. The injected clock is synthetic and does not establish trusted UTC,
  real monotonic time, suspend behavior or a production observation lifetime.
- Mutex poisoning fails with the existing closed `BrokerUnavailable` error.
  A fresh process/instance restores no evidence or authority. There is no durable
  assessment, revocation transaction, persistence or anti-rollback service here.

Reports contain only enums and fixed arrays, with no raw identities, digests,
paths, host details, observation bodies or secret values. This avoids presenting
arbitrary host output as trusted evidence and keeps ordinary diagnostic output
closed. Reports are point-in-time model results, not portable attestations or
ongoing measurements; the future enforcement path must revalidate its boundary
at the actual handoff/dispatch point and handle changes during execution.

## Functional verification

With the module hook present:

```sh
cargo test --locked --offline --features vault-spike vault::deployment:: --lib
cargo test --locked --offline --all-features --doc vault::deployment
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
```

Focused tests cover every required slot; negative/unknown/unsupported findings;
same-UID/principal/key separation; exact duplicates and sticky contradictions;
concurrent conflicting observations; exclusive expiry, time overflow and
regression; every artifact/host/identity/policy binding; wrong instance/observer;
no restoration; poisoning; the closed report schema; and unchanged production
refusal after a complete simulation. No host permissions, services, credentials,
OS clocks, provider state or deployment settings are changed by these tests.

These are implementation checks, not independent security review, real-host
adversarial evidence, approval of a live-secret trial, or proof that the current
machine denies the agent access. The later operator-owned canary ceremony must
supply the missing platform evidence and production integrations before a
separately authorized human key-entry decision.
