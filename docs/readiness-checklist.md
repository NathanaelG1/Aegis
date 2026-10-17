# Aegis readiness and deployment decision checkpoint

**Updated 2026-10-07: ready for continued synthetic engineering; not ready to receive a real GitHub App private key.** The optional composed exercise now joins exact broker approval, durable synthetic intent, disposable maintained-library RSA signing, mock exchange, safe metadata output, deduplication and explicit mock revocation. A green unit test does not establish protected deployment. The subsequent [vendor-neutral access-control decision](access-control.md) refines the architecture and adds synthetic acceptance regressions; remote activation still requires the end-to-end deployment decisions below.

## What is complete, and what it proves

- [x] Main-broker exact reviewed authority, bounded use, one reserve/revoke serialization point and safe V2 result schemas; legacy issue interfaces preserved.
- [x] Personal selected-repository fixture for NathanaelG1, explicit metadata-only operation scope under a minimal installation ceiling; organization/all-repository/surplus permission substitutions denied.
- [x] Sync-before-effect synthetic journal, strict version/state parsing, crash/fault injection and inspection-only recovery; no restored grants/sessions, automatic retry or uncertain-use refund.
- [x] Optional disposable RSA-2048/RS256 signing through private approval-bound permits; strict claims, exact current-time verification, no public credential bytes or general signing method.
- [x] Focused independent code review and Linux non-listener regression evidence, with remaining failures explicitly recorded.

These establish exercised synthetic behavior. They do not authenticate a human, protect files or process memory from an agent, detect malicious journal rollback, contact GitHub or deliver credentials to an isolated application.

## Overnight code milestone and remaining gates

An [optional integrated canary vault](vault-delivery-spike.md) now joins actual signed principal/approval checks, exact ACLs, encrypted records/capsules and durable delivery/rotation/revocation through the main core. This is code/test progress, not a generic secret-entry product. Real operator entry, production identity/clock/transport integration, independently protected custody/anchor and an actual isolated recipient adapter remain missing. The [operator-owned ceremony](operator-owned-deployment.md) lists the concrete later permissions and required adversarial evidence. Removing agent admin access alone does not complete those code gates. [Separate typed agent/admin handlers](vault-protocol.md) now provide reusable library connection boundaries and role-specific runtime key ownership. Their constructors still load fixed-canary fixtures; transport peer binding and independently provisioned production identities remain missing.

## Primary usage and hosting lifecycle

The primary product flow is episodic project setup and secret delivery/rotation. Prefer a host lifecycle compatible with waking for a request and becoming idle after durable completion or retained uncertainty. The recipient can use an installed credential directly while Aegis sleeps; continuously mediating every application API call is an optional separate mode. Short-lived provider credentials can still require refresh wakes. This is a product/deployment preference, not an implemented sleep/wake feature or a guarantee of instant revocation.

A private Sprites pilot is approved only for budget-bounded synthetic development/testing; it is not a selected or approved real-key deployment. Its baseline tests establish Unix workflow behavior, not protected wake/persistence/isolation or production availability. Evaluate any candidate against protected durable state and rollback detection, cold-start authentication/policy revalidation, recipient isolation, secure wake ingress and the required transport/exposure tests. Vendor-neutral application authentication/ACLs stay mandatory; private networking stays optional. No host setup or service purchase is authorized here.

## Minimum missing end-to-end components

| Required component | Minimum exit evidence |
| --- | --- |
| Named, supported OS/host boundary | Broker identity isolated from the actual agent's shell, files, process memory, environment, descriptors, debugging, service/admin/container sockets and mutable code/configuration. Demonstrated denials and fail-closed startup when protection is absent or changes. |
| Application authentication and ACLs | Verified issuer/subject/enrollment before exact default-deny ACL evaluation; protected bootstrap/admin, separate authentication/operational credentials, revocation and bounds; no reliance on IP/network membership or client/proxy claims. Actual remote enforcement remains unimplemented. |
| Independent human approval | Authenticated control channel outside agent reach, canonical request challenge tied to instance/profile/repo/permissions/key revision/limits, explicit human action, replay prevention and tested lock/logout/cancel/expiry behavior. A terminal under the same unrestricted UID does not satisfy this. |
| Protected sign-only key custody and provisioning | User-controlled secure entry into an independently protected broker/vault, no agent-visible import/PEM/export/log path, key identity/version binding, lock/rotation/deletion behavior and tested recovery. The optional age fixture is not this backend. |
| Operational durable state | Protected namespace and authenticated records, explicit rollback/deletion detection or fail-closed external generation anchoring, crash-safe transactions/rekey/recovery, correct real issuance/revocation timestamps, consumed budgets and reconciliation that cannot resurrect authority. No checksum should be described as tamper-proof. |
| Reviewed fixed live transport and real time | Maintained TLS/HTTP stack, fixed GitHub destination/API routes, no redirects or environment proxies, strict headers/body/scope/response limits, current trusted UTC plus elapsed-clock handling, actual installation-token expiry, timeout/unknown outcomes and independently checked exchange/revocation behavior. Current mock request flags do not enforce networking. |
| Request-driven lifecycle | Durable revocation/approval-decision/use/rotation state; fail-closed cold start/restore, fresh epochs/authentication, explicit durable-approval semantics, concurrent-wake fencing and crash/acknowledgement reconciliation. Neither sleeping nor restoring a snapshot may reset budgets or revive revoked authority. |
| Full host/protocol composition | Listener/IPC suites pass on the selected host; authenticated control and agent principals remain separate; real agent harness gets safe results and cannot synthesize consent or read/redirect credentials. Reboot, process crash, suspend and lost acknowledgements have recorded behavior. |
| Release and independent security review | Pinned per-target dependencies, native/unsafe and advisory/license review, artifact provenance and protected installation/update path; adversarial composition review with findings remediated. |

A real-key trial should start with one read-only metadata operation on one selected disposable personal repository, only after the above gates. This is a proposed validation scope requiring separate user authorization. The intended app is owned by NathanaelG1, restricted to installation on that account and selected personal repositories. The eventual installation ceiling is Contents read/write plus Metadata read; this initial operation requests only Metadata read. Existing app permissions must not silently expand; no organization, workflow, administration or user-token access belongs in this first step. GitHub installation tokens last one hour; local policy may stop using them sooner but cannot claim GitHub issued a shorter TTL. See [GitHub’s installation-token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

## Deployment choices requiring a decision and permission

The application identity/ACL contract is vendor-neutral and mandatory for a future network API. Operator-managed private networking is optional and independent of the hosting choice. A configurable listener must use TLS or an explicitly trusted secure reverse proxy, enforce backend trust and verify private-only exposure when selected. Current Aegis has no HTTP/TLS listener or private-network setup path; see [the transport contract](access-control.md#transport-and-optional-private-network-deployment).

### Recommended first target: dedicated Linux environment with enforceable identities

Choose a specific user-approved host/VM where standard local IPC is permitted and the trusted operator can enforce separate broker/agent identities. The agent may instead be on a different machine with only authenticated TLS API access; no private overlay is mandatory. In either topology, its tools must not administer or read the secret-bearing broker host. On the broker/recipient host, the agent must lack root/sudo, tracing rights, broker filesystem access, service administration and privileged container/control sockets. Broker binaries, libraries, configuration and journal parent directories must be outside the agent's writable namespace. Select an independently authenticated human approval endpoint before key provisioning.

Key custody can be either an independently protected local backend with a reviewed unlock/recovery design, or an external sign-only vault/HSM. The latter adds a provider/account/cost and access-policy decision; it is not currently integrated. The cloud preference does not itself authorize host purchase, service identities, ACL/security changes, firewall rules, external vault access, credential creation or upload. Those exact actions and destinations require approval first. A dedicated VM label or container name alone is insufficient.

### Current dot cloud workspace: development evidence only

The current Debian/Linux cloud workspace builds and runs non-listener tests, but 14 existing Unix-listener interface tests fail because binding is denied with `EPERM`. The documented supported execution attempt did not remove this restriction. No full signed foreground/IPC workflow or protected broker/agent OS separation is verified here. Do not bypass the sandbox, disable its controls, assume administrator access, or place real keys in this workspace. A supported environment with documented IPC and isolation controls must be selected before deployment testing; ordinary same-UID file modes cannot fix this boundary.

### Private synthetic Sprite pilot

The separately operated private pilot passed all 169 default and 228 all-feature tests for source `e353a6b`, including the 14 listener cases blocked in the dot workspace, plus an actual GitHub foreground/MCP v2 smoke. Newer increments need their own immutable-source verification. Same-UID recovery-kit reads and automated terminal approval were also reproduced, so these passes do not establish secrecy from an administrator/agent with equivalent access. Its current agent admin/exec/filesystem/checkpoint/restore access must be removed under a separately approved operator-owned ceremony before any real-key deployment, after the missing production code gates are completed.

### macOS alternative

A separately protected service identity or actually confined agent, protected recipient/key-store access and independently authenticated IPC/human approval could be evaluated. Existing same-account terminal/peer checks and historical Mac tests establish workflow only. This would require explicit Mac access/security configuration approval and fresh current-code tests; it also reintroduces the user's lock/disconnection availability concern. It is not the preferred next target for this cloud-first task.

### Windows alternative

A separate service identity with tested DACLs/process protections, an appropriately confined agent and authenticated control may be viable. Aegis currently lacks Windows transport; named-pipe/identity, filesystem, lifecycle and recovery behavior would need implementation and independent validation. No Windows support or equivalent confinement follows from the Rust build. This is a later port, not the shortest first deployment.

## Primary delivery goal and optional Git/API operations

Metadata access alone does not complete the user's agent-blind application-delivery goal. Git requires a trusted isolated worker or explicitly bounded broker operations. It must pin repository/remote/operation scope and trusted executables, disable agent-controlled hooks/helpers/config/plugins/proxies and hostile transport/file paths, and keep credentials out of agent environment/argv/stdout and general shell. An ordinary credential helper hands a token back to its caller and therefore does not meet the guarantee.

The primary application-delivery path needs recipient enrollment, immutable executable/dependency/configuration/destination binding, independently authenticated approval, direct protected handoff and durable crash/acknowledgement reconciliation. The existing [application-delivery contract](application-delivery.md) remains design work. Do not claim an isolated Git worker or agent-blind delivery exists because metadata signing works.

## Verification plan for an approved isolated target

1. Record OS/version/filesystem, identities, privileges, tool access and protected binary/configuration provenance. Use disposable canaries only.
2. Run the complete current default/all-feature suites, including the previously blocked 14 listener tests. Reproduce the composed broker path through the actual agent host and separate human channel.
3. Attempt agent reads/redirects through files, environment, `/proc`/debuggers or platform equivalents, inherited handles, IPC/control endpoints, helpers/plugins and administrative/container APIs. Any accessible credential/control path blocks the mode.
4. Force final-use/revoke and simultaneous-wake races, stale review/key versions, denied/missing protection, clock changes, lock/suspend/logout, idle shutdown/cold start, process kill/restart, partial/sync writes, missing/rolled-back restore state and lost provider/handoff acknowledgement. Verify no secret output, unreviewed effect, retry/refund or restored authority.
5. Independently review evidence and remediation. Only then request approval for a least-privilege live test and user-performed secure provisioning. Verify provider-side repository/permission/expiry/revocation behavior separately; never infer it from mocks.

## Effort estimate and stopping point

The earlier estimates below describe read-only metadata validation followed by protected delivery work; they do not require an always-running broker. Episodic delivery still needs the cold-start and durable-state gates above, and no hosting latency/cost estimate has been verified.

Planning estimate, not a delivery promise: for one experienced engineer plus an independent reviewer, one chosen Linux deployment, read-only metadata scope and timely host/approval decisions, budget roughly **4–8 engineering weeks** for a defensible first real-key trial. A boundary feasibility pass is several days; protected custody/approval, operational persistence/live transport and adversarial composition typically take further weeks and may overlap. Unknown host restrictions, a new human-auth mechanism, recovery requirements or review findings can extend this substantially. Multi-platform support and a production release need additional work.

A constrained isolated Git worker/application handoff is a separate substantial increment, plausibly **2–4 additional weeks or more**, depending on allowed operations and platform evidence. These are engineering estimates, not promises of a security guarantee. The next action is to choose the supported Linux host, custody model and human-approval mechanism, then approve only the concrete deployment changes needed for a synthetic boundary test. No provisioning, remote activation, authentication enrollment or real-key request is implied by this checklist. The architecture/acceptance update leaves these deployment permissions unchanged.
