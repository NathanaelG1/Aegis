# Protected agent-blind application delivery

**Status: required product design, not implemented or verified.** The current code supports synthetic reviewed operations, foreground control, Unix IPC and MCP, plus an optional [encrypted canary delivery fixture](vault-delivery-spike.md) with typed references and cryptographic actor proofs. It has no operational application enrollment, real-key entry, protected-file installation, descriptor handoff, credential-store adapter, independently authenticated human mechanism or OS confinement verifier. The existing synthetic tests do not prove this design. [ADR 0007](adr/0007-protected-application-delivery.md) establishes the requirement; [verification](verification.md) records actual implementation evidence.

## Product contract

Aegis must let an agent working under human-delegated authority arrange configuration of two systems without receiving or being able to read the token that connects them. The agent proposes non-sensitive references and typed configuration changes. A separately authenticated human approves a broker-resolved immutable plan. The trusted broker installs the exact credential directly into the approved isolated application's protected destination, then returns bounded status. A broker-only provider API is useful but does not satisfy this application-configuration requirement.

For example, an agent may propose linking an enrolled client service to an enrolled provider account using credential reference `provider-account`, version `7`, and recipient slot `provider-auth`. These are illustrative public identifiers, not implemented commands. The broker resolves the recipient, protected configuration, approved endpoint/scope and delivery mechanism; the human reviews the resolved plan. The agent never writes the token or chooses an arbitrary path, command, auth header, endpoint, proxy, or plaintext response route. A reciprocal connection needs its own explicit bindings and authority rather than inheriting consent from the first side.

The approved application receives plaintext and joins the trusted computing base. Its code and effective configuration must prevent returning the token through logs, diagnostics, plugins, proxies, arbitrary operations, or outputs visible to the agent. Isolation alone cannot make a recipient that deliberately exports its token trustworthy.

## Request-driven lifecycle

The primary use is episodic setup of a project, delivery of an approved credential, rotation/replacement, cleanup or reconciliation. Prefer a deployment that can wake for a request and become idle after its durable outcome is recorded. Once configured, the enrolled recipient may call its provider directly without contacting Aegis for every application API call. The broker's separately reviewed bounded-operation/API-mediation mode remains optional and has different availability and latency requirements; it is never an arbitrary proxy or raw-secret export.

The intended sequence is wake, establish the supported isolation and transport boundary, authenticate the caller, load/validate durable state, resolve exact references and current policy, obtain independent approval where needed, reserve durably, perform the enrolled handoff or authorized rotation, retain acknowledgement/uncertainty, return safe status, then allow idle shutdown. A request may trigger infrastructure wake without authorizing any broker action; wake ingress needs bounded admission/rate limits and must not expose secrets or administration.

Revocation records, pending/approved/denied decisions, consumed uses, request IDs and handoff/rotation outcomes must survive a cold start in protected authenticated state. Missing/corrupt/unavailable state, stale snapshot/generation, rollback, uncertain handoff, unavailable trusted time or a changed recipient/key/policy must fail closed. Sleeping never pauses credential/approval expiry or discards a pending revocation; cold start must establish current trusted time and revocation/policy freshness before any new effect. Concurrent wakes require durable writer exclusion/fencing so a last use cannot be spent twice. A new process gets a fresh epoch/session; old handles and instance-bound approvals cannot silently resume. Reusing any approval across cold starts requires an explicitly approved durable scope/schema plus full current revalidation; until specified and implemented, fresh approval is required. A pending decision never becomes approved because the process restarted.

Idle shutdown does not replace crash recovery: the platform may stop the broker before or after any installation/acknowledgement boundary. Record consumed intent before effects, reconcile ambiguous delivery/rotation without automatic repetition or refund, and never restore older policy or counters from a VM snapshot. Closing an unlock lease or stopping a process does not prove plaintext erasure from memory snapshots, disks or recipients. The current synthetic journal restores no authority and is not this operational state backend.

A sleeping broker cannot itself enforce every later recipient/provider use or instantly revoke delivered plaintext. Future-delivery denial, recipient cleanup/termination and provider-side revocation remain distinct actions; a revocation request may need to wake the trusted broker and complete a separate provider action before reporting that effect. Provider-enforced expiry still applies. Short-lived credentials may need additional on-demand or explicitly authorized scheduled renewal, so infrequent project setup does not imply every provider credential can remain useful indefinitely without refresh. This lifecycle and its cold-start/restore tests are design requirements, not implemented hosting features.

## Required access boundary

Delivery requires a tested OS boundary between agent-executed code and the broker, human control, recipient, and every place plaintext can appear. Supported arrangements may use separate service identities or an actually confined agent with a protected recipient. They must deny agent access to credential files/stores, process memory, inherited descriptors/handles, debug interfaces and administrative control, and deny modification of recipient code, dependencies, security-relevant configuration, or confinement policy. The human channel must authenticate independently of the agent's session and automation tools.

An unrestricted agent with the recipient's UID is unsupported. Mode `0600` permits that UID to read a file; current-UID IPC authenticates account membership rather than human consent. Redaction only changes captured output. Agent-controlled container management, host mounts, exec/debug interfaces, service supervision, privileged groups or capabilities can bypass a nominally isolated identity. Changing a label, approving an executable digest, or merely placing the recipient in a container does not establish this boundary.

Delivery must fail closed when enrollment, independent approval, confinement, destination protection, or effective recipient identity cannot be established or has changed. No best-effort fallback may copy the credential into an agent workspace or pass it through agent stdout. Platform enrollment is a separate human administrative action; this design authorizes no current OS permission changes, service installation, credential migration, or live provider use. A compromised OS/kernel, privileged administrator, trusted human, or approved recipient is outside the proposed agent-isolation guarantee.

## Proposed typed workflow

These are the intended operational objects/actions. The optional canary fixture implements a closed typed subset; it is not a stable operational enrollment/delivery API or a real application adapter. Versioned schemas, bounds and error codes must be frozen only after the enforcement spikes.

| Object/action | Proposed meaning | Agent-visible data |
| --- | --- | --- |
| Delivery proposal | Request ID, exact credential reference/version, enrolled recipient/slot IDs, typed non-secret configuration intent, requested lifetime/budget within policy | References and bounded intent; never credential bytes |
| Resolved delivery plan | Broker-resolved complete bindings, effects, boundary mode and exact protected configuration revision | Only policy-authorized non-sensitive fields; public discovery is non-authoritative |
| Request approval | Create bounded pending state for the immutable plan | Pending/interaction-required status; no consent claim |
| Human approval receipt | Independently authenticated decision bound to the exact plan, broker instance/policy generation and principal/session | Approval state/opaque lookup handle; receipt is not agent-supplied authority |
| Deliver approved plan | Revalidate bindings and boundary, reserve budget, durably record intent, deliver through the enrolled mechanism | Delivery ID and bounded state; no raw application/provider response |
| Delivery status | Scoped lookup of reservation, installation, recipient acknowledgement or uncertainty | Reviewed state/reason categories; no file contents, token hashes, environment or diagnostic dump |
| Revoke delivery authority | Human control revokes future reservations; a session may surrender its own authority without expanding it | Safe revocation/cleanup status, with effects distinguished |

Agent rationale is untrusted display data, not configuration or consent. Client labels do not establish identity. Proposal IDs are scoped lookup handles. Duplicate request IDs with changed canonical intent or bindings conflict; identical retries return existing state. Cancel before reservation prevents delivery. There is no generic export, shell runner, arbitrary endpoint proxy, raw-secret read, or plaintext-return variant.

An agent may assemble a non-secret reference proposal in its workspace. The recipient must never load mutable security-relevant configuration from that workspace. A trusted installer produces a protected canonical configuration revision from reviewed schema fields and enrolled references. This includes provider URLs, proxy/redirect settings, plugin/module paths, launch environment, diagnostics, output destinations and every other field that can redirect credential use or disclosure. Updating any such field invalidates old approval. Agent edits to application code cannot be promoted into the protected recipient without a separate trusted installation/review process.

## Immutable approval bindings

The human interface displays the broker-resolved fields independently from agent-written rationale, with safe text rendering. Approval is indivisible: any changed binding requires a new resolved plan and decision.

| Binding | Required content |
| --- | --- |
| Authority | Broker-established agent principal/session, authenticated human authority, broker instance, protected policy/enrollment generation, proposal ID and canonical plan version |
| Credential | Immutable credential ID and exact version; trusted account/issuer context and established scope, with no silent `latest` following |
| Recipient | Enrolled service identity, recipient instance rules, executable/build identity, approved dependency/module/plugin closure and immutable launch policy |
| Configuration | Exact protected configuration revision and effective security-relevant inputs, including environment, runtime loaders, diagnostics and network/output routing |
| Destination | Enrolled slot, mechanism, protected directory/object/store identity, permitted file format/key or descriptor/handle contract, ownership/access policy and replacement semantics |
| Provider | Exact approved origin/endpoint profile, account/resource/scope, TLS/destination policy, permitted routes, redirect/proxy restrictions and allowed effects |
| Bounds | Approval expiry, session and delivery lifetime, delivery count/use budget, retention/cleanup policy, permitted recipient credential use and required provider expiry/revocation semantics |
| Disclosure | Plaintext recipient, allowed result/status categories, residual lifetime after handoff and the limits of local cleanup or revocation |

An executable digest alone does not pin scripts, dynamic imports, plugins, shared libraries or dependencies. The closure and protected launch/configuration must be stable at use time. References cannot certify issuer permissions by inspecting opaque token bytes. Provider scope must come from trusted provisioning/enrollment evidence and provider enforcement where needed.

One reserved use counts a delivery attempt, not every later API call by the recipient. Once a reusable credential is delivered, a broker counter cannot limit the recipient's provider calls. Any advertised downstream use count or expiry requires demonstrated recipient/provider enforcement, such as scoped short-lived credentials; otherwise the human view must clearly limit its promise to future broker deliveries.

## Delivery lifecycle, crash and revocation semantics

The proposed logical sequence is `proposed -> awaiting approval -> approved -> reserved -> installation committed -> acknowledged`, with pre-reservation cancellation/denial/expiry and retained `failed` or `outcome_unknown` states. These states are distinct from the implemented operation state machine. Acknowledgement means only the evidence defined by the recipient adapter; it is not proof that all future use is safe.

Before any plaintext handoff, the broker revalidates exact bindings, current recipient/boundary and grant expiry under the reservation/revocation serialization domain. It reserves at most one use for the delivery ID and commits a protected durable intent. Effects run outside the state lock. Revocation winning before reservation prevents delivery; an already reserved handoff may complete. Unsupported persistence or uncertain boundary evidence blocks delivery.

A crash or lost acknowledgement after installation can mean the recipient already has the token. Keep consumed authority and `outcome_unknown`; never automatically reinstall, mint another credential, refund a use, or retry under a new ID. Restart invalidates session authority and requires protected journal reconciliation before another delivery to the affected slot. Reconciliation examines trusted object/version and recipient evidence without returning plaintext. Single-file atomic installation is not an atomic transaction across journal, configuration, credential store and recipient process. Each mechanism needs a fault matrix and explicit recovery protocol.

Revocation has separate effects:

- **Future delivery authorization:** stop new reservations at the broker's serialization point.
- **Local cleanup:** remove or invalidate the enrolled installed object where safe and report verified cleanup, failure or uncertainty. Removing a pathname cannot erase open descriptors, memory, snapshots or copies.
- **Recipient lifetime:** a separately authorized supervisor may stop the recipient and close resources. Process termination is not guaranteed erasure of all copies or backups.
- **Provider credential revocation/rotation:** a separately reviewed, authorized provider action disables issuer authority, subject to provider propagation and existing-session semantics. Local grant revocation does not perform this action implicitly.

Neither revocation nor an expired broker session retracts plaintext already delivered. The approval display must make that limit clear. Ambiguous provider revocation also requires retained uncertainty and reconciliation.

## Protected destination mechanisms

All mechanisms are unimplemented candidates; support only after mechanism-specific adversarial and fault tests.

| Mechanism | Required protections |
| --- | --- |
| Protected application file | Human-enrolled protected directory and fixed slot/format; broker-controlled installation; agent cannot read/write parents, target, staged file, backups or mount namespace |
| Descriptor or OS handle | Direct transfer to the authenticated enrolled recipient; explicit inheritance allowlist; agent cannot duplicate, reopen via process interfaces, inspect or capture the handle; no secret in command line/environment |
| Native credential store | Broker writes the exact enrolled item with demonstrated recipient-only access policy; agent cannot query it, broaden access, substitute the item, or automate trusted consent |

File installation must anchor operations to enrolled directory handles/object identities rather than check a string path and reopen it. Reject symlink/magic-link traversal, unapproved parent replacement, hard-linked targets and mount/bind-mount/reparse substitution. The agent must lack access to mutate the enrolled namespace. Stage a new regular object privately within the enrolled destination, set and verify the recipient-only access policy before writing, serialize slot updates, and atomically install the expected version with explicit no-overwrite/replacement rules. Verify object identity, ownership, link count, file type and access policy through the handles actually used. Flush object and directory/journal state according to the tested platform durability protocol. Hard-link exclusion and protected namespace ownership require their own checks; symlink flags alone are insufficient. Never mutate an existing object through an untrusted alias.

Protect plaintext in broker/recipient memory, temporary buffers, files, inherited descriptors/handles, process inspection and environment. Credential values must not enter command arguments or general process environment. Paths/references can be non-secret only under a reviewed metadata policy. Prevent token capture through logs, telemetry, stdout/stderr, panic reports, dumps, backups, application diagnostics, shell tracing, malicious plugins and configurable proxies/output routes. Buffers and local artifacts need an explicit cleanup policy with honest erasure limits; no universal memory-erasure guarantee follows from file deletion or a canary search.

## Platform proposals and primary references

The following are design inferences from documented mechanisms, not claims of tested Aegis support. These references were consulted for this design; shipping support must pin the actual OS/service-manager/API versions and record settings and bypass tests. No settings were changed for this work.

| Platform | Proposed arrangement | Evidence still required |
| --- | --- | --- |
| Linux | Separate broker/recipient/agent service identities, protected unit/build/configuration, service credentials or a reviewed direct handle/file adapter; independently authenticated human control | Actual identities, mount/process isolation, privilege/debug restrictions, credential visibility, protected installation, durable recovery, and agent bypass attempts |
| macOS | Protected service identities, or an actually confined agent plus hardened protected recipient and authenticated IPC/human control | Signing/entitlements/runtime configuration, protected dependencies/configuration, file/memory/handle access, consent spoofing, lifecycle and installation faults on named macOS versions |
| Windows | Separate service identities, explicit file/process/store DACLs and minimal handles; AppContainer/LPAC for the agent where appropriate; authenticated human control | Token/capability/DACL composition, inherited/duplicated handles, debug privileges, reparse/path races, protected config, consent and recovery tests on named Windows versions |

Linux [systemd credentials](https://systemd.io/CREDENTIALS/) provide per-service credential files and recommend mount namespacing; this suggests an adapter, not an Aegis guarantee against agents sharing that identity. Linux [Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) describes same-UID process inspection and configurable ptrace restrictions; no single ptrace setting proves complete isolation. The [openat2 manual](https://www.man7.org/linux/man-pages/man2/openat2.2.html) documents directory-relative resolution and symlink/magic-link/mount restrictions; it does not solve hard links, namespace ownership or whole-transaction durability.

Apple describes code provenance checks and sandboxed app access in [Gatekeeper and runtime protection](https://support.apple.com/en-gb/guide/security/sec5599b66df/web). Those controls motivate further platform-specific recipient/agent spikes; notarization or Gatekeeper alone does not establish this delivery boundary. Microsoft documents profile/capability/token setup in [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) and DACL, memory-read and handle-duplication rights in [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights). A container label or file DACL alone cannot justify the composed guarantee.

## Synthetic adversarial acceptance gates

Use only public synthetic canaries and test identities in dedicated fixtures. Each claimed mode must exercise an adversarial process with the agent's actual effective access, plus a positive enrolled-recipient read/use. Record OS, architecture, service manager, filesystem, identity/token/capabilities, launch/configuration and attempted bypasses. None of these gates has been completed for application delivery.

| Gate | Required observable result |
| --- | --- |
| Missing or bypassable confinement | Delivery refused before credential resolution/handoff; unrestricted same-UID, privileged group, agent-controlled supervisor/container or debug access cannot select a protected mode |
| Unauthorized plaintext reads | Agent cannot read installed/staged files/stores, environment, broker/recipient memory, descriptors/handles, dumps, logs or backups; enrolled recipient can consume the fixture |
| Recipient/configuration substitution | Changing executable/build/dependencies/plugins, service instance/identity, protected revision, launch environment or destination invalidates approval with zero handoff |
| Provider/route substitution | Endpoint, DNS/destination policy, proxy, redirect, headers, diagnostics or output-route tampering cannot redirect credential use or disclosure |
| Forged human approval | Agent-supplied approval/identity, replayed receipt, spoofed control endpoint, automated terminal or UI action cannot create consent within the declared mode |
| Replay and restart | Same ID never repeats handoff; changed bindings conflict; stale epoch/session/approval rejected; crash after installation retains uncertainty and blocks blind retry |
| Cold start and concurrent wakes | Missing/corrupt/rolled-back state fails closed; fresh authentication/epoch, no stale approval revival, durable last-use exclusion, and retained unknown handoff/rotation without repeat/refund |
| Concurrent final use and revocation | Forced barriers show at most one final-use reservation; revoke-before-reserve prevents delivery; already reserved completion and cleanup/revocation outcomes are explicit |
| Path and object races | Symlink, hard link, parent rename, mount/bind-mount/reparse, target replacement and stale handle attempts cannot install to or expose an unapproved object |
| Hostile recipient extensions | Agent-writable plugin/import/config, malicious proxy, debug endpoint or diagnostic/output route cannot gain access to the protected recipient's token |
| Installation and lifecycle faults | Failure/crash at every staging, flush, install, journal and acknowledgement boundary leaves a reconcilable protected state; lock/suspend/logout/expiry and cleanup tested per supported mode |

Implementation order and release gates are tracked in [roadmap](roadmap.md). An API-only canary test, successful ordinary file write, compilation on another OS or demonstration under a trusted same-user account does not satisfy these gates.
