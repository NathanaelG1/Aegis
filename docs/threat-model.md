# Threat model

## Protected-mechanism development delta (9 October 2026)

[ADR 0018](adr/0018-protected-mechanism-development.md) adds maintained TLS 1.3
mutual authentication with exact fixture enrollment and exporter-bound frames,
a bounded ciphertext-only import experiment, and a fixed recipient child process
joined to durable broker reservation/receipt handling. These introduce TLS/X.509
libraries, input/publication code and a process supervisor into the trusted
implementation. Their contracts record [transport](tls-transport.md),
[import](protected-entry.md) and [recipient](recipient-process.md) limits.

The development process owns its test TLS identities and simulated human proof
signers. The recipient child and its parent share one UID and trust domain;
the current executable is not an immutable enrolled deployment. Input memory,
path operations, logs, backups, recovery and host control-plane access still need
the operator-owned boundary. A successful cryptographic channel does not attest
either endpoint. The import drill and delivery drills are not an operational
end-to-end service, and no live provider path exists. All real-key admission
remains refused. Ordinary functional checks for this increment do not resume or
replace the stopped independent adversarial review.

**Status:** Implemented synthetic policy/Unix/MCP foundation with an optional fixed-fixture recovery experiment. Protected agent-blind application delivery is required but not yet implemented or verified. No independent audit, proven human-presence mechanism, real-secret storage guarantee, or OS containment deployment is established.

## Product promise and boundary

The intended promise is that an agent can invoke only the reviewed operations delegated to its broker-bound principal/session and receives only the operation's authorized result. It must also be able to propose application configuration using secret references while the broker delivers the token directly to an approved isolated application and the agent is unable to read it. Human administration and approval are separate from agent requests. Credentials are used by the trusted broker/executor or enrolled recipient rather than copied into the agent protocol. The [application-delivery design](application-delivery.md) specifies the unimplemented boundary and approval requirements.

The first proof is narrower: the synthetic in-memory broker enforces its tested API contracts, concurrency, and failure semantics. The Unix workflow retains control in the foreground terminal while the MCP process has only an agent socket bridge. Current-UID checks, new private directories, cached canonical review, and per-broker epochs enforce specific workflow rules. They do not stop same-account code from automating control or bypassing its own trust boundary. The trusted Rust embedding process can also hold both handles. A malicious embedding host can obtain or bypass its own capabilities.

## Assets

| Asset | Why it matters |
| --- | --- |
| Credential and unlock/recovery material | Enables provider use or snapshot decryption; currently synthetic only |
| Profile and grant authority | Determines permitted action, resource, inputs, output, time, and use count |
| Principal/session binding | Prevents lookup IDs or labels from transferring authority |
| Request/run state and reservations | Prevents duplicate effects, overspending, and ambiguous retries |
| Provider result data | May be sensitive, hostile, misleading, oversized, or malformed |
| Private metadata and audit data | May reveal account/resource names or activity even without credentials |
| Broker binary, configuration, adapters, and dependency graph | A change can bypass policy or leak credential material |
| Enrolled recipient, protected configuration and delivery destination | Code, dependency, route, slot or process substitution can expose plaintext after approval |
| Future snapshots, identity, backups, and recovery kit | Need confidentiality, valid schema, recoverability, and explicit rollback limits |

## Adversaries and failures

Assume model-controlled requests can be malicious, prompt-injected, stale, malformed, repeated, or concurrent. They may lie about identity/approval, broaden scope, guess handles, flood pending requests, request a different credential, or induce retries. Provider content can be attacker-authored. A fake provider should exercise hostile output and ambiguous acceptance.

Also consider accidental logs/debugging, panics, crashes, corruption, clock/lifecycle changes, dependency compromise, mutable consumers, stolen backups, hostile local storage writers, and old snapshot rollback. These are separate from a compromised host/kernel and from arbitrary code with the same user's full access.

## Protection modes

| Mode | Trusted components | Intended eventual guarantee | Current evidence |
| --- | --- | --- | --- |
| Portable workflow | User account, host, broker, approved consumer/executor | Private storage and explicit API workflow under a trusted account | Synthetic API and Unix/MCP workflow; separate synthetic age drill, no operational storage/unlock |
| Restricted agent operation | Host that actually restricts tools, broker, reviewed adapters, provider | Model requests can exercise only delegated operations through this interface | No integrated host enforcement tested |
| Isolated agent deployment | Tested separate identity/sandbox/VM, broker, protected human authority | Stronger separation from malicious agent-executed code | No deployment or platform proof |

Do not choose a stronger label because a configuration says tools are restricted. Record and test enforcement. A dedicated non-administrator identity may be appropriate later; a root/system broker is not a convenience shortcut.

Protected application delivery cannot be offered as a confidentiality guarantee in the trusted same-user workflow. It requires tested separate service identities or actual agent confinement, protected recipient files/process resources and independently authenticated human control. Agent-writable recipient code/dependencies/plugins/configuration or agent-controlled supervisor/container/debug interfaces invalidate it. File mode `0600`, peer UID checks and redaction alone cannot prevent agent access. Delivery must refuse an unsupported or changed boundary before handoff. No such refusal/confinement verifier is implemented today.

## Boundary analysis

| Boundary | Required defense | Synthetic check | Remaining work |
| --- | --- | --- | --- |
| Agent -> prepare | Typed inputs, fixed reviewed operation/resource, bounds | Wrong scope and malformed inputs rejected before executor use | Fuzzing and complete resource bounds |
| Agent -> approve | No agent approval method or trusted boolean | MCP/wire have no control method; terminal approval requires exact cached inspect | Protected human channel and presence evidence |
| Prepared -> dispatch | Exact current bindings and expiry checked atomically with reservation | Stale bindings, expiry, last-use race | Durable journal if budgets persist |
| Agent -> run status | Scope checked on every lookup | Bound client scope; no principal selector; MCP metadata cannot establish identity | Distinct-principal host integration and enforcement proof |
| Executor -> result | Reviewed output version, schema, fields, size | Hostile fake output rejected | Actual provider transport and data contracts |
| Revoke -> dispatch | One serialization point | At most pre-revoke dispatches may complete | Provider cancellation/revocation semantics |
| Host -> broker/control | Prevent editing binaries/config, memory/file reads, control synthesis | Same-account Unix peer checks implemented; account itself is trusted and uncontained | Host-specific spike with bypass attempts |
| Storage -> policy | Full validation, owner-controlled writer, non-authoritative catalog | No storage implementation | Permissions, provenance, import/restore, rollback tests |
| Recovery -> ready | Independently saved kit plus fresh process restoration | Fixed synthetic snapshot restored in a fresh process; grants disabled/session empty | Operational gate, independent custody, platform/cancellation/fault tests |
| Broker -> application | Immutable approval, enrolled isolated recipient, protected destination and durable handoff state | No delivery implementation or tests | File/descriptor/store adapters, confinement, authenticated control and crash reconciliation |
| Agent -> recipient plaintext | Deny file/store/env/memory/handle reads and code/config/route substitution | No OS boundary tested | Synthetic adversarial processes, path races, malicious plugins/proxies/diagnostics and per-platform evidence |

The Unix endpoint caps active connections at eight, uses bounded frame I/O, rejects existing/symlink-component paths, and checks the current UID on server/client. A random broker epoch prevents an existing bridge from silently following a restart. Path checks are nonatomic and same-account code remains trusted; an epoch does not authenticate a trusted broker binary. All socket connections currently share one principal/session. See [verification](verification.md) for actual observed outcomes and gaps.

## Action safety versus confidentiality

An adapter can keep a token out of the result while performing a harmful action. Constrain issuer authority, resource, concrete input range, effects, output, lifetime, and call budget. The human approval must describe these constraints accurately. A read operation can still disclose sensitive data; result projection is part of authorization.

No generic redaction or keyword filter makes arbitrary provider output safe. No model judgment is an authorization decision. User-authored returned content remains untrusted even when the transport and schema are valid.

## Network adapter requirements

No live network adapter is authorized or implemented in the first foundation. A future reviewed adapter must fix the provider origin and route construction, verify TLS, disable redirects initially, and reject caller-controlled origins, authentication headers, proxies, arbitrary routes, and credential references. Bounds cover time, bytes, decompression, pagination, and projection.

Transport must validate the destination used for the actual connection, including DNS/address behavior. A preflight string allowlist with a different connection path does not establish destination safety. Private-network providers need explicit profiles. Provider-enforced least privilege and short-lived tokens reduce consequences but do not replace broker policy.

## Storage and recovery risks

Future protected delivery must cover plaintext in installed/staged objects, descriptors/handles, process memory, environment, logs, backups, dumps and application diagnostics. Protected configuration cannot be read from a mutable agent workspace. The approved recipient is trusted to avoid exporting its token; granting it arbitrary output, plugin or proxy routes defeats isolation. File installation needs enrolled directory/object handles, symlink/hardlink and parent/mount/reparse defenses, versioned atomic installation and fault-tested journal recovery. Unknown handoff outcomes consume authority and prohibit automatic retry. See [delivery acceptance gates](application-delivery.md#synthetic-adversarial-acceptance-gates).

The optional age 0.11.1 [synthetic spike](storage-spike.md) saves a fixed encrypted snapshot and a separate recovery kit, then restores in a fresh process with grants disabled and sessions empty. It accepts no caller-provided real values and does not become broker authority or an operational `ready` state. The operational backend remains planned. Recipient encryption does not certify that the policy came from an authorized writer: an attacker who knows a public recipient can create a new encrypted snapshot. Live storage ownership and restore/import grant disabling matter. A future untrusted writer/synchronization feature needs policy provenance anchored outside the attacker-controlled store.

Generation checks prevent certain accidental lost updates, not hostile rollback. Old snapshots remain decryptable by identities that could read them. Deleting a record, revoking a session, changing a passphrase, changing recipients, and rotating a provider credential have different effects. Previously exported plaintext cannot be retracted.

An atomic snapshot replacement does not establish an atomic multi-file rekey. Crash tests must show an old matching identity/snapshot pair or a new matching pair remains usable. Network/shared filesystems are unsupported until tested.

## Approval mechanism spike

The implemented terminal workflow requires inspection before approval, refuses nonterminal stdin unless the explicit synthetic test flag is used, and stops on EOF. Before claiming genuine private approval, select a protected host integration and demonstrate:

1. The agent cannot obtain the control handle or call an administrative endpoint.
2. The approval view shows broker-resolved canonical fields, not agent-crafted text.
3. Agent automation cannot synthesize the human action within the claimed mode.
4. No credential reaches agent stdin/stdout/stderr, logs, traces, or crash output.
5. Approval, denial, cancel, expiry, revoke, and resume behave without hidden prompts or authority broadening.

A terminal controlled by the same fully privileged account can establish a workflow but not containment against that account. Evidence must name the OS, host, agent tools, identities, permissions, and attempted bypasses.

## Explicit non-guarantees

- No containment of arbitrary same-user code or a compromised host/kernel.
- No protected application delivery, recipient enrollment, independent human authentication, protected-file/handle/store installation or verified agent-blind plaintext boundary.
- No retraction of already delivered plaintext; future-delivery revocation, local cleanup, recipient termination and provider revocation have separate effects.
- No production credential custody, recovery, or filesystem durability yet.
- No exactly-once external effects or automatic safe refund after an unknown outcome.
- No persistent cross-session/cross-restart call budget.
- No proven suspend/lock behavior or headless approval.
- No trusted output text beyond the specific typed projection.
- No cross-platform support based solely on compilable Rust.
- No security audit or dependency audit inferred from tests and a lockfile.

## Review triggers

Update this model for a new provider, write operation, raw-value embedding API, persistence/journal, unlock provider, IPC transport, host integration, consumer runner, plugin, background service, output text/data category, or claimed platform. Each change needs concrete authority and failure tests before its guarantee appears in product documentation.

## GitHub App preparation delta

[ADR 0008](adr/0008-github-app-synthetic-preparation.md) adds a synthetic-only GitHub adapter to the reviewed source surface, not a live provider or agent capability. Threats exercised include organization/all-repository scope substitution, stale signer/installation bindings, permission surplus, mutable route names, malformed/hostile output, stale token use, unknown mint/read outcomes, replay and revoke races. Tests use only public fake tokens. All real-key, independently authenticated approval, durable intent, live destination/TLS and OS-isolation gates remain closed. Private types cannot resist a same-UID shell, altered code, memory inspection or logs from a malicious trusted implementation. No actual key custody, network confinement, secure erasure, Git-worker isolation or crash-safe provider reconciliation is demonstrated.

## Synthetic intent-journal delta

[ADR 0009](adr/0009-synthetic-durable-github-intents.md) adds persistence for non-secret fixed GitHub fixture facts. New risks are partial writes, lost sync acknowledgement, invalid/reordered history, competing writers/readers, process exit between effect and receipt, and accidental restoration of authority. The experiment uses pre-effect sync, a lifetime OS file lock, strict bounded parsing/transition validation, sticky failure and inspection-only recovery. It assumes trusted storage/namespace; valid-history rewrites, whole-record truncation, rollback/deletion and malicious same-UID writers are not detected. No cryptographic provenance, protected journal enrollment, key material persistence or device-power-loss guarantee is claimed. See [the journal contract](github-intent-journal.md).

## Main-broker GitHub integration delta

[ADR 0010](adr/0010-versioned-synthetic-github-broker.md) introduces a fixed synthetic V2 agent operation and a typed adapter dispatch boundary. Threats include cross-operation profile/result substitution, legacy-wrapper mutation before rejection, forged/stale review, duplicate-ID effects, double consumption, lost durable reservations and cross-schema recovery. The core is the sole authority, its reservation/revoke lock precedes journal sync, and provider execution consumes one private non-Clone work item outside that lock. Broker-bound schema 2 records actual review/budget context but does not authenticate those claims or reconstruct every idle decision. Human-presence, protected custody/namespace, live transport, rollback defense and agent-blind Git delivery remain open.

## Optional signing-source delta

[ADR 0011](adr/0011-optional-disposable-signing-source.md) adds native crypto and JWT/DER libraries only behind `signing-spike`. Its disposable-key source exercises exact key/version/issuer/algorithm binding, stale handles, lock/revoke/owner-drop ordering, bounded signing, clock regression, strict JOSE fields and claim validation. The public surface returns evidence only and the protected source always refuses. Buffer zeroizing drops do not protect against same-process/same-UID access, copies, native temporaries, swap or dumps. Process-global provider exclusivity fails closed and complicates embedding. First-party unsafe prohibition does not cover native/unsafe dependency internals. This is not protected storage or a live broker composition; the [contract](signing-spike.md) lists the native build, maintenance and review costs.

## Approval-bound signing composition delta

[ADR 0012](adr/0012-approval-bound-synthetic-signing.md) connects private one-shot signing to the exact core review after durable reservation. New risks include review/budget substitution at execution, duplicated permits, untracked clock observations, slow-sync JWT expiry and treating key lock as token revocation. Frozen-view equality, one-shot ownership, a source-checked issuance stamp plus current post-sync verification, and separate cached-token authority address these within the synthetic model. Fault/panic/crash tests retain consumed uncertainty. No keys/JWTs enter the journal or agent surface. The explicit optional constructor adds no live transport, authenticated human control or OS protection. [The readiness checklist](readiness-checklist.md) defines those unresolved composition/deployment gates and the current cloud listener restriction.

## Vendor-neutral authentication/ACL design delta

[ADR 0013](adr/0013-vendor-neutral-authentication-and-acl.md) defines future remote identity and authorization independently of the hosting/private-network vendor. Added threats include display-name or IP impersonation, forged proxy assertions/direct backend bypass, confused issuer/audience/credential versions, partial-ACL scope union, agent escalation into bootstrap/admin, unavailable verification fail-open and accidental public exposure of a private listener. [The contract and acceptance matrix](access-control.md) require authenticated stable enrollment, exact default-deny policy plus human approval, explicit proxy trust, protected backend access and verified IPv4/IPv6 exposure. Network admission remains supplemental. Current tests exercise only existing typed wire/core spoofing denial; no HTTP authentication, configured ACL, network containment or same-UID secrecy is established.

## Integrated synthetic vault delta

[ADR 0015](adr/0015-integrated-synthetic-vault-delivery.md) adds actual signed-assertion checks and an encrypted canary handoff to the main core. Review must cover unauthenticated-handle inheritance, cross-role/epoch/request/ACL/recipient/secret substitution, legacy approval bypass, nonce replay, known-failure versus post-handoff uncertainty, malicious signed-state parsing and reset of durable use/revocation history. The fixture key kit intentionally contains every simulated actor key, its separate anchor shares the same host trust, and the recipient runs in-process. A same-UID/admin attacker can defeat those custody assumptions; coherently restoring the whole kit/state is not detected. All real-key readiness remains unavailable. The [operator-owned ceremony](operator-owned-deployment.md) requires independent signers/custody/anchor and demonstrated removal of privileged agent access before real material.
