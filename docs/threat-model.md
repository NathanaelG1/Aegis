# Threat model

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
