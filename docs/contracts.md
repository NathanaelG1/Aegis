# Product and policy contracts

This document separates the synthetic foundation's intended invariants from future release requirements. The executable tests and [verification record](verification.md) determine what has actually been demonstrated. No contract below authorizes real credentials, provider calls, or production use.

The 9 October [mechanism milestone](adr/0018-protected-mechanism-development.md)
adds actual [TLS records](tls-transport.md), [bounded encrypted import](protected-entry.md)
and a [separate recipient process](recipient-process.md) using fixed canaries.
The existing core remains the delivery authority: the process handoff follows
durable reservation, correlated receipts determine the closed result, and
uncertainty retains the consumed use. Certificate enrollment chooses protocol
role before application parsing; it does not replace signed actor proofs or
genuine human approval. The standalone input/import drill is not connected to
an operational vault. Same-UID process separation and fixture identities do not
meet the protected-deployment contract.

Protected agent-blind application delivery is required but not yet implemented or verified. The operation objects and lifecycle below describe the current synthetic core. The separate [application-delivery contract](application-delivery.md) proposes typed reference-only proposal, approval, delivery, status and revocation workflows; it introduces no current wire methods.

## Authority objects

| Object | Meaning | Binding rule |
| --- | --- | --- |
| Credential record | Immutable administrative ID and exact version of opaque material | A grant never silently follows `latest` |
| Operation profile | Reviewed adapter, resource, inputs, output contract, and limits | Revision changes require rejection or new approval |
| Grant | Bounded authority for a broker-bound principal/session and profile | Authority is not inferred from an agent label |
| Prepared request | Resolved concrete operation and exact bindings at one policy generation | Its ID is a lookup handle, not bearer authority |
| Run | One dispatch decision and its outcome | Status lookup enforces the same principal/session scope |

A session pins the profile revision, resource, implementation contract, credential ID/version, output contract, and protected policy generation. Prepare also pins canonical concrete parameters and expiry. Dispatch revalidates these bindings against current broker state. A different revision, account, resource, output shape, or expired request must not inherit an old approval.

Exact versions are the initial default. A future rotation alias must demonstrate equivalent resource and authority bindings or require reapproval. An opaque token cannot prove its issuer permissions by inspecting its bytes.

## Human and agent channels

The trusted control capability creates the synthetic frozen authority, reviews a resolved request, approves it, revokes the grant, and stops the session. The foreground CLI implements terminal `inspect ID`, `approve ID`, `cancel ID`, `revoke`, and `stop`; `approve_reviewed` compares the cached canonical plan, prepared handle, broker instance, and remaining uses in the same critical section that approves. The lower-level embedding `approve` capability does not attest to a displayed review. The agent client can discover, prepare, request approval, invoke, cancel a request before dispatch, and inspect scoped status. Scope denial returns an error rather than a retained `denied` lifecycle state.

The implemented agent-facing contract has no raw-secret read, generic execution, arbitrary HTTP/URL route, recipient change, export, or human approval method. Planned delivery may name only enrolled recipient/slot references under policy; it cannot change a recipient's protected enrollment or return plaintext. Unknown fields such as `approved=true` must not become authority. Client-provided identity strings are display data only.

An agent approval request creates or refers to bounded pending state. It does not approve the request or attest to human presence. The current JSON-lines fixture leaves the request `awaiting_approval` and invocation returns `approval_required`; it has no private control connection. An integrated broker must return `interaction_required` where no supported human interaction is available. Neither path may prompt for passwords or ask for credentials in chat.

The synthetic demo uses a trusted Rust embedding control handle. The foreground CLI separates terminal control from an agent-only Unix socket, requiring terminal stdin by default; `--synthetic-control-pipe` is an explicit test facility. EOF invalidates the session. Both approaches demonstrate agent API separation, without proof that a human acted or that same-user automation cannot reach an administrative interface.

## Discovery and resolved planning

Any discovery sourced from a public catalog is explicitly unverified. It may advertise names/input shapes, but cannot certify authorization, current credential context, or authoritative scope.

The approval display must use the broker-resolved plan. Display security-relevant fields independently from agent-written rationale: requesting host/session, operation/resource, concrete inputs or permitted range, credential label/account context, effects, result categories, expiry/use limits, and enforcement mode. Escape control characters and misleading rich-text content. A cached agent preview is not consent.

The synthetic fixture has broker-owned policy rather than a public storage catalog. The foreground `inspect` display renders the resolved synthetic operation/resource/input, profile revision, credential version, output contract, policy generation, expiry, remaining uses, effects/result categories, session limits, and workflow mode. No locked-vault discovery or account-aware real-provider approval UI is implemented.

## Request lifecycle

```mermaid
stateDiagram-v2
    [*] --> Prepared
    Prepared --> AwaitingApproval: request approval
    Prepared --> Approved: bounded session grant
    AwaitingApproval --> Approved: trusted control approves exact plan
    Prepared --> Canceled: cancel before dispatch
    AwaitingApproval --> Canceled: cancel before dispatch
    Approved --> Reserved: atomic scope / expiry / budget decision
    Reserved --> Dispatched: commit dispatch decision
    Dispatched --> Succeeded: validated authorized result
    Dispatched --> Failed: reviewed known failure
    Dispatched --> OutcomeUnknown: acceptance cannot be established
```

The diagram specifies the logical lifecycle; implementations combine `Reserved` and `Dispatched` inside one serialized transition. Scope denial, cancellation, expiry, and stop before dispatch prevent a new dispatch. The prepared-request deadline applies only before dispatch. Approval, cancellation, expiry checks, and retries cannot overwrite dispatched or terminal states. The already accepted invocation may return its validated completion after revocation or session expiry; it cannot refresh an expired session. Later result lookup/replay requires a valid session and retention limit. A missing record is not proof that a prior external effect did not happen.

## Atomic use reservation and revoke

Inside one broker-owned critical section:

1. Check principal/session, session lifetime, grant state, request state, exact bindings, input scope, and remaining uses.
2. Resolve an existing run for a retry, or reserve one remaining use exactly once.
3. Bind the run to the prepared request and commit the dispatch decision.

Grant revocation commits in the same synchronization domain. After revoke wins that serialization point, new dispatch reservations fail. If dispatch wins first, that operation may complete. Revocation is not a promise to retract a provider action or previously delivered plaintext.

Two concurrent distinct requests racing for one final use must produce at most one reservation and one dispatch. Two invocations of the same prepared request must refer to one run, not independently reserve two uses. Provider execution occurs after the decision, outside the state lock.

Session-local counters are not durable global budgets. Restart requires a new control authorization; an old grant or run ID cannot resume authority implicitly. A random per-broker epoch greeting makes an existing socket bridge reject a restarted broker rather than follow reused numeric handles. All current socket clients share one broker-bound principal/session. A persistence design must reserve durably before an effect and identify crash/rollback semantics before advertising cross-restart limits.

## Idempotency and unknown outcomes

The deduplication key is broker-bound principal/session plus caller request ID. Compare canonical typed parameters and exact resolved bindings, rather than hashing arbitrary JSON text and treating formatting as policy.

| Situation | Required behavior |
| --- | --- |
| Same ID, same prepared inputs/bindings | Return existing prepared/run state or result |
| Same ID, different canonical inputs | `request_id_conflict`; no new dispatch |
| Invocation while the same run is dispatched | Return in-progress state; do not dispatch again |
| Retry after success | Return the stored validated result; do not repeat the effect |
| Known failure after reservation | Preserve the run and consumed reservation unless a separately specified safe refund rule exists |
| Provider acceptance uncertain, panic, or lost receipt | Preserve consumed authority; `outcome_unknown`; no blind repeat |
| Broker restart | Old session authority invalid; no implicit resumption |

Exactly-once local reservation is different from exactly-once provider effects. A later write adapter requires provider idempotency or explicit reconciliation. An unknown result must not be converted into `provider_unavailable` followed by a transparent retry. Human reconciliation may be necessary even after local restart.

## Session and time semantics

The current synthetic setup enforces a default 600-second idle and 1,800-second maximum session; trusted setup can impose shorter limits. Tests use an injected clock. The foreground loop checks validity as well as its maximum duration. These process-local limits do not establish platform suspend/lock guarantees.

Use a broker-owned clock abstraction for deterministic expiry tests and a monotonic production time source for process-local duration. Only a successful authorized activity may refresh idle time. Denials, approval requests, discovery, and status polling must not extend authority. Absolute maximum lifetime never extends.

Invalidate the session when lifecycle state becomes untrustworthy. Suspension, screen lock, clock behavior, logout, and headless interaction require platform tests before supported behavior is promised. No auto-start, reboot unlock, or background service is part of this foundation.

## Inputs and outputs

Start with one fixed fake status operation whose inputs select a bounded issue/resource. The adapter supplies the endpoint/authentication/route in later network implementations. In this operation schema, an agent cannot provide an auth header, raw URL, route template, secret reference, or process command through a convenience field. The distinct planned delivery proposal accepts exact secret references only through its own reviewed schema and resolves them to enrolled protected recipients; it is not a general credential selector or export route.

Return a typed, bounded projection such as numeric issue ID and enumerated state. Validate the provider response before release. Wrong ID/resource, unexpected status enum, oversize content, malformed schema, or unsupported output version produces a reviewed error. No raw response, headers, native exception, or arbitrary provider content is returned by default.

Output contracts are information-release decisions. They are not a general-purpose secret detector. A future text-returning operation needs its own data-access grant and explicit treatment of provider/user text as untrusted. Generic redaction is not the security mechanism.

## Bounds

Every shipped interaction needs concrete tested limits on request bytes, identifier lengths, parameter values, pending requests, retained results, approval prompts, concurrent dispatches, response bytes, and execution duration. Current synthetic limits include 64-byte ASCII identifiers, at most 128 retained requests, at most four concurrent dispatches, at most 1,000 granted uses, at most 600-second idle/1,800-second maximum sessions, and at most 15-second prepared-request lifetime. The protocol allows 16 KiB frames including the mandatory LF and 256 frames per connection. Unix transport permits eight active connections, a one-second absolute deadline to receive each frame, and a one-second write-syscall timeout; the bridge uses two-second greeting/response read deadlines. Socket paths are limited to 100 bytes before creation; terminal control permits 128 commands of at most 256 bytes. The current code's constants and tests are authoritative; future vault limits and actual execution deadlines are not established by these bounds.

The design's 16 MiB snapshot and 64 KiB secret limits are measurement candidates. They must be evaluated against allocation behavior, parser nesting, age header/work-factor limits, and target memory before becoming storage promises.

## Stable non-sensitive errors

| Code or category | Agent action |
| --- | --- |
| `approval_required` / `interaction_required` | Pause; let the supported trusted control flow act; never supply credentials |
| `scope_denied` / `principal_mismatch` | Stop this request; ask the human for a separately reviewed grant if needed |
| `request_expired` / session expiry | Prepare a new request only within newly valid authority |
| `budget_exhausted` / revoked grant | Stop; a retry does not create new authority |
| `request_id_conflict` | Fix caller bookkeeping; do not reuse an ID for changed inputs |
| stale exact binding | Reprepare and obtain new approval; do not substitute a newer credential |
| reviewed provider/output failure | Inspect scoped state; do not print raw provider content |
| `outcome_unknown` | Reconcile through the trusted workflow; do not blindly repeat |
| malformed/oversize/unsupported protocol | Correct the request using the documented version and limits |

Exact wire codes are experimental; see the tested protocol types for the current set. Error text is not a transport for credentials, full requests, or provider bodies.

## Persistent-secret gate

Protected application delivery additionally requires independently authenticated human authority and a tested OS access boundary, immutable recipient/build/dependency/configuration/destination/endpoint bindings, protected durable reservation and handoff reconciliation, and the full synthetic adversarial gates. A token delivered to a recipient is plaintext disclosure to that trusted application; removing the broker grant does not erase it. Delivery budgets cannot count later recipient/provider calls without separate enforcement. See [the proposed delivery contract](application-delivery.md) for the unimplemented lifecycle and revocation limits.

Planned operational persistent setup transitions `uninitialized -> pending_recovery -> ready`. Only a fresh process restoring the saved snapshot with independently saved recovery material may satisfy the recovery gate. The generating process decrypting its own canary with a retained key is insufficient. The optional [synthetic age spike](storage-spike.md) demonstrates fresh-process fixed-fixture recovery, but does not set any operational state to `ready` or satisfy the real-secret gate.

Restore must use a new destination, validate schema/vault identity, and disable imported grants/sessions. Changing a recovery recipient invalidates earlier verification. Real-secret persistence remains unavailable until the recovery, custody, transaction, and platform gates are demonstrated. A synthetic demo cannot report production readiness.

## GitHub synthetic adapter experiment

The [GitHub preparation contract](github-app.md) covers a separate private fixed-fixture adapter. It models immutable personal installation/signer/repository bindings, metadata-only token narrowing, closed metadata output, expiry/refresh and unknown/revocation outcomes. It adds no operation, profile, approval capability or wire method to the core contracts above. Its simulated approval is not a human grant, its token envelope is not a live HTTP parser, and real minting remains blocked on custody, isolated deployment, independent approval, durable intent and versioned broker integration.

The later [synthetic intent journal](github-intent-journal.md) retains GitHub mock reservation/effect evidence across process exit. This is not persistence for the core broker above: existing journals can only be inspected, with zero grants/sessions restored and no automatic retry/refund. Full-file/schema/state-machine validation rejects malformed histories; internally valid rollback remains outside the trusted-storage prototype.

## Versioned GitHub core operation

The later [core integration contract](github-broker.md) adds a closed synthetic metadata operation through the same broker state machine. Legacy v1 types/wire remain issue-specific; their handle methods reject GitHub before mutation. V2 requires a canonical reviewed control decision, records actual core authority/budget in schema-2 synthetic journals and produces only a typed metadata projection. Reservation/persistence uncertainty never refunds authority. A same-session/handle static GitHub unknown receipt remains readable after session invalidation; other result lookups retain normal session checks, and legacy behavior is unchanged. No live key/provider, real human-authentication or protected durable-authority claim is added.

## Optional synthetic sign-only source

The private key-source/lease interfaces in `signing-spike` are separate from broker authority. Exact key label/version/issuer/algorithm, instance generation, logical lock/revoke/owner lifetime, monotonic lease limits and a signing-attempt cap are checked at the signing serialization point. The public no-input example returns only safe evidence, never a key or signed JWT. The unsupported protected source always refuses. Only the explicit optional signed-synthetic constructor obtains a one-shot permit after durable core reservation; no default operation or agent method obtains general signing authority. [The signing contract](signing-spike.md) defines fixed claims, strict verification, native dependency costs and memory/host limits. The [composition contract](github-signed-composition.md) binds the source to the actual approved credential revision and preserves reservation/unknown-outcome rules.

## Planned application ACL contract

[ADR 0013](adr/0013-vendor-neutral-authentication-and-acl.md) places authenticated application identity before the broker's policy decision for a future network API. Its [exact ACL contract](access-control.md#exact-deny-by-default-acl-contract) binds principal/enrollment, policy revision, action/effect, secret version, explicit recipient/executor target, provider/resource, verified context and expiry/use bounds. Missing or unverified data denies; independent human approval and tighter broker limits still apply. Administrative policy is never taken from request fields or transport membership. API-authentication credentials and operational secret versions remain distinct. Current trusted synthetic setup deliberately creates a fixed grant; no configurable ACL loader, remote verifier or default-deny multi-principal service is claimed.

## Optional authenticated synthetic delivery

[The vault increment](vault-delivery-spike.md) implements the closed `synthetic.vault.deliver.v1` operation only with `vault-spike` on Unix. It reuses this core, with exact secret/recipient/resource/generation bindings, a cryptographically verified opaque client capability, and separate proof hooks inside approval and before use consumption. Proof/ACL denial consumes no use; a durably reserved handoff never receives an automatic refund/retry. Safe delivery status has no raw value/capsule/acknowledgement. The public constructors remain fixed-canary creation/inspection. [Separate typed connection handlers](vault-protocol.md) now support authenticated agent/admin messages, with admin session revalidation in mutation hooks. Real entry, protected connector/network transport, multi-principal deployment and genuine human presence are not implemented.
