# Vendor-neutral application access control

**Accepted architecture direction, 2026-10-07; operational remote authentication, HTTP listeners and configurable production ACL enforcement are not implemented.** The default design for a future network API is authenticated application identity followed by deny-by-default authorization. Operators may add private networking in their own environment. Aegis must not require Fly, WireGuard, Tailscale or another hosting/network vendor to decide who may act.

Current Unix/JSON-lines/MCP functionality remains synthetic. A trusted constructor deliberately creates one fixed grant and bound principal/session; this is not a deployed multi-principal ACL service. The current program has no HTTP listener, TLS configuration, remote enrollment endpoint or network-authentication bootstrap. Four [acceptance regressions](../tests/access_contract.rs) exercise existing typed protocol/core boundaries; the deployment acceptance matrix below remains future work.

The later [integrated vault fixture](vault-delivery-spike.md) adds actual signed-assertion verification, opaque bound client capabilities and exact ACL evaluation for one fixed synthetic principal/session. It is not a remote authenticator, production bootstrap or independently protected human channel, and it changes none of the deployment gates below.

The subsequent [vault connection handlers](vault-protocol.md) expose separate bounded agent/admin wire paths over those checks, with role-specific runtime key ownership. Each handler represents one private connection; reusing an authenticated object for unrelated peers would defeat its binding. Actual network/channel authentication, protected connector enrollment and human presence remain deployment/code gates.

## Separate reachability, identity and authority

A network route answers whether a client can reach the API. Authentication establishes an enrolled application principal. Authorization decides whether that principal may perform this exact action in its current context. Independent human control approves the permitted delegation or operation. Neither private-network membership nor a successful authentication creates a grant, proves human presence or permits secret export.

The broker and agent may run on different machines. A remote agent can use the authenticated API over ordinary TLS without a private overlay. Its actual tools must still be unable to administer or read the secret-bearing broker/recipient host; exposing only the API can be part of that verified boundary. Application ACLs cannot repair unrestricted agent shell/admin access to the machine holding the keys.

The intended request path is:

1. Verify the selected transport protection and authenticate the caller using an enrolled credential and supported verifier.
2. Bind a stable principal from the trusted issuer and immutable subject/enrollment, credential version, audience and relevant assurance. Display names, email labels, request fields and IP addresses cannot select that identity.
3. Resolve the closed operation or delivery proposal from protected server-side enrollment. Validate input and exact resource/recipient/credential revisions; treat caller-supplied context as untrusted until resolved.
4. Evaluate the current ACL and existing broker grant/approval together. Revalidate at reservation under the same policy/revocation/budget serialization point before resolving a secret or creating an effect.
5. Return only the permitted bounded projection or safe status. Authenticate and scope discovery, polling, cancellation and retained outcomes too; knowing a handle or request ID is never authority.

Missing/invalid/expired/revoked authentication, unavailable verification or required revocation state, unsupported transport protection, missing context or no matching grant must fail closed. Errors must not disclose secret existence, credential values or raw verification exceptions. The narrow existing same-bound-client unknown receipt releases only static uncertainty, not a result or renewed authority; a future remote implementation still authenticates that client before lookup.

This separates application authorization from network location, consistent with [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final). The specific Aegis rules below are design decisions, not a claim of conformance or implemented zero-trust deployment.

## Exact, deny-by-default ACL contract

An ACL is protected administrative policy, not a request-supplied `acl_allowed` field. Empty, missing, invalid, unavailable or unsupported policy denies access. The first implementation should use closed, exact allow entries with explicit revocation/deny precedence; no implicit wildcard, string-prefix match, role-name inference or merge of partial matches from different entries. A matching allow rule defines the ceiling; it does not bypass required human approval or the broker's tighter session/request limits.

| Binding | Required decision data |
| --- | --- |
| Agent identity | Trusted issuer plus subject/enrollment mapped to the stable broker principal; credential/assurance requirements and active enrollment revision |
| Policy authority | Exact ACL/rule revision, broker instance/session, policy generation, human-approved delegation/review reference and revocation state |
| Action and effect | Closed operation/delivery kind, adapter/output contract revisions and allowed read/write/configuration effect |
| Operational secret | Exact opaque secret binding and version resolved by the protected profile; no raw value, caller-selected path or arbitrary secret lookup |
| Recipient | Explicit broker-internal executor target for operations, or exact enrolled recipient/instance, protected build/configuration revision and destination slot for delivery; absence never means “any recipient” |
| Provider/resource | Exact provider/account/installation and repository/resource IDs; validated typed parameters and requested permissions within the approved ceiling |
| Context | Server-bound principal/session, request/approval ID, deployment mode and required verified device/workload/recipient assurance; missing required context denies |
| Bounds | Server-owned not-before/expiry, idle/maximum lifetime, request deadline, remaining uses, concurrency and request capacity; authenticated request labels cannot extend them |

For GitHub, the first profile remains NathanaelG1's selected personal repositories, no organizations, with explicit operation-level permission narrowing. Application authentication to Aegis is separate from GitHub App authentication. A principal authorized to invoke metadata cannot use that fact to obtain a token, run Git, choose another installation/repository, deliver to a different application or modify ACLs.

The canonical human review must show the resolved action/resource/recipient/secret revision and limits, including the relevant ACL revision. Policy, enrollment, recipient, operational-secret or review changes invalidate stale authority and require re-evaluation/reapproval. Authentication-credential rotation/revocation is a separate dimension from the GitHub/private operational-secret version; one cannot silently substitute for the other.

At reservation, every applicable binding and bound must hold in one decision. Consumption and revocation are serialized with existing broker invariants. Revocation denies future reservations; already dispatched work may finish, and previously delivered plaintext/provider credentials cannot be recalled by changing an ACL. Unknown outcomes consume authority and cannot trigger automatic retry/refund. Future persistent ACLs/budgets require protected authenticated state and rollback-aware recovery; the current synthetic journal does not supply those properties.

## Authentication and bootstrap without a vendor dependency

Use a small authentication boundary that produces a server-owned authenticated principal, not a general plugin that executes agent-controlled code. Implement one reviewed mechanism first; optional mechanisms can share the same principal/ACL contract without making any hosted provider mandatory. Suitable standards-based deployment choices include:

- Mutual TLS with an operator-managed trust anchor, verified client certificate/key possession and an explicit certificate-to-enrollment mapping.
- Short-lived audience-restricted OAuth access credentials from an explicitly configured issuer, with maintained signature/token validation and sender constraint where supported. Validate issuer, audience, algorithm/key selection, expiry and required revocation/freshness; a decoded claim or ID-token-shaped string is insufficient.
- An enrolled local workload/OS identity carried over a protected local channel, when that deployment demonstrates the necessary peer and process isolation. Current same-UID Unix checks do not by themselves establish this stronger mode.

These are supported **design options**, not working adapters. Authentication credentials identify a client to Aegis; operational credentials authorize Aegis or an enrolled recipient to a downstream provider. Keep both categories out of model prompts, normal results and agent-readable environment/argv/files. The intended agent calls through a protected enrolled host/connector that holds its own authentication material; placing a shared API key in an unrestricted agent shell would not satisfy that custody boundary. No new credential is generated, stored or configured by this increment.

Bootstrap starts closed. An independently authenticated operator establishes the broker identity, trust anchors/issuers, initial administrator and agent/recipient enrollment through a protected administrative flow. The first network caller, a loopback address, a request body, an existing network membership or an MCP client name cannot become the owner. Enrollment, credential issuance/import, rotation, trust-anchor changes and recovery need explicit protected administration and auditable revision changes. Lost trust/configuration must not trigger anonymous fallback or automatic re-enrollment.

The separate human administrative plane owns ACLs, enrollment, secret provisioning and canonical approval. Agent credentials are not administrative credentials and cannot be exchanged for human authority. Use distinct credential audiences/roles and separately protected control routes, preferably a separately bound control endpoint; network co-location cannot collapse this separation. A future browser control flow also needs origin/CSRF/session protections and evidence of actual human action. The existing same-account terminal flow remains a test workflow. OAuth implementations must follow maintained security guidance, including token privilege restriction and protected proxy deployments in [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).

## Transport and optional private-network deployment

The future listener configuration must state the binding address/interface, address family, public/private intent, TLS termination and any trusted proxy identities/header contract. Default operation stays local/closed unless an operator explicitly enables a network listener. Remote transport requires TLS with server authentication, either directly in Aegis or through a specifically enrolled secure reverse proxy with a protected backend hop. Private addresses, loopback and an encrypted overlay are not automatic exemptions from application authentication or the selected transport-security contract.

Private-network support means operators can bind a future listener to their existing private interface/address and choose their own routing, firewall, VPN/overlay or local infrastructure. Aegis should not provision that network or require its membership service. There is no private-network setup “out of the box” to claim today because the HTTP/TLS listener is absent. Once implemented, the same authenticated API/ACL behavior must work whether the operator uses private routing or an explicitly approved public TLS endpoint.

For a declared private-only deployment, startup and deployment verification must confirm the actual IPv4/IPv6 listeners and exposed paths. Reject wildcard/public binds, missing/down interfaces or fallback to a broader address; do not silently publish a private listener. Inspect reverse proxies, load balancers, container port publishing, NAT/firewall rules and public DNS/routes as applicable, and test from outside the intended network. A private IP string alone cannot prove no public exposure through forwarding. If exposure cannot be verified, report the mode as unsupported/unverified and do not advertise a private-only guarantee.

An optional network IP allowlist can reduce reachability, but it never establishes a principal or replaces the ACL/human decision. Derive any address condition from a verified connection/proxy chain, not a supplied header. A peer accepted by that allowlist may still have no application grant; a valid application credential may still be denied by a configured network admission rule.

### Reverse proxy trust

By default, no forwarded identity headers are authoritative. `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto`, claimed user/certificate headers and generic `trusted_proxy=true` values cannot authenticate a caller. Forwarding metadata has explicit integrity limitations in [RFC 7239, section 8.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-8.1).

A proxy deployment must explicitly enroll the proxy, authenticate/secure its backend hop and prevent direct untrusted access to the backend. A protected Unix socket with verified peer/isolation or mutually authenticated TLS is an option to validate; an unprotected loopback TCP port is insufficient against an unrestricted same-host process. The proxy strips inbound identity headers, authenticates the external client and writes only its configured canonical assertion; Aegis accepts only the exact assertion contract from the authenticated enrolled proxy, with subject/issuer/audience/freshness constraints. Proxy identity and forwarded end-user/workload identity remain distinct. Ambiguous, duplicate or conflicting identity assertions and unsupported proxy chains fail closed.

Never trust all proxies, all private subnets or a client-controlled `Host`/scheme/header to select authority or bypass TLS. A new trusted proxy or header mapping is a security-critical configuration change, not a convenience toggle. Client-IP forwarding and identity delegation need separate treatment; neither grants human administrative presence.

## Acceptance matrix and current evidence

| Scenario | Required outcome | Evidence status |
| --- | --- | --- |
| Claimed principal/admin, IP/private-network or proxy identity in request fields | Reject before allocation/effect; no lifecycle or budget change | New current V1/V2 typed-wire regression; not an HTTP-header test |
| MCP display identity claims admin/network ownership | Canonical review retains host-bound principal; human approval still required | New current MCP/core regression; no remote authentication established |
| Claimed ACL/human approval or administrative/secret-export/proxy method | Reject; pending request and budget unchanged | New current typed-wire regression |
| Changed principal, secret version, resource, session/revision, expiry/use limits or another instance's review | Deny review; revocation denies subsequent dispatch | New current typed-review/core regression, supplementing existing policy suites |
| Unknown/expired/revoked credential, wrong issuer/audience/key/algorithm or verifier unavailable | No authenticated principal, ACL lookup, secret resolution or provider dispatch | Required future authentication-adapter tests |
| Empty/missing ACL, no exact match, partial matches across entries, explicit deny or missing context | Deny without scope union or network-membership override | Required future configured-ACL tests; no ACL loader/evaluator claimed |
| Agent credential reaches admin/approval/bootstrap or reuses another subject's handle | Deny; no administrative mutation or result disclosure | Existing agent-method separation; future remote/admin and multi-principal tests required |
| ACL/enrollment/auth credential revoked or rotated during requests and restart | Serialized denial of new reservations; no restored/replayed authority; retain unknown effects | Existing synthetic broker race/restart tests; future auth/ACL composition required |
| Client sends forged proxy headers, bypasses proxy, uses an untrusted proxy or duplicate assertions | No identity delegation; deny unsupported route | Required future real HTTP/proxy tests |
| Private interface absent, wildcard/IPv6 public bind, port publishing or unexpected public route | Fail deployment/private-mode verification; no silent broadening | Required future listener/deployment tests |
| Valid private-network member lacks an application grant; authorized caller changes network vendor | First request denied; application identity/ACL semantics independent of vendor | Required future deployment matrix; no network is configured here |

The real HTTP/TLS, authentication bootstrap, proxy, ACL-loading, administrative and private-exposure gates must be independently reviewed on a named supported deployment before live keys. The current cloud's 14 Unix-listener `EPERM` failures remain explicit unverified coverage. This architecture does not remove the [same-UID custody/isolation boundary](application-delivery.md) or the remaining [readiness gates](readiness-checklist.md).
