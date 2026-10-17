# Separate agent and administrator protocol handlers

The optional Unix `vault-spike` feature now exposes reusable, transport-neutral `AgentEndpoint` and `AdminEndpoint` handlers in `aegis::vault::protocol`. They parse bounded JSON into closed operation types and use the main broker's authorization/reservation machinery. There is **no HTTP/TLS listener, remote session service, operational enrollment or secret-entry route**. `SyntheticProtocol::create/open` assemble only the existing fixed-canary fixture, and live deployment remains refused.

## Ownership and connection binding

Runtime storage receives its storage-decryption and journal/capsule-signing material, the recipient public encryption key, and its public receipt verifier. The recipient receives its own decryption/receipt keys and the broker public verifier. Authentication gates receive only agent/admin public verifiers. Neither runtime role retains the agent/admin private proof signers; the broker does not retain recipient private material, and the recipient does not retain broker storage/signing keys. A regression drops both simulated actor signers before invocation and verifies the already-issued assertion still validates, while weak references show the runtime did not retain those signers.

This is Rust ownership separation inside a trusted process, not host isolation. The trusted fixture constructor briefly loads an all-role dummy kit and still leaves that kit on the same filesystem. Its existence, the host's privileges and possible allocator/native copies remain outside the confidentiality claim. A production constructor must enroll public identities and load role-specific protected custody independently; it must never promote this fixture kit.

Each endpoint object represents **one private connection/capability**, with its own bound session. Treat it as a connection handler, not a stateless global HTTP handler shared by unrelated callers. Do not let an agent select or obtain an administrator's already-authenticated endpoint. A future transport must own peer/channel binding and confidentiality, create the correct connection objects, and enforce independent agent/admin routing. A client-supplied plane, name, IP address or forwarded header is not authentication. The current factory supports one fixed agent and one fixed administrator session, not general multi-principal enrollment or session renewal.

## Versioned messages

Each frame contains exactly `protocol`, `version` and `action`. The protocol family is `aegis.synthetic.vault.v1`, version is `1`, and `action` has exactly `method` and `params`. This separate family does not change the legacy issue-status V1 or operation/MCP V2 protocols. Unknown fields, duplicate struct fields, unexpected methods/types and oversized frames are rejected with fixed errors before dispatch. Frames are at most 16 KiB; each endpoint processes at most 256 attempts, including invalid input. Pending challenges/proofs remain bounded independently.

| Agent methods | Required authority |
| --- | --- |
| `connect_challenge`, `connect` | One-use purpose/audience-bound proof by the enrolled agent; no policy/effect access from a claimed identity |
| `discover_operations`, `prepare_operation`, `request_approval`, `get_run_status`, `cancel` | This endpoint's exact authenticated client capability plus the core's current policy/ACL checks |
| `invocation_challenge`, `invoke_approved` | Authenticated client; execution additionally requires exact independent approval and a fresh agent invocation assertion at reservation |

| Administrator methods | Required authority |
| --- | --- |
| `connect_challenge`, `connect` | A distinct administrator connection purpose and enrolled admin verifier |
| `inspect_review`, `approval_challenge` | This endpoint's exact authenticated admin capability; challenge requires the unchanged canonical review |
| `approve` | Exact submitted review, one-use admin approval assertion, and admin session rechecked inside the core mutation hook |
| `revoke_challenge`, `revoke` | Authenticated admin capability; revocation assertion/session checked before the durable revocation guard and core transition |

Authentication assertions are supplied by the caller that owns the corresponding identity key. The handlers return no assertion, private key, capsule or credential value. There is no generic signing, decryption, export, URL/proxy or command method. Input assertion buffers have no `Debug`/response serialization implementation and selected owned buffers zeroize on drop; this is not a guarantee about every allocator/parser/native copy.

These frames are a host-to-broker wire contract, not a model-visible tool schema. In a supported deployment, the enrolled connector holds its authentication key outside the agent's readable tools and injects the request-bound proof without placing it in a model prompt, normal log or tool result. The model-facing adapter would accept only bounded operation inputs and opaque references. That protected connector and its enrollment remain unimplemented; this module does not change the existing MCP tool schema.

`ProofChallenge` contains the server nonce, fresh broker epoch, purpose, exact digest, issue/expiry times, elapsed bounds and enrollment/ACL revisions. Claims use the fixed strict RS256 profile from the integrated vault contract. Agent issuer/subject is `synthetic-vault-agent` and audience is `urn:aegis:synthetic:agent:v1`; admin issuer/subject is `synthetic-vault-admin` and audience is `urn:aegis:synthetic:human-control:v1`. The admin connect purpose differs from agent connect. Key possession alone does not attest a human action.

`ReviewPlan` is the complete typed approval view, including exact secret/recipient/configuration/repository binding, request/session/epoch, policy revision, expiry and limits. The trusted UI must display and retain the exact plan, verify its challenge digest and sign that plan only after an explicit user action. Rust callers can use `ReviewPlan::digest`; it hashes the versioned typed serialization, not arbitrary caller JSON bytes or a universal JSON canonicalization format. A non-Rust client requires matching serialization vectors before support. The current test actors simulate this flow; an independent UI/signing provider is not implemented.

Responses are a closed tagged enum: challenge, connected, catalog, safe run status, review or revoked. Responses always identify the synthetic protocol. Original raw errors/assertions are not reflected. Terminal or unknown receipts still require the connection's valid authenticated capability, and a fresh endpoint/cold start cannot inherit another connection's identity.

## Lifecycle and evidence

The protocol shares the existing durable guard, journal, recipient and budget rules. It does not create another policy engine. A cold start requires new proofs for both roles and a new exact approval; old challenges/epochs are unusable. A consumed or uncertain operation cannot be repeated/refunded. An already-reserved operation can complete when authentication expires or revocation starts; the result is preserved and subsequent authority is denied. The injected clock remains a synthetic fixture dependency; callers cannot choose it through a request. Production trusted time, fencing and an external generation anchor remain gates.

Tests cover the complete serialized agent/admin delivery and rotation path, cold authentication, revoke, exact plan/proof substitution, wrong-role proofs, stale epochs, endpoint/session scope, empty ACL, malformed/oversized requests, frame limits, concurrent duplicate invocation and safe retained uncertainty. These are in-process protocol/library tests. They do not exercise a network stack, separate OS identities, a real agent tool's access boundary or independent human presence. Platform results and the incomplete independent-review gate remain in [verification](verification.md).
