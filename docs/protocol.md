# Experimental agent protocol v1

The JSON-lines fixture and Unix agent endpoint adapt the same broker API used by the demo. They have no independent policy engine, secret input, or human control command. The MCP adapter maps its six tools onto this protocol; JSON-lines envelopes themselves are not MCP messages. Public type/schema evolution is experimental until a compatibility policy is frozen.

## Framing and bounds

Each UTF-8 JSON request occupies one line. The envelope accepts only `version` and `action`. Version is exactly `1`; any other version yields `unsupported_version`. Unknown fields, invalid enum variants, invalid identifiers, wrong types, malformed JSON, and oversize requests yield a stable non-sensitive error.

Each frame requires a final LF, which counts toward the 16 KiB limit. An oversized frame or an incomplete frame at EOF returns a stable error and closes without executing it. The reader never uses unbounded `read_line` allocation. It processes at most 256 request frames per connection and then ends with a capacity error.

Responses have three fields:

```json
{"version":1,"result":null,"error":"approval_required"}
```

A successful response carries a typed operation/discovery/run view inside `result` and `error: null`. Parse the structured code, not error prose. No raw provider exception/body/header belongs in an error.

## Methods

| Method | Parameters | Result |
| --- | --- | --- |
| `discover_operations` | No `params` member | Unverified operation descriptor |
| `prepare_operation` | `request_id`, `profile_id`, `parameters` | Prepared run view/handle |
| `request_approval` | `prepared_request_id` | Existing view moved to awaiting approval when appropriate |
| `invoke_approved` | `prepared_request_id` | Existing or newly dispatched run view; requires broker authority |
| `get_run_status` | `prepared_request_id` | Scoped state/result |
| `cancel` | `prepared_request_id` | Canceled before dispatch, or existing state afterward |

`request_id` and `profile_id` contain 1–64 ASCII letters/digits, `-`, or `_`. The synthetic profile is `issue-status`. Parameters are `repository_id` (nonzero `u64`) and `issue_number` (nonzero `u32`). The frozen synthetic resource is repository `4242`; another repository is `scope_denied` before dispatch.

For example:

```json
{"version":1,"action":{"method":"prepare_operation","params":{"request_id":"agent-1","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}}}
```

Request deduplication uses the broker-bound session and caller ID. A repeated ID with identical typed input finds the existing request; changed parameters/profile produce `request_id_conflict`. The `prepared_request_id` is a local numeric lookup handle, not a bearer credential. A fresh broker has fresh in-memory state; copying a handle does not restore prior authority.

## Run view and result

The run view contains `prepared_request_id`, `state`, optional `result`, and optional `error`. The current public lifecycle vocabulary is:

```text
prepared, awaiting_approval, approved, reserved, dispatched,
succeeded, failed, outcome_unknown, canceled, expired
```

Reservation and dispatch occur in one serialized decision, so callers should not depend on observing the intermediate `reserved` state. Scope denial is an error, not a `denied` run state.

The approved status projection contains only `repository_id`, `issue_number`, and `state` (`open` or `closed`). The fake provider returns open for odd issue numbers and closed for even numbers. These synthetic states are deterministic fixture behavior; no real issue is queried.

The broker validates output IDs against dispatch and accepts only the reviewed status enumeration. Unexpected output becomes `invalid_provider_result` without exposing the raw value. An unknown effect or trusted-executor panic becomes `outcome_unknown` with no automatic retry/refund. A trusted embedding host controls its own panic hooks and debugging; see the [threat model](threat-model.md).

## Unix endpoint and broker epoch

The foreground broker creates a new `0700` directory and `agent.sock`; the directory must not already exist. Both server and bridge check the current effective UID. macOS uses `getpeereid`; Linux code uses `PeerCredentials` but remains untested. Relative paths, symlink components, and complete socket paths over 100 bytes are rejected before endpoint creation. Nonatomic path traversal does not exclude hostile same-account races.

Before operation frames, a socket connection receives a bounded greeting:

```json
{"version":1,"session_epoch":"32-hexadecimal-characters"}
```

The epoch is generated from 16 random bytes per broker. `SocketBridge` caches it and rejects a changed epoch after reconnect. It is a session continuity check, not bearer authority or server identity proof against a malicious same-account process. A socket greeting is absent from the standalone `synthetic-agent` stdin/stdout fixture.

The server permits at most eight active connections. Each frame has a one-second absolute read deadline, so partial byte progress cannot keep a slot indefinitely. Writes use a one-second syscall timeout. The bridge uses two-second greeting/response read deadlines and a one-second write timeout. These are transport timeouts; a trusted executor's actual operation deadline requires separate enforcement. All connections currently share one synthetic principal/session rather than separate per-client grants.

## MCP mapping

The stdio adapter implements MCP `2025-11-25` initialization, `ping`, fixed `tools/list`, and the six method names above through `tools/call`. It validates typed mapping before IPC while the broker remains the policy authority. There is no credential elicitation, control tool, broker startup, or key custody in the client. Notifications cannot execute a tool. MCP request IDs must be integers or strings; explicit null IDs are rejected rather than mistaken for omitted IDs. Invalid JSON returns JSON-RPC `-32700`; invalid request shapes return `-32600`. Duplicate object members, including escaped-equivalent keys at nested levels, are rejected before tool mapping.

MCP results carry a text content block containing the versioned broker response JSON and `isError` matching the broker error. Malformed/unsupported MCP messages return bounded JSON-RPC errors. The adapter shares the 16 KiB frame and 256-frame limits; it requires a fresh adapter connection after exhausting that work budget. See [agent quickstart](agent-quickstart.md) for exact JSON-RPC examples. Broader MCP-host compatibility remains untested.

## Separate human authority

The wire has no `approve`, credential, principal-selection, grant-creation, export, subprocess, or URL method. `request_approval` only creates pending state. `synthetic-agent` has no private human control connection, so the wire cannot complete that approval. Use the library/demo's trusted control flow to test approved completion.

The foreground broker maintains this split with terminal control commands `inspect ID`, `approve ID`, `cancel ID`, `revoke`, and `stop`. Approval compares the cached canonical inspection, prepared handle, broker instance, and remaining budget under the broker lock. A stale comparison cannot race with dispatch to approve an outdated review. Terminal stdin is required by default; an explicit synthetic test-pipe flag bypasses that workflow check. EOF invalidates authority. These controls do not prove that same-account automation cannot impersonate a human.

A host-readable MCP stderr stream is not the broker's control channel, and a client-supplied identity label or MCP annotation cannot create authority.

See the [agent quickstart](agent-quickstart.md) for a full request sequence and [contracts](contracts.md) for retries, expiry, and revoke semantics.

## Explicit operation protocol version 2

The legacy contract above remains version 1. [The GitHub core integration](github-broker.md#wire-version-2) adds explicitly tagged operation/result types on version 2 and an opt-in V2 MCP mapping with the same six tool names. It has no control-approval, provider-revocation or credential-input method. Duplicate/unknown fields and cross-operation shapes fail closed. Existing LF/frame limits and broker epoch checks remain; socket responses must match the requested operation-protocol version.

## Future authentication and network metadata

The current wire is not HTTP and has no credential/identity/proxy-header fields. Host-bound identity is unaffected by MCP display metadata. [Access-contract regressions](../tests/access_contract.rs) reject claimed principals, IP/private-network and proxy/ACL claims as ordinary unsupported JSON fields; this does not test actual HTTP headers or a deployed proxy. A future transport authenticates before binding the client and evaluating the [application ACL](access-control.md), including status/discovery scope. Human administration remains separate. No new method or protocol version is added.
