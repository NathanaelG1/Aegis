# GitHub App integration: synthetic preparation

**Status: fixed synthetic adapter exercise. Real GitHub credentials are still unsupported.**

Aegis's first planned integration is a GitHub App owned by **NathanaelG1**, installed only on that personal account and selected personal repositories. This checkpoint implements a private mock adapter and adversarial tests. It does not import a private key, create a valid JWT, contact GitHub, run Git or establish an OS boundary. The later [broker integration](github-broker.md) adds a fixed synthetic V2 agent operation. The built-in IDs and tokens are fictional public fixtures, not discovered account information.

```sh
cargo run --locked --offline --example github_app_spike
cargo test --locked --offline github::
```

The example accepts no configuration, credentials, paths, environment settings or live mode. It returns only a typed report: repository ID/private/archived flags, mock call counts, replay/denial results and mock revocation state. `github::live_readiness()` returns unavailable on every platform with six open gates. This is a closed availability report, not a confinement verifier, proof of human approval or an invitation to supply booleans to enable real use.

## Milestones

1. **Implemented here: synthetic provider boundary.** Validate a frozen personal installation binding; construct narrowed token requests; simulate JWT claims and exchange; retain uncertain outcomes; constrain metadata output; test expiry, refresh, revocation, duplicate calls and races.
2. **Protected deployment and human approval.** Select a named Linux/macOS/Windows deployment, prove separation from the agent's actual tools, enroll protected binaries/configuration, and authenticate human control independently. A same-UID arbitrary-shell agent is unsupported. This requires a separate deployment decision and authorization for security-sensitive changes.
3. **Key custody and durable intent.** A [fixed synthetic journal](github-intent-journal.md) now tests pre-effect persistence and refusal to resume after restart; protected operational persistence remains open. Integrate protected sign-only custody using a maintained RS256/JWT library or reviewed signing service. Implement bounded operational storage, independently held recovery and restart reconciliation before a live mint can occur. Do not turn the existing fixed-fixture age exercise into a vault by accepting arbitrary input.
4. **Broker and live read integration.** The synthetic versioned operation/profile/result integration now reuses the main broker's approval, scope, deduplication and reservation logic. Add a bounded, fixed-origin GitHub HTTP adapter with trusted enrollment evidence, TLS/destination validation and no redirects or environment proxies. Complete disposable synthetic/live-fixture review with separate authorization before actual credentials are provisioned.
5. **Protected Git worker or bounded write operations.** Enroll a trusted isolated recipient or implement narrowly typed writes; then perform the full delivery, malicious-config and crash/recovery acceptance gates. A generic credential helper is not an agent-blind integration.

Milestone 1 did not finish milestones 2–5. [ADR 0010](adr/0010-versioned-synthetic-github-broker.md) subsequently integrates the synthetic metadata operation with the main broker through explicit versioned types and a reviewed control path. The legacy operation remains synthetic issue status, with issue-specific parameters, approval display, result and wire contract. Reusing those shapes for GitHub metadata would misrepresent delegated authority. The private fixture models adapter lifecycle decisions; its standalone approval simulation is disabled in broker-owned mode, where the core is the sole authority.

## Exact bindings and authority narrowing

The private binding records App ID, client ID, installation ID, numeric account ID, literal owner login, account kind, selected repository IDs/names/owner IDs, exact signer reference/version, permission ceiling and enrollment revision. It rejects organizations, other owners, all-repository selection, empty or duplicate selections, missing IDs, invalid names/paths and unsupported permissions. At most 500 enrolled repositories are modeled. Each fixture instance selects one exact repository; a token is never reused for a different repository.

The installation ceiling allows only Contents read or write and Metadata read. This does **not** grant an operation or justify every permission on every token. The implemented metadata read narrows each mock exchange to one explicit `repository_ids` element and exactly `metadata: read`, even when the App ceiling has Contents write. No Workflows, administration, issues, user authorization/token or organization access is modeled. Empty/omitted repository or permission requests are never generated.

A future human enrollment must establish the App, installation, owner, permission and selected-repository facts from authenticated GitHub data, not agent labels, webhook payload claims alone or the shape of an opaque token. Validate installation suspension/removal, account identity and policy changes before use. The same login with another numeric account ID, transferred/renamed repository or changed credential version requires reapproval. A provider token response must confirm exact requested scope; a broader, absent or malformed scope cannot be used.

## Signer, request and output boundary

Token/JWT/request/transport types and extension traits are private and have no `Debug`, `Clone`, `Serialize` or public value accessor. The public entry point uses only built-in fixtures. This is API discipline, not protection from a trusted embedding process, debugger, same-UID shell or a modified build. Synthetic strings are not securely erased; real memory custody, crash dumps and protected processes are open gates.

The mock signer emits a plainly invalid synthetic marker. It tests client-ID issuer binding, an `iat` 60 seconds behind trusted UTC, a nine-minute future `exp`, checked arithmetic and exact signer version. **It performs no cryptography.** Actual RS256 signing must use a maintained implementation and protected key source; no home-grown signing, shell/OpenSSL subprocess or PEM input was added. The manifest and lockfile are unchanged.

The modeled exchange is `POST https://api.github.com/app/installations/{fixed-id}/access_tokens`. Metadata uses `GET https://api.github.com/repos/{fixed-owner}/{fixed-name}`; explicit provider revocation uses `DELETE https://api.github.com/installation/token`. Request policy pins the GitHub origin, API version `2026-03-10`, accept type, ten-second timeout intent, 16 KiB response ceiling, no redirects and no environment proxies. The mock checks that construction; there is no live TLS, DNS, socket deadline, decompression, HTTP-status or pagination implementation. The token envelope is a private already-decoded mock response, not a GitHub JSON/RFC3339 parser.

Metadata response parsing is byte-bounded and checks repository ID/name plus owner numeric ID/login/User type. It releases only numeric repository ID and Boolean private/archived flags. Arbitrary descriptions, URLs, headers and provider text are discarded. Duplicate known fields, malformed/nested/oversize JSON, wrong identities and wrong types fail with closed error categories. Tokens permit bounded visible ASCII up to 4,096 bytes rather than assuming GitHub's historical 40-character format; the bound needs revalidation for a live adapter.

## Expiration, replay and revocation

- Cached leases are bound to the frozen installation, signer version and one-repository metadata-only scope. Trusted UTC models GitHub claims/expiry; an independent elapsed clock bounds local reuse from exchange start, including a slow exchange with stalled UTC. Every observed timestamp is checked against the preceding observation. Either clock regressing blocks new work. These are injected test clocks, not tested host suspend/lifecycle semantics.
- Reject missing/expired/implausibly long lifetimes, tokens with at most 60 seconds remaining, invalid material and scope mismatches before any metadata call. Expiry is validated again after exchange completes and before token use. GitHub installation tokens normally expire after one hour; a local earlier cutoff does not change GitHub's TTL.
- A new approved request may refresh inside the 60-second margin. It never refreshes merely to replay a completed request or poll status. An overlapping prior token is retained for explicit provider revocation until both time models consider it expired. The exercise retains at most 32 operation records and consequently at most 32 token attempts; it never evicts a record and then treats that ID as unused.
- One reservation/flight is allowed at a time. A duplicate returns its retained outcome or in-progress state; changed canonical intent conflicts. A different concurrent request cannot cause another exchange. Each simulated approval pins the full binding and a random fixture epoch; it expires after 30 elapsed seconds before dispatch. Fixture authority ends at two hours.
- Lost mint acknowledgement, invalid receipt or unknown read prevents new request IDs from hiding a retry. A panic is retained as unknown, and a received token is retained before further fallible processing. An established unknown receipt is not overwritten by clock/session failure; exact-bound replay returns that static uncertainty without another effect. Catching a panic does not sanitize its hook or make an arbitrary adapter safe; trusted implementations must not embed secrets in panics/logging.
- Local `revoke_future` stops new reservations. A previously reserved operation may finish. It does not claim GitHub revocation or erase plaintext. Separate explicit mock provider revocation covers every known cached/overlapping/quarantined token once; an unknown acknowledgement is retained and never automatically retried. An unacknowledged mint with no known token remains `unresolved_exchange`, even if older known tokens were successfully revoked.

The original no-input demo remains volatile. The subsequent [synthetic journal experiment](github-intent-journal.md) records sync-before-effect intent and supports read-only fresh-process inspection. It restores no grants/sessions and provides no operational cross-restart budget, imported authorization or authenticated reconciliation. A real mint is a persistent-access action: deployment must durably reserve and reconcile before it can be offered. A fresh synthetic example simply creates fresh fictional fixtures; that is not a real-provider restart strategy.

## Safe Git support design

Do not put the App key or installation token in an agent's environment, command arguments, workspace, `.git/config`, credential helper, stdout or agent-controlled Git process. Git helpers return plaintext credentials and can execute shell commands. Hiding a token from model chat while an agent-controlled Git process can obtain it does not meet the product requirement.

A later trusted Git worker would receive only a typed job and approved repository/object references. It must run under the tested isolated recipient identity and have a protected Git executable/dependency closure, working storage, launch environment and canonical configuration. Constrain all of:

- System/global/local/worktree configuration, include/includeIf files, command/environment config overrides, remote/push URLs, URL rewrites and upload/receive-pack executable selection.
- Credential helpers, askpass/SSH commands, protocol/ext helpers, remote helpers, hooks, templates, filters, diff/merge/pager/editor tools, LFS, submodules and plugins. Disable unsupported paths rather than accepting agent configuration.
- Proxies, redirects, TLS options, alternate object directories, inherited file descriptors, trace/diagnostic destinations, dumps and output. Fix the approved GitHub account/repository destination and validate the real connection.
- Repository-controlled inputs including symlinks, attributes, malicious object/pack data and transfer size. Do not execute code from agent-writable repositories inside the token-bearing worker. A writable `.git` tree is security-relevant input, not merely data.
- Read versus write authority, branch/ref allowlists, expected-old-object IDs, object limits, protected-branch policy and unknown push reconciliation. No arbitrary argv or shell fallback.

The alternative is bounded broker API operations with exact repository/path/ref/object/effect contracts and typed results. Contents permission alone is not an authorization policy for arbitrary writes. Workflows remain outside scope. Neither Git approach is implemented here; a token-bearing general-purpose Git helper would violate the access objective.

## What is feasible on each platform

| Platform | Feasible without deployment changes now | Required before real custody/use |
| --- | --- | --- |
| Linux | Compile and exercise the synthetic Rust logic/Unix workflow in an ordinary cloud workspace; actual checks recorded in verification | Protected broker and recipient identities/build/configuration; denied agent file/memory/handle/debug/supervisor/container access; independent human channel; validated service manager/mount/network settings; protected journal/recovery and real adversarial tests |
| macOS | Same portable synthetic library; prior Mac checks cover the pre-GitHub checkpoint only | Protected service or actually confined agent, authenticated IPC/human channel, protected signing/key storage with tested access controls; lifecycle, code/dependency/config integrity, memory/file/handle bypass and durability tests on named versions |
| Windows | Portable fixture logic is a candidate but untested; current Unix agent transport is unavailable | Native authenticated transport; service identities/process tokens/DACLs, minimal handles and appropriate agent confinement; independent human approval; protected storage, reparse/path/race, debug, lifecycle and recovery tests |

No service, identity, permission, entitlement, firewall, container, keychain or credential-store settings were changed. A cloud computer avoids dependence on an unlocked Mac but does not itself establish protected key custody. Separate deployment authorization and evidence are needed.

## Creating the App while Aegis is being prepared

The human may register the App under NathanaelG1, choose **Only on this account**, and later install it with **Only select repositories** for the explicitly approved personal repos. For the planned Git work, use only **Contents: read and write** and **Metadata: read**; the current mock metadata slice needs only Metadata read. Keep organization access, Workflows/admin permissions and user authorization off unless a separate future requirement is approved. No webhook receiver, OAuth callback flow or user-token exchange is needed for this scaffold.

Do not paste a private key into chat or save it in this checkout, an agent-visible filesystem or a general shell environment. Real-key provisioning has no supported Aegis destination yet. A private key is long-lived App authority even though its minted installation tokens expire; key storage must be reviewed before one is entrusted to Aegis. When that gate opens, identifiers can be enrolled separately from private key material and GitHub's actual selected-repository/permission state must be verified.

## Sources and interpretation

Official GitHub documentation consulted 2026-10-06:

- [Install your own GitHub App](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app): personal account installation and selected repositories.
- [Generate installation access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app): explicit repository/permission narrowing and one-hour expiry. Omitting either scope can inherit broader installation access.
- [Generate a JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app): RS256, issuer and time claims.
- [App REST endpoints](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app), [repository metadata](https://docs.github.com/en/rest/repos/repos#get-a-repository), and [token revocation](https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token): modeled provider routes.
- [Manage App private keys](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps): private key custody and sign-only storage direction.

The deployment and Git-worker design is Aegis's proposed enforcement contract, not a claim that these provider documents establish OS isolation. See [application delivery](application-delivery.md), [threat model](threat-model.md) and [verification](verification.md).
