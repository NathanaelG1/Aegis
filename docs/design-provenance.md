# Public design references

The product contracts, architecture decisions and threat model in this repository describe the current synthetic implementation and its future verification gates. Planning attachments and private operational material are not included. Only commands present in the source and exercised by tests are implemented.

## Primary references checked for this checkpoint

Primary documentation was accessed on 2026-10-06. These links support design choices, not an audit of the resolved binary or dependency graph. Mutable documentation must be rechecked when shipping versions are selected.

| Reference | Relevance and limit |
| --- | --- |
| [serde 1.0.228](https://docs.rs/serde/1.0.228/serde/) | Serialization framework documentation for the exact manifest pin; no security endorsement |
| [serde_json 1.0.145](https://docs.rs/serde_json/1.0.145/serde_json/) | JSON value/typed serialization documentation for the exact manifest pin; resource limits remain broker/protocol responsibilities |
| [getrandom 0.2.17](https://docs.rs/getrandom/0.2.17/getrandom/) | OS randomness interface used for the 128-bit per-broker epoch; no custom cryptographic primitive |
| [nix 0.29.0](https://docs.rs/nix/0.29.0/nix/) | Safe Rust-facing Unix APIs, with explicit socket/user features; peer checks still need per-platform evidence |
| [age 0.11.1](https://docs.rs/age/0.11.1/age/) | Optional storage feasibility version; its documentation labels pre-1.0 releases as beta/testing-only, consistent with a synthetic spike |
| [Rust Mutex documentation](https://doc.rust-lang.org/stable/std/sync/struct.Mutex.html) | Standard synchronization API reference; stable docs are not pinned Rust 1.96.1 build evidence |
| [age format v1.1.0 URL](https://c2sp.org/age@v1.1.0) | Standard recipient wrapping and authenticated payload format; not a selected Rust backend dependency |
| [MCP transports, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Stdio JSON-RPC framing and protocol-only stdout; hosts may capture stderr, so neither stream is private |
| [MCP elicitation, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) | Form mode excludes credential collection; accepting an out-of-band interaction does not establish completed authorization |
| [Apple accept(2), archived manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/accept.2.html) | Accepted-socket property inheritance motivated explicit blocking mode before timeout-based serving; the current Mac subprocess regression supplies implementation evidence |

The current local compiler is Rust 1.96.1 and the package declares Rust 1.96, edition 2021. Standard Mutex references use the readable stable page rather than a pinned compiler page; actual local compiler/test output is the compatibility evidence. An earlier core-only Rust 1.80.1 check is historical and does not establish compatibility of the current optional graph.

The specific nix 0.29.0 peer-credential API pages were also inaccessible through that tool; the crate index was readable. Do not infer macOS/Linux peer-authentication equivalence from that index.

The writer-authentication limitation of recipient encryption is an architectural inference: knowledge of a public recipient allows creation of another encrypted payload, so encryption does not by itself identify a trusted policy writer. Do not design a policy trust anchor inside an attacker-controlled replacement snapshot.

## Future feature references

These public sources should be revisited during corresponding feature work; the current foundation does not claim implementation based on them:

- [Rust age library](https://docs.rs/age/latest/age/) — select and pin a released version/features before integration.
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — review destination validation and redirect risks when a network adapter is added.
- [GitHub installation token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) — provider resource/permission/lifetime behavior if GitHub is chosen.
- [Rust Command documentation](https://doc.rust-lang.org/std/process/struct.Command.html) — executable lookup, environment and argument caveats when designing a protected recipient launch adapter; no generic runner is planned.
- [MCP tools, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) — annotations remain descriptive hints rather than broker authority.

## Evidence discipline

The required [protected application-delivery design](application-delivery.md#platform-proposals-and-primary-references) checked primary systemd credentials, Linux Yama/openat2, Apple Gatekeeper/runtime protection and Microsoft AppContainer/process access documentation on 2026-10-06. Its platform arrangements are inferences and proposals only; none establishes tested Aegis delivery, confinement or human authentication. [ADR 0007](adr/0007-protected-application-delivery.md) supersedes the earlier optional consumer-delivery direction.

ADRs record accepted directions and outstanding experiments. [Verification](verification.md) records actual tested scope and gaps. Neither a design recommendation nor a successful synthetic API test should be presented as a storage, platform, presence, containment, or external-effect guarantee.

## Review-phase protocol references

The follow-up framing and error review checked the primary [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification), [MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), and [MCP overview/message definitions](https://modelcontextprotocol.io/specification/2025-11-25/basic). These support delimiter and request/error semantics; the local regressions establish this adapter’s exercised behavior rather than broad host compatibility.
