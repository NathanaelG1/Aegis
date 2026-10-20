# ADR 0020: Generic service-scoped secret injection

Status: implemented experimentally in the opt-in Unix `proxy` feature.

An agent may administer an application host while Aegis runs on a separate,
owner-controlled host. Giving the application a provider credential would also
give it to that agent. Instead the application names secret references in a
bounded operation request; Aegis authenticates its service identity, checks the
owner's secret ACL and exact HTTPS operation, and injects header values locally.
There is no remote owner endpoint, raw-secret export, arbitrary URL/headers, exec,
or arbitrary signing surface. Service tokens convey operation authority only.

The owner provisions and rotates real credentials through a private terminal or
bounded stdin. age encryption, private files and atomic locked state persist
credentials, policy and at-most-once request intents. Credentials are used by the
broker, not delivered to an agent-controlled recipient. Existing synthetic
experiments retain their original gates; their readiness booleans are not changed.

Response JSON projection and known-value checks reduce accidental disclosure.
The configured provider and response contract remain trusted: generic inspection
cannot prove that a malicious API will not encode a credential. Authorization of
a method and endpoint does not impose application-specific business constraints.
Key signing protocols and protected delivery require their own implementations.

Reuse the existing Hyper/Tokio and Rustls stack with a small one-request connector;
reuse age, SHA-256 and existing Unix primitives. Add only Tokio's Rustls adapter,
CA roots and Hyper's small client support dependencies. Do not add a second TLS
implementation, general HTTP proxy, provider SDK or language runtime. Release
packaging, fixture tests, inventory and the Sprite client are native Rust tooling.

See [setup, protocol and threat boundaries](../secret-proxy.md). Real deployment,
provider credentials and administrator isolation require separate operator
verification; local TLS fixtures demonstrate application behavior only.
