# ADR 0011: Optional disposable-key sign-only source

**Status:** Implemented optional synthetic experiment; protected custody and live composition gated. **Date:** 2026-10-06.

## Context

The GitHub adapter's mock signer does not establish cryptographic signing or a key-source contract. A real key must not be accepted before independently protected custody, human approval and deployment are verified. The small default dependency graph should not absorb experimental native cryptography.

## Decision

Add opt-in `signing-spike` with a private sign-only lease interface and unregistered in-memory RSA-2048 keys. Export only a no-input fixed demonstration and safe report. Keep broker/protocol/mock signing unchanged. The protected-store placeholder always refuses. Bind each lease to exact reference/version/issuer/RS256, instance epoch and generation; serialize signing with logical lock/revoke/rotation, enforce elapsed limits/budget, sticky clock invalidation and owner-drop revocation.

Use pinned `jsonwebtoken` over AWS-LC for signing/verification, AWS-LC for generation and maintained borrowed PKCS#8 parsing. Layer strict bounded canonical JOSE/claim policy on top; never depend on default algorithms, leeway or implicit `iat` validation. Fail closed if the JWT library's process-global provider was initialized elsewhere. Do not export or persist private key/JWT bytes.

## Consequences

The Linux signing graph is 40 packages versus default 19; default and storage-only graphs remain unchanged. An AWS-only fixed-JWS alternative is 32 but shifts protocol maintenance into Aegis. Native compiler requirements, passive JWT upstream maintenance, global-provider exclusivity and bounded buffer-zeroization properties are explicit tradeoffs. The feature remains optional pending composition/platform/dependency review. Tests establish disposable signing and lifecycle behavior, not memory isolation, protected storage, authenticated approval or live access. See [the experiment contract](../signing-spike.md) for pins, measurements and limits.

ADR 0012 subsequently adds one explicit optional synthetic broker composition. The default/mock and no-live-key constraints remain; the earlier standalone-only composition status is historical.
