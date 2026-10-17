# Optional disposable-key signing experiment

**Synthetic only.** `signing-spike` exercises a private sign-only key-source contract with a newly generated, unregistered RSA-2048 key. The standalone experiment has no key input, key file, persistent credential, network call, OS configuration or live-provider composition. A subsequent [explicit optional broker composition](github-signed-composition.md) reuses the private source with reviewed synthetic authority. Default broker behavior, mock constructors and `live_readiness()` are unchanged. This is implementation evidence for an interface and signing policy, not protected storage or an audited credential service.

```sh
cargo run --locked --offline --features signing-spike --example signing_spike
cargo test --locked --offline --features signing-spike --lib signing::tests
```

The no-input example returns only fixed labels, counts and booleans. Its public API cannot return keys or JWTs. Private visibility and omission of `Debug`, `Clone` and serialization on credential wrappers reduce accidental API disclosure; they do not resist arbitrary code in this process or under the same OS identity.

## Contract and lifecycle

Private `KeySource::resolve` accepts an exact label, version, issuer and algorithm, returning a sign-only lease. It has no plaintext-export or arbitrary-message-signing method. The fixed source accepts only the fixture reference and `RS256`. `UnavailableProtectedStore` always refuses resolution; no caller flag can turn it into protected custody.

The ephemeral source owns an AWS-LC-generated key and random instance epoch. A lease binds epoch, generation and exact reference. The source has a 600-second elapsed-time lifetime, leases have 30 seconds, and at most 32 signing attempts are reserved. Signing and lock/revoke/rotation decisions share one mutex. Lock/unlock changes generation, so an old lease cannot regain authority. Revocation and owner drop discard the owned key and deny surviving leases. Test-only rotation changes key version and invalidates old leases. Generation overflow fails closed. UTC or elapsed-clock regression permanently invalidates future use; checked claim arithmetic cannot wrap.

Lock is a logical future-signing restriction: it retains the in-memory key. Revocation, rotation and owner drop cannot recall an already produced JWT or a provider token. A verifier with the old public key still accepts the previously issued JWT until its expiry. None of these controls is authenticated human unlock, secure memory locking or provider-side revocation.

## Signing and verification policy

The maintained `jsonwebtoken` layer signs and verifies using its explicit AWS-LC provider. RSA key generation uses `aws-lc-rs`. AWS emits PKCS#8 DER; the maintained borrowed `pkcs8` decoder validates the RSA algorithm identifier and obtains the embedded PKCS#1 representation for the JWT library. No custom crypto, ASN.1 decoder, PEM parser or key-import path is added.

The fixture signs `typ=JWT`, `alg=RS256`, the fixed synthetic issuer, `iat=now-60` and `exp=now+540` using checked arithmetic. The 600-second claim interval is distinct from GitHub installation tokens' provider-set one-hour expiry; this experiment does not create installation tokens. The clock is injected and fixed for the public demo; it is not an operational clock implementation.

Verification first enforces an ASCII compact JWT bounded to 4,096 bytes, exactly three nonempty components, canonical unpadded base64url, header/payload components at most 1,024 bytes and a 256-byte RSA signature. Strict typed header/claims reject unknown and duplicate members, wrong types, surplus JOSE fields and every other algorithm. The library then verifies signature, algorithm and issuer. Its OS-wall-clock expiry check is disabled only to use the explicit injected test clock: local policy requires `iat <= now < exp` and `0 < exp-iat <= 600` with zero leeway. `iat` is not implicitly validated by the general JWT library. No unverified/dangerous decode API is used, and pre-parsed claims are never an authorization result.

`jsonwebtoken` 11.1 has a process-global provider. This experiment installs its fixed AWS-LC provider once and caches success. If any other code already installed a provider, the experiment fails closed even if that provider is AWS-LC. It neither trusts nor overwrites an earlier provider. This deliberate embedding limitation must be resolved before production composition; signature tests and a fresh-process prior-initialization regression cover it.

## Memory and threat limits

The owned JWT wrapper zeroizes its string on drop. The selected JWT library's owned encoding-key buffer and AWS-LC's owned exported DER buffer have zeroizing drop implementations; the borrowed PKCS#8 view adds no owned private-key copy. These are specific buffer-lifecycle properties only. Native signing temporaries, allocator/reallocation copies, stacks, swap, dumps, debuggers, kernel access and malicious same-process/same-UID code remain outside the claim. Dependencies contain native/unsafe code despite first-party `unsafe_code = forbid`.

No signing key or JWT is persisted or printed by the example. Tests generate disposable keys in memory and inspect them only within the private test module. Real custody still needs protected provisioning, independent human authentication, isolated broker identity, authenticated durable state and a reviewed live transport. The source is available only to the explicit optional signed-synthetic constructor; default GitHub constructors and CLI/MCP selection remain unchanged. No signing/export agent method exists.

## Dependency decision and cost

All additions are optional. Comparing Cargo metadata with commit `9ac90ff` shows identical default and `storage-spike` package versions **and enabled features**. No previously locked package identity changed; the combined cross-target lockfile adds 26 package identities. The [Linux inventory](dependency-inventory-linux-signing.json) includes build/proc-macro packages, not just code linked into an executable:

| Linux x86_64 configuration | Third-party package identities |
| --- | ---: |
| Default | 19 |
| Storage only | 129 |
| Signing only | 40 |
| All features | 146 |
| Metadata-only alternative: AWS-LC + base64 + zeroize, no JWT/PKCS#8 layers | 32 |

AWS-LC alone could sign fixed JWS bytes with existing serialization, reducing the signing graph by eight identities. It would make Aegis maintain more compact-JWS construction, parsing, algorithm dispatch and validation behavior. The chosen layer keeps cryptographic/JWT operations maintained upstream, plus a narrow strict application profile. The extra eight identities are `jsonwebtoken`, `pkcs8`, `der`, `spki`, `const-oid`, `signature`, `rand_core` and `zeroize_derive`. This is a conscious maintenance tradeoff, not a claim that a general JWT library removes protocol risk. The alternative was dependency-metadata comparison only, not an implemented or security-tested replacement.

`ring` was considered but lacks this in-process RSA generation path; adopting it would require different test-key custody or additional generation machinery. The JWT library's RustCrypto backend introduces separate RSA/ECDSA/EdDSA stacks. AWS-LC is selected for native RSA generation and the maintained JWT provider; no other algorithm is enabled by Aegis policy, although the underlying provider supports more algorithms.

| Direct optional dependency | Exact pin | Declared Rust minimum | Purpose |
| --- | --- | --- | --- |
| `jsonwebtoken` | 11.1.0 | 1.88 | JWT signing/verification; default PEM features disabled; AWS-LC backend only |
| `aws-lc-rs` | 1.18.1 | 1.71 | Disposable RSA generation; lockfile selects non-FIPS `aws-lc-sys` 0.45.0 |
| `pkcs8` | 0.11.0 | 1.85 | Borrowed PKCS#8 decoding; default features disabled |
| `base64` | 0.22.1 | 1.48 | Canonical bounded compact-profile decoding, matching the JWT library's version |
| `zeroize` | 1.9.0 | 1.85 | Drop cleanup for the private JWT buffer |

The Aegis minimum stays Rust 1.96, with pinned toolchain 1.96.1. Pins provide reproducible selection, not advisory immunity. Upstream `jsonwebtoken` marks maintenance as passive; its 11.1.0 release and provider changes were inspected. The documented type-confusion advisory [GHSA-h395-gr6q-cpjc](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc) affects versions before 10.3.0; the selected pin is outside that range. This limited check is not a full advisory, license, native/unsafe or supply-chain audit. Reassess maintenance and providers before promotion.

## Build and platform evidence

AWS-LC introduces a native FFI/build dependency. Its [current requirements](https://aws.github.io/aws-lc-rs/requirements/index.html) call for a C/C++ compiler for non-FIPS builds; CMake, bindgen and Go are not required in that mode. A `cmake` Rust package is present in the graph, which does not mean the CMake executable was used. No FIPS feature or certification claim is made. Native compilation and target-specific toolchains reduce build portability compared with the default Rust graph.

Observed here: Debian 13.6/Linux x86_64, Rust/Cargo 1.96.1, existing GCC 14.2.0, no CMake executable. The optional code and native library build successfully without installing OS tooling. macOS and Windows were not built or tested for this increment. Upstream platform support is not Aegis deployment evidence; Windows still lacks Aegis broker transport. Cross compilation needs the corresponding native target toolchain.

Historical ADR0011 optimized, unstripped local release measurements before the later composition (not reproducible size/performance promises): prior default broker 1,542,992 bytes; current default broker 1,543,000 bytes; signing-enabled broker 1,589,440 bytes; standalone signing example 3,964,312 bytes. At that checkpoint, the broker did not call the signing module, so its size was not the full signing implementation's cost. One observed cached-dependency build took about 8 seconds for each default build and 26 seconds for signing; no controlled benchmark is claimed. The final verification record identifies the tested source and checks.

## Next gate

The [approval-bound synthetic composition](github-signed-composition.md) now implements that binding through one private permit after durable core reservation. Further implementation pauses at the [readiness/deployment decision checkpoint](readiness-checklist.md). Protected deployment, real provisioning and authenticated human approval require separate decisions and permissions.

Primary references: [JWT API](https://docs.rs/jsonwebtoken/11.1.0/jsonwebtoken/), [validation API](https://docs.rs/jsonwebtoken/11.1.0/jsonwebtoken/struct.Validation.html), [AWS-LC RSA API](https://docs.rs/aws-lc-rs/1.18.1/aws_lc_rs/rsa/struct.KeyPair.html), [PKCS#8 API](https://docs.rs/pkcs8/0.11.0/pkcs8/), and [GitHub App JWT requirements](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app).
