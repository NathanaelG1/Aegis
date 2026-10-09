# Fixed-fixture mutual TLS transport

The optional Unix `vault-spike` now includes `aegis::vault::tls::run_synthetic_tls_drill(root, kit, recipient)`. It uses real Rustls TLS 1.3 handshakes and encrypted TLS record I/O between disposable peers in the same process. It runs the existing agent/admin protocol through those channels, completes one exact reviewed canary delivery, revokes, and inspects the existing durable evidence. The three paths must be new synthetic fixture destinations. There is no listener, network connection, caller-supplied credential/certificate/hostname, raw-secret API, or production channel constructor.

`SyntheticTlsReport` is the only additional public type. It contains fixed booleans and counts, without keys, certificates, exporters, paths, proofs, requests, receipts or canary values. `Channel`, certificate enrollment, the endpoint dispatcher and framing helpers are private. This adds transport dependencies and a transport boundary to the experimental trusted computing base; it does not change broker authorization, approval policy, credential custody, existing result projection or deployment admission.

## Authentication and role ownership

Each drill generates a new CA and separate server, agent, administrator and recipient leaf keys using rcgen. TLS identities remain in memory; they are not loaded from operational credentials, written to disk, logged or returned. The existing canary actor kit is still persisted under the supplied synthetic kit path by `SyntheticProtocol::create`, as in earlier drills. All actors and their keys remain controlled by one trusted fixture process.

Rustls's standard WebPKI verifiers validate the configured CA path, certificate validity, signature and appropriate server/client EKU. Mutual client authentication is mandatory. The client also validates the fixed server name `broker.aegis.invalid`. There are no system trust roots or verification bypasses. After a full handshake, both sides additionally require the exact enrolled leaf DER and a single-leaf chain of at most 4,096 bytes. A different certificate from the same CA is refused, even if its subject/name looks right. The client DNS label does not confer authority: the exact enrolled certificate has a fixed role.

Private host setup binds each owned protocol endpoint to its expected enrolled certificate and role. It exposes the endpoint only after that peer authenticates. Agent, administrator and recipient use distinct mandatory ALPN values: `aegis-agent/1`, `aegis-admin/1`, and `aegis-recipient/1`. Role bytes in an application frame are equality checks against this binding, never routing selectors. An agent cannot send an admin method, admin role byte or valid agent proof to obtain admin authority.

Both configurations enable only TLS 1.3. Client resumption and early data are disabled; the server has no session store, issues/accepts zero TLS 1.3 tickets and accepts zero early-data bytes. A resumed handshake is explicitly rejected. No key logger is configured. Existing protocol challenges, signed actor proofs, exact review equality and main-broker durable reservation remain required after TLS authentication. The frame exporter does not replace or change those signed proof schemas.

The recipient-role exchange currently verifies authenticated transport of a fixed dummy payload. It does not route the runtime recipient capsule or acknowledge installation over TLS. The protocol delivery uses the existing recipient implementation; [recipient integration](recipient-adapter-contract.md) and any future external recipient transport have their own gates.

## Exporter-bound application framing

After handshake completion, Rustls derives a 32-byte binding using its standard TLS exporter, label `EXPORTER-Aegis-fixture-channel-v1` and the enrolled role's ALPN as context. This value stays inside encrypted application frames and private memory. It is a per-channel binding, not a custom cipher, MAC or independently protected credential.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | `ATL1` framing/version magic |
| 4 | 1 | Enrolled role: agent 1, admin 2, recipient 3 |
| 5 | 1 | Fixed peer marker, equal to the enrolled fixture role |
| 6 | 1 | Direction: client-to-server 1, server-to-client 2 |
| 7 | 1 | Reserved, must be zero |
| 8 | 32 | TLS exporter binding |
| 40 | 8 | Big-endian per-direction sequence, starting at zero |
| 48 | 4 | Big-endian body byte count |
| 52 | body count | One bounded body |

A protocol body is the existing `aegis.synthetic.vault.v1` JSON, not a new authority schema. Body length is 1–16,384 bytes; the application frame including header is at most 16,436 bytes. Magic, role, peer, direction, exporter, sequence and length are checked before body allocation or endpoint dispatch. Sequences cannot repeat, skip or wrap: each direction permits at most 32 frames. TLS record integrity also rejects modified, replayed or cross-connection ciphertext. Re-encrypting an old application frame into a fresh connection fails the exporter check.

The private request/response dispatcher permits one complete application frame per exchange, rejects multiple complete frames before dispatch, and bounds JSON serialization before growing its response buffer. Endpoint protocol denials return the existing safe error and consume a sequence. TLS, binding, sequence, framing, EOF, deadline or resource errors close both directions and drop the owning endpoint. No reset, reconnect, automatic retransmission or endpoint extraction API exists. Failure after an operation was dispatched does not undo an effect or refund its durable reservation. The drill never retries an uncertain invocation.

## Byte, work and time bounds

| Boundary | Limit |
| --- | --- |
| One plaintext body | 16 KiB |
| One serialized TLS flight/receive slice | 64 KiB |
| Handshake wire accounting, both peers | 256 KiB, conservatively counting send and receive |
| Established channel wire accounting | 256 KiB total incoming/outgoing |
| Handshake/channel processing budget | 4,096 counted steps each |
| Application frames | 32 per direction |
| TLS outgoing buffer setting | Body + header + 4 KiB |
| TLS record fragment setting | 4,096 bytes |
| Whole handshake | 2 seconds |
| Established channel lifetime | 30 seconds, never refreshed |
| Partial receive and each private message transfer | 1 second, absolute |

The receive clock starts with the first encrypted byte, even before a TLS record or plaintext header completes. The decoder also times partial plaintext frames. The complete private transfer checks an independent one-second budget while fragmenting records into 257-byte input slices. Empty receive calls can check an existing deadline but cannot extend it. Tests inject private `Instant` observations without exposing caller-controlled time publicly.

These are finite input/work budgets and deadline checks at processing boundaries. They do not preempt a single native crypto call, scheduler stall or filesystem operation. `set_buffer_limit` controls outgoing application buffers, not all Rustls/native allocations. The fixture runs synchronously with no sockets, remote peers, connection-admission loop or blocking-network cancellation. It therefore provides no measured live-network slow-peer, host-isolation or production peak-memory guarantee. A future listener must independently implement bounded admission and actual read/write cancellation.

Owned frame/plaintext buffers, exporter fields, fixture key DER and rcgen's owned serialized key buffers are zeroized on drop or terminal close. Native library state and compiler/parser/allocator copies, swap and dumps remain outside that claim. All private errors are fixed payload-free variants, mapped to `BrokerUnavailable` at the public TLS boundary; existing fixture creation/storage errors retain their original codes.

## Dependency provenance and feature effects

Direct new dependencies are pinned exactly to Rustls `0.23.45` (`std`, `aws_lc_rs`) and rcgen `0.14.10` (`crypto`, `aws_lc_rs`, `zeroize`), both with defaults disabled and enabled only by `vault-spike`. Existing AWS-LC supplies their cryptography. TLS 1.2, default `ring`, certificate compression, rcgen PEM and rcgen X.509 parsing are not enabled in the Linux build. Default-feature Aegis remains free of these TLS dependencies.

The official Rustls advisory [GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc), checked on 2026-10-09, lists `0.23.13`–`0.23.44` as affected by accepting TLS 1.3 handshake messages at incorrect encryption levels and `0.23.45` as patched. This is why the implementation pins `0.23.45`. It is not a claim that this graph has no other advisories. The [Rustls 0.23.45 API](https://docs.rs/rustls/0.23.45/rustls/) and [exporter/I/O documentation](https://docs.rs/rustls/0.23.45/rustls/struct.ConnectionCommon.html) are the implementation references. rcgen APIs were checked against the exact downloaded `0.14.10` package source and its Cargo feature manifest.

`Cargo.lock` adds 38 resolved package entries and does not update or remove any previous package version. Its optional/target resolution also records packages absent from the exercised Linux compilation, including `ring` and `x509-parser`; their presence in the lockfile is not evidence that their features compiled. No OS trust store, system TLS library, FIPS mode or platform certification is implied. Rustls/WebPKI, rcgen/time/ASN.1 generation and the AWS-LC/native toolchain remain dependency and provenance review obligations. The lockfile SHA-256 for this slice is `90e27be2374c74135cd31fe1285db74bdd264d62b64673b217080989ca9de55b`. The pinned graph and advisory check are not a dependency audit, signed release, SBOM refresh or first-install verification.

## Functional evidence and unchanged admission

Ten focused tests cover:

- Real TLS plus signed agent/admin authentication, exact approval, one canary delivery, durable consumed use, final revoke and safe report output
- Three role ALPNs, full non-resumed handshakes, matching peer exporters and distinct fresh-channel exporters
- Wrong CA/name/leaf/role/ALPN, missing client certificate, wrong EKU and expired certificate rejection
- Every plaintext split point, one-byte TLS input and maximum-size body roundtrip
- Oversized/empty lengths before allocation, bounded response serialization and immutable header fields
- Application and ciphertext replay, cross-channel frame/ciphertext rejection and ciphertext corruption
- Frame, byte, processing-step, handshake-time, first-encrypted-byte and lifetime limits
- Truncation/EOF, sticky failure, dropped endpoint ownership and multiple complete frames rejected before dispatch

Compile-fail documentation confirms that the private channel and enrollment types are inaccessible. These are ordinary functional tests; the previously stopped independent adversarial review remains incomplete and is not resumed or replaced by this work.

Independent key custody, protected operator enrollment, independent human presence, OS isolation, operational certificate renewal/revocation, external-recipient delivery over TLS, protected durable anchors and deployment admission remain unverified. `require_live_deployment()` remains unconditionally `UnsupportedDeployment`; the report always leaves custody, human-presence, protected-deployment and real-key readiness false. A successful handshake is not permission to use real keys or deploy a listener.

The integrated example uses the same fixed-fixture entry point:

```sh
cargo run --locked --offline --all-features --example tls_spike -- /tmp/new-vault /tmp/new-kit /tmp/new-recipient
```

Use fresh destinations and remove the disposable fixture files when finished. The example prints only the closed report. Its execution is verified separately in the integration branch.

Validation commands (Linux x86_64, Rust 1.96.1, pinned lockfile):

```sh
cargo test --locked --offline --all-features --lib vault::tls -- --test-threads=2
cargo test --locked --offline --all-features --doc vault::tls
sh scripts/check.sh
```

Verification on 2026-10-09: the 10 focused TLS tests, two private-API compile-fail doctests, formatting, all-feature/all-target Clippy and all-feature rustdoc with warnings denied passed. The full checkpoint stopped at 14 existing Unix-socket interface tests because this executor returns `EPERM` on local socket binding. An escalated run had the same result; no socket restriction was changed. The focused TLS tests use in-memory record I/O and do not establish listener behavior. Combined integration and hosted CI results must be recorded separately; this is not a full checkpoint pass.
