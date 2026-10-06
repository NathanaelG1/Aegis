# ADR 0006: Release evidence and licensing

**Status:** Accepted. **Date:** 2026-10-06.

## Context

Aegis source is public under an owner-approved MIT license. Portable architecture and passing synthetic tests do not establish a supported secrets product.

## Decision

Apply the [MIT license](../../LICENSE) to first-party source and documentation. Preserve third-party licensing and attribution separately in [third-party notices](../../THIRD_PARTY_NOTICES.md) and the dependency inventory. Keep Cargo package publication disabled; a public Git repository does not imply authorization to publish a registry package or a supported binary release.

Declare the actual tested OS, architecture, toolchain, context, feature combination, and filesystem. Security claims require corresponding enforcement/fault evidence plus independent composition review. Maintain a draft security policy without inventing a monitored private contact or supported production versions.

Pin dependency resolution and minimize trusted dependencies without replacing established cryptography. Per-target advisory/license review, unsafe review, notices, SBOM/provenance, and artifact verification remain release gates.

## Consequences

Public source permits MIT reuse; it does not establish production readiness or containment. Development and tests use synthetic fixtures. Live provider integration, credential migration and operational use require their own contracts and verification. Mac evidence does not imply Linux/Windows security support.

## Open gates

Protected reporting/response ownership, packaging/signing/first-install trust, independent security review and remediation, and a cross-platform integration matrix.
