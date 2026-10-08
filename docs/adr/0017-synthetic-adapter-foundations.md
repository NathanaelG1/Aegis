# ADR 0017: Exercise adapter boundaries before production activation

- Status: accepted for fixed-fixture development only
- Date: 2026-10-07

## Context

The recovered runtime has durable synthetic delivery and separate agent/admin handlers. Operator entry, an enrolled external recipient, and an authenticated production channel remain missing. A successful unit test cannot make the development host an operator-owned secret boundary.

## Decision

Develop three independent, bounded fixture adapters: a metadata-only operator-entry ceremony, an exact-enrollment encrypted recipient handoff, and per-connection framing over a sealed dummy channel. Keep their implementation and focused tests separate so they can be developed in parallel and integrated with the existing library. Expose only fixed-fixture drills and safe observations. No arbitrary credential entry, generic trusted-channel constructor, remote listener, or production activation switch is added.

Entry state must retain exact artifact/configuration/role bindings and invalidate stale or cancelled review. Recipient delivery must compare the enrolled immutable identity/destination, correlate receipts, and retain uncertainty rather than retry. Transport must own one role/peer/channel and close on framing or binding failure without routing an agent request to administrator authority.

## Consequences

These modules provide executable contracts and integration seams. They do not implement a protected browser/desktop entry UI, externally measured enrollment, production TLS, protected custody, trusted external time, a generation anchor, or crash-safe external-recipient dispatch. The existing core and durable store remain separate from the new recipient fixture until their integration is explicitly tested. Production entry remains refused.

The previously stopped independent review remains incomplete. Functional tests, secret-marker checks for publication, and ordinary code integration do not resume or replace it. Any future assurance or deployment claim needs its own authorized review and evidence.
