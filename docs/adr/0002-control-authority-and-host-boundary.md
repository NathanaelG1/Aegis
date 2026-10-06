# ADR 0002: Control authority and host boundary

**Status:** API split and synthetic terminal workflow implemented; protected approval mechanism pending. **Date:** 2026-10-06.

## Context

Agent requests must not approve themselves. A separate terminal alone does not demonstrate human presence against code with the same account's permissions. The current process is a trusted Rust embedding host.

## Decision

Use separate trusted `Control` and bounded `AgentClient` handles. Only the trusted handle administers/approves/revokes/stops authority. Do not serialize it or expose it on the agent wire. The control view uses broker-resolved canonical fields.

The synthetic harness may hold both capabilities, and is labeled accordingly. The foreground broker retains control in terminal stdin, with `inspect ID` required before a matching `approve ID`. Terminal EOF stops authority. Its separate Unix agent endpoint has current-UID checks, while the MCP child has no control tool, credentials, keys, or broker startup capability.

The normal foreground command reports `interaction_required` for nonterminal stdin; the explicit `--synthetic-control-pipe` test flag creates no human-presence guarantee. The standalone JSON-lines fixture retains an awaiting-approval state and cannot complete private approval. Neither client labels nor approval booleans establish identity or consent.

## Consequences

This creates a tested API boundary and a separate-process synthetic workflow. It trusts the account/embedding host and provides no containment against arbitrary same-user code or terminal automation. Product language keeps portable workflow, restricted-host operation, and isolated deployment distinct.

## Spike before stronger claims

Select a host/OS-controlled human channel and attempt administrative, file, memory, configuration, and binary bypasses with the agent's actual tools. Demonstrate private approval, canonical display, denial, cancel, expiry, and resume. Record platform/version/identity details before claiming human presence or containment. Do not introduce a root/system broker for convenience.
