# ADR 0019: Owner-controlled remote fake-secret workflow

**Status:** Implemented experiment; deployment boundary and real-secret readiness pending. **Date:** 2026-10-17.

## Context

The owner will provision and deploy a separate Sprite without giving agents its administrative rights. Cooperative agents should use a key without copying it into their context or tool output. We also want evidence for basic rejection of role crossover, self-approval, output disclosure and restart replay. The existing local Unix/terminal workflow cannot authenticate a remote owner independently from an agent.

## Decision

Add an opt-in Unix `sprite-demo` feature using Axum/Tokio HTTP transport and separate random owner/agent bearer credentials compared using `subtle`. Generate only a new fake fixture during private initialization; accept no real-secret input or arbitrary provider route. Keep the fake provider inside the trusted process and reuse the existing core for all operations. This is a separate experiment superseding the remote-access/background-service exclusion only for this fake workflow; it does not convert the foreground local release into a remotely accessible operational vault.

The owner receives canonical review through an independently authenticated route. Inspection creates a bounded, random one-use review receipt holding the complete core approval view. Approval consumes it and calls atomic `approve_reviewed`. The agent receives only references, pending/run state and typed results. Neither role can export the key through this API. Owner authentication proves possession of a role credential, not physical human presence. One broker has one bound agent principal; there is no user-supplied principal or model-based trust.

Require loopback listeners and an operator-supplied protected tunnel/TLS gateway for remote deployment. Pin requests to a random process instance, retain volatile bounds and deny automatic approval/budget restoration. Do not manage Fly credentials, Sprites, gateways, services, deployment or provider accounts from this implementation. The owner controls the source/build promoted to the protected host.

## Evidence and limits

An executable local verifier creates a fresh fixture and separate role credentials, runs the real server and a distinct stdio MCP agent process, drives owner approval, checks negative paths/retries/restart behavior, and scans captured responses/logs before exporting source/binary hashes, a report and an agent transcript. A fake-account unit test rejects an incorrect key. Existing core lifecycle and concurrency tests remain applicable.

This is bounded API evidence. The verifier knows both role credentials and is not an OS sandbox. It cannot attest Sprite administrative exclusion, TLS/gateway deployment, file/memory isolation or absence of every possible disclosure. The fake fixture is plaintext on owner-controlled disk, not encrypted operational storage. Protected application delivery remains required and unimplemented under ADR 0007. Linux execution must be recorded separately from local macOS evidence. Passing tests neither authorizes real credentials nor implies an independent audit.
