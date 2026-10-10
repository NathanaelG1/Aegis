# ADR 0022: Compose two reviewed imports through application replacement

Status: accepted for closed canary-only development, 10 October 2026. Functional
results belong to their exact source in the [verification record](../verification.md).
Operational rotation and protected entry remain unavailable.

## Context

[ADR 0021](0021-fixed-application-slot.md) installs the actual version-one import
through the TLS broker process and fixed recipient child. Its two-version
replacement test uses an in-process fixture. Neither result demonstrates that
two independent input reviews, encrypted imports and delivery approvals reach
the same application slot through the composed process path.

## Decision

Add the separate, optional `aegis-application-rotation` drill. Preserve the
one-import application-slot drill and its contract. The new public command
accepts only a new absolute disposable root, or `inspect` with an existing root.
It accepts no value, key, input stream, recipient, configuration, endpoint,
executable, version selector, readiness declaration or fault control.

1. Create two independent fixed-canary import ceremonies. Each has its own
   exact frozen review, one-shot approval and committed ciphertext, bound to
   the same fixture vault and the appropriate exact version and installation
   profile. Import approval does not grant delivery authority.
2. Admit both actual committed records into the signed broker manifest. Bind
   each ciphertext and its import metadata to its exact version and profile.
   Do not regenerate a value, clone one import into two versions or fall back
   to a legacy fixture constructor. Reopen must verify both retained imports.
3. Authenticate through the existing process-owned TLS agent/admin channels.
   Obtain a separate exact delivery approval for each version through the
   existing broker. Retain the installation adapter/output contracts `2/2`;
   profiles have distinct revisions `1` and `2`. A `latest` alias or an old
   approval must not follow the new version. Each broker process freezes one
   profile: restart and freshly authenticate for version two, then again for
   the revoke phase; do not silently mutate the first process's grant.
4. Consume and synchronize each broker reservation before possible effect.
   Pass its signed encrypted capsule through the fixed recipient-child route
   to the same application slot. Install version one at generation one and
   then version two at generation two using the existing handle-relative slot
   protocol.
5. Verify and retain both signed installation receipts and correlated broker
   outcomes. Each live phase checks its exact duplicate without another effect.
   The version-two phase rejects a version-one request without rolling back
   the file. Reopen retains signed history, not in-memory run handles, sessions
   or approvals; fresh authentication and durable revoke remain required.

TLS terminates at the broker's role endpoints. Recipient delivery continues to
use signed encrypted capsules and signed responses over inherited local IPC.
No TLS recipient endpoint, network listener, operational custody provider or
second authority engine is introduced by this composition.

## Failure and evidence contract

The [composed rotation contract](../composed-canary-rotation.md) defines the
fixed layout, public report and required acceptance observations. Both import
bindings, ciphertexts, delivery reviews and receipts must be checked; observing
the final version-two file alone is insufficient. Runtime inspection verifies
cryptographic evidence and the installed object. External tests that decode
signed payloads only establish the metadata they observe, not signature validity.

Exercise actual recipient exits at each second-install boundary: synchronized
intent, synchronized stage, rename, synchronized directory and synchronized
completion before acknowledgement. The first completed receipt must survive.
The second reservation stays consumed and unknown when its reply is lost,
even if the file or signed completion already shows version two. Preserve any
pending intent and require reconciliation; never retry, refund, fabricate a
receipt or revive a session/approval to resolve uncertainty. Inspection must
not repair, remove or rewrite evidence. This is a process-crash contract, not a
claim about power loss or arbitrary storage failures.

Public reports contain only bounded fixture facts, counts, stable errors and
booleans for checks the run actually performed. These fields are neither
deployment admission evidence nor claims of human presence, custody or
isolation. Report observations separately from tests not yet run and historical
checks for the one-import path.

## Next operational decision and retained limits

This completes a bounded composition question once its acceptance checks pass;
it does not establish a general or operational rotation service. Choose the
actual protected-entry and recipient adapters using the short
[operator decisions](../operator-decisions.md), then implement and validate
them against that selected boundary. Further synthetic success cannot choose
the host, custody/unlock mechanism, independent human client or recovery anchor.

The agent should remain on another machine. The recommended trial uses one
operator-controlled Linux x86_64 host/VM with distinct broker/recipient service
identities and protected installation closure, plus independently controlled
human approval/unlock and recovery/anchor authority. Removing administrator
access alone does not exclude same-UID files/processes/debugging, mutable
application configuration, backups or host/control-plane access.

All fixture processes remain `UNISOLATED`; live-key and protected-deployment
claims stay false and `require_live_deployment()` remains an unconditional
refusal. There is no authorization for deployment, listeners, access/security
changes, credential entry, provider calls or Sprite use. The previously stopped
independent adversarial review remains unresolved; this milestone neither
resumes nor replaces it.
