# ADR 0018: develop protected mechanisms with fixed canaries

**Status:** accepted for development on 9 October 2026; operational activation is
not authorized. Baseline: merged PR #1, `90c6d928b54d9edf0f2f610b5fa3f0bd3ff0be43`.

## Decision

Replace selected simulated boundaries with executable mechanisms while keeping
the public experiments restricted to disposable built-in canaries:

1. Use maintained TLS 1.3 with mutually verified certificates, exact peer/role
   enrollment and exporter-bound frames. An application frame cannot select its
   own authority or upgrade an agent channel into an administrator channel.
2. Exercise bounded zeroizing input and encrypted transactional import against a
   frozen review. Neither a general secret-value argument nor an operational
   credential-input command is exposed.
3. Execute the recipient in a separate process that loads only its role material.
   Preserve the existing broker's pre-effect durable reservation, exact receipt
   checking and consumed uncertainty. A transport error never triggers a second
   delivery or refunds a use.

These components are developed in separate worktrees and integrated on a branch
from the merged source. The exact integrated source must pass the existing
functional and quality checks, including all Unix listener cases in hosted Linux
CI. A compile result, isolated component test or historical CI run does not
establish that final result.

## Trust and authority consequences

TLS certificate parsing, the new input/import path and the process supervisor
join the trusted computing base. Standard maintained libraries supply the
cryptography. Development-generated keys and certificates are fixtures; they do
not establish authenticated operational enrollment or independent custody.
Transport confidentiality is a useful mechanism but cannot protect plaintext
from a compromised endpoint, same-UID debugger or host administrator.

A child process is a real execution boundary. In the development harness it runs
under the same operating-system identity and remains accessible to the parent
and its administrator. It is not an isolated recipient deployment. The child
must be a fixed program path selected by the implementation, with no shell or
agent-selected executable, environment, destination or generic command route.
The exact future installation and its dependency/configuration closure must be
operator-controlled and immutable to the agent.

The operator-entry experiment must not describe an in-process simulated approval
as genuine human presence. Input bounds, zeroizing buffers and ciphertext-only
files do not protect a human's keyboard/display, process memory, swap, dumps,
logs, backups or recovery authority. No claim of secure erasure follows.

## First intended operational use

The planned pilot remains a GitHub App installed on selected **personal**
repositories. The root App private key belongs in protected sign-only broker
custody, never in the recipient or agent. A recipient would receive a narrowed,
short-lived installation token for one exact repository and fixed metadata-read
operation. The built-in delivery canary is not an App key, installation token,
provider response, live permission check or verified provider revocation.

## Gates retained

`require_live_deployment()` continues to reject all real-key use. Missing work
includes independently authenticated human interaction and peer enrollment,
protected custody/unlock/recovery, a supported operator-controlled host boundary,
separate service identities and effective access denial, independently protected
rollback authority, and the selected provider adapter. The
[operator trial plan](../operator-live-trial-plan.md) specifies the required
host/action approvals and acceptance evidence.

No host installation, identity/permission or network change, credential entry,
grant, live provider call or production deployment is part of this decision.
The previously stopped independent adversarial review remains unresolved. This
development and its ordinary functional checks neither resume nor replace it.

## Evidence

Record the final component behavior and limits in their respective contracts,
and exact integrated test results in [verification](../verification.md).
Publication uses a conventional-commit draft PR; passing CI is functional
regression evidence, not a go decision for real credentials.
