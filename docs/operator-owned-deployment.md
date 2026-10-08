# Operator-owned production boundary and key-entry ceremony

**Plan only. No production key belongs in the current development workspace or pilot.** The integrated canary path can be reviewed and tested before this ceremony. It still lacks an operational generic key-entry path, production clock/identity/transport integration, independently protected custody/generation anchor and a real enrolled application adapter. Completing host permissions alone is insufficient while those code gates remain open.

## Required separation

The user or another explicitly trusted operator must own the production control plane. The agent may invoke only authenticated, ACL-bounded application methods. It must not retain host administration, exec/shell, filesystem read/write, memory/debug, service/configuration changes, environment/secret management, volume mounts, checkpoint download/restore, backup recovery, network/proxy administration or an equivalent route through another account/tool.

Remove access comprehensively: disconnecting one plugin is insufficient if CLI credentials, SSH, dashboards/cookies, another connector, shared cloud account, CI/deployment credentials or writable artifacts can recreate that access. The agent must also be unable to read/administer the independent human signer, recipient, recovery material and generation anchor. The precise provider permissions must be verified rather than assuming a platform offers resource-level separation. If the selected provider cannot enforce the boundary, use an operator-owned account/environment or another supported deployment. No vendor/private-network service is mandatory.

Install an immutable, operator-reviewed build/configuration by verified digest. Production must not automatically follow an agent-writable branch, mutable dependency/configuration/plugin path or agent-controlled CI runner. The broker holds only what its role needs; human-control private credentials belong to the independent operator channel, and recipient private credentials belong to the recipient. The all-keys synthetic fixture kit must never be promoted to production.

## Sequence and evidence

1. Finish and independently review the missing production adapters. Name the OS/filesystem, host control plane, intended agent tools, credential types, recipient mechanism, clock behavior and protected anchor outside the checkpoint rollback domain. Keep live entry disabled on unsupported configurations.
2. The operator creates/configures the production environment and installs the pinned artifact. Configure authenticated TLS/application identity and exact default-deny ACLs, independent human administration, optional private binding and any specifically trusted proxy. Verify actual exposure and backend-bypass denial.
3. Establish operator-owned signers/recovery/custody and the independent generation anchor without passing private material through the agent. Verify cold start, missing state, rollback, duplicate wake, expiry and lost-acknowledgement behavior with disposable canaries only.
4. Remove the agent's privileged access through every identified route. The operator retains a separate recovery path. Record the effective permissions and artifact/configuration identity after removal.
5. Run canary attacks through the agent's actual remaining tools: filesystem/environment/process/debug reads, exec, service mutation, recipient/plugin/proxy redirection, admin/approval impersonation, checkpoint/backup extraction or restore, replay/rollback, stale policy/key/recipient versions and simultaneous final-use requests. Expected denials must be observed; a label, mode bit or successful unit test is not evidence of removal. Tests must also show the enrolled recipient succeeds and only safe status reaches the agent.
6. Independently review the results and unresolved paths. State the precise supported threat boundary and exclusions, including a compromised operator, cloud/OS administrator or deliberately exporting trusted recipient. Do not claim a universal “never exposed” guarantee.
7. Only after a go decision, the user performs separately authenticated key entry through the operator-owned protected interface. No key goes into this chat, agent-readable commands/environment/files or the pilot kit. Start with one least-privilege, disposable provider scope; verify provider-side expiry/revocation separately. Do not return privileged troubleshooting access to the agent after production keys exist. If such access becomes necessary, first revoke/remove real credentials under operator control and re-establish a keyless development environment.

## Concrete approvals still needed

These are the actions to request when their exact targets are known, not approvals already granted:

- “May we create/configure production environment [account/host] with [stated cost/limit], and install artifact [verified digest] for the canary-only boundary test?”
- “May we change [specific identities, ACLs, transport/proxy/bind settings] on [exact host], and remove [listed agent admin/exec/filesystem/checkpoint/restore routes], while [operator recovery identity] retains control?”
- “May we enroll [specific agent, independent human signer and recipient] with [exact roles/audiences/scopes/expiry], and configure [named custody/recovery/independent-anchor location]?”
- After verified go: “Will you enter [specific provider key] directly into [verified operator-owned interface] for [selected account/repository and minimum permissions]?” This is a user-performed secure handoff; the assistant does not handle the private value.

The synthetic pilot's approved budget does not authorize these production access/security changes or real-key provisioning. Preserve the scoped evidence and stop on an unavailable boundary, uncertain custody, failed revocation or incomplete recovery.
