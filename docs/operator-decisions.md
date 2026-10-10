# Operator decisions for protected entry

**Design choices only. Live entry remains NO-GO.** The
[two-import composition](composed-canary-rotation.md) addresses the remaining
fixed-canary dataflow question. To choose and implement actual operational
adapters, answer the six questions below. No passwords, private keys, tokens or
recovery material are needed in these answers.

The use case is settled: NathanaelG1's GitHub App on selected personal
repositories. Its private key stays in broker sign-only custody; the fixed
recipient receives a short-lived token for one repository and metadata read.
Exact App/installation/account/repository IDs come during enrollment.

## Recommended starting architecture

Keep the agent on a separate machine. Use one operator-controlled Linux x86_64
host/VM for distinct broker and recipient service identities, a pinned protected
installation and one recipient-only credential file. Give the agent only the
authenticated, narrowly authorized application endpoint. Use an independent
human device/client for exact review, signing and manual custody unlock, plus
recovery material and an authoritative rollback/fencing anchor outside the
host's restore domain. Start with explicit unlock and one approved operation;
defer unattended unlock/renewal and same-host agent execution.

No custody product or deployment is validated here. “No administrator access”
alone is insufficient: same-UID execution, process/debug/descriptor access,
files, mutable application configuration, logs/backups, service updates and
control-plane routes can still expose or replace trusted components.

## Six choices to return

1. **Host:** Which existing/proposed Linux x86_64 host/VM, operator/control-plane
   owner, OS/version and local filesystem? Recommended: a dedicated
   operator-controlled target without agent host/control-plane credentials.
2. **Agent access:** Which separate agent machine/client and retained
   tools/accounts? Include shell, files/processes, service/deploy controls,
   dashboards, backups and recovery. Recommended: only the enrolled Aegis
   application endpoint reaches the target; independently verify exclusions.
3. **Recipient:** Which fixed application/build, distinct service identity and
   protected slot? Who controls its binary, dependencies, service/startup
   environment, configuration and parent directories? Recommended: the fixed
   GitHub metadata recipient with a pinned installation and one protected file,
   without agent-written configuration or automatic deployment of agent builds.
4. **Custody/unlock:** Any hardware/offline requirements, unlock constraints or
   existing key store? Is manual per-session unlock from the independent human
   client acceptable? Recommended: independent role stores, sign-only App-key
   use, exact-version approval for rotation and no unattended release. “No
   preference; recommend after host/client choices” is sufficient; use those
   facts to select a suitable backend before implementing its adapter.
5. **Human approval:** Which device/client displays the exact plan and uses the
   human signer? Can agent tools read or automate it? Recommended: a separate
   operator-controlled device/client outside agent read/automation, with
   approval distinct from unlock. Say if the client needs implementation.
6. **Recovery/anchor:** Who will own recovery, and what separately controlled
   account/host is available outside the broker/recipient restore domain?
   Recommended: independently retained recovery material and an authenticated
   generation/fencing authority outside agent access and the host backup set.
   Use the available account/host to propose the exact anchor adapter. Offline
   backups alone do not provide fencing or authoritative current state; another
   file or volume in the same restore domain is insufficient.

“Unknown” with the person who can decide is a useful answer. Resolve those
unknowns to select one bounded implementation target, including authenticated
transport and trusted time. More synthetic drills cannot make these choices.

## Later actions need their own approval

Answering selects a design; it does not approve provisioning or costs, creating
credentials, granting persistent access, changing security/network settings,
starting a listener/service, deploying code, enrolling identities, sharing
files or entering real material. Prepare those exact actions and consequences
for separate approval under the [operator trial plan](operator-live-trial-plan.md#4-operator-choices-and-later-action-approvals).
The operator enters any real App key directly through the verified protected
interface; it must never pass through the agent or chat.

The protected entry/custody and isolated-recipient implementations remain
missing. Deployment measurements, canary acceptance and a separate live go
decision remain necessary. The previously stopped independent adversarial
review remains unresolved; these choices neither restart nor replace it.
