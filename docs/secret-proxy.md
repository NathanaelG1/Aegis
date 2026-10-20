# Service-scoped secret injection

Aegis can run on an owner-controlled host while agents administer applications on
other hosts. An application authenticates with its own Aegis service token and
names the secret references required by an operation. Aegis checks that service's
ACL, loads the encrypted credentials, injects them into approved HTTP headers, and
sends the request to the configured HTTPS endpoint. The application receives the
status and explicitly selected JSON fields, never a secret-export response.

This is a generic HTTP access pattern. It supports API-key and bearer-token header
authentication. It does not implement provider-specific signing, arbitrary TLS
tunnelling, SDK emulation, wallet signing, or business-level spending controls.
An application whose provider requires request signatures needs an independently
designed signing adapter; header injection alone cannot authenticate those calls.

## Install

Linux x64/ARM64 and macOS Intel/Apple Silicon releases include the proxy and native
HTTP/MCP client. Linux requires glibc 2.35+. Windows downloads retain the synthetic
CLI; the owner-hosted service is Unix-only.

After a release containing this feature is published:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/NathanaelG1/Aegis/main/install.sh | sh
```

The installer selects the newest public release, including prereleases, verifies
the platform archive against `SHA256SUMS`, and installs the native executable to
`~/.local/bin/aegis`. It refuses older releases without proxy support. v0.0.3 does
not contain this feature. Publishing a new tag is required before the public
one-line install can provide it. Checksums detect corrupted downloads; both the
script and release assets rely on the GitHub repository owner's integrity. They
are not independent signatures. For reviewed deployments, pin the script URL to
a reviewed commit/tag and set `AEGIS_VERSION` to that published tag.

No Rust installation, language runtime, or dependency installation is required on
the host. `curl`, `tar`, and a system SHA-256 utility are used during installation.
To build this checkout now:

```sh
cargo build --release --locked --features proxy --bin aegis
./target/release/aegis
```

Use `~/.local/bin/aegis` below, or substitute `./target/release/aegis` for a source
build. Add `~/.local/bin` to your PATH if you want to use the short `aegis` command.

## Guided terminal setup

Run **aegis** with no arguments in an interactive terminal. The Linux/macOS
proxy builds open a fullscreen owner console with an ASCII shield logo, keyboard
menus and guided forms. No additional terminal library or runtime is installed.

1. Choose **Set up a private vault**. The default is `~/.aegis`; you can choose
   another absolute folder through the UI. Existing vaults open the dashboard.
2. Choose **Add a secret**, give it a reference name, and paste its value into
   the hidden field. The value never appears in the UI or terminal scrollback.
3. Choose **Connect a service** and name your application.
4. In the policy editor, **Add an operation**. Enter the provider's exact HTTPS
   endpoint, choose its HTTP method and the secret to inject. Choose Bearer token,
   API-key header, raw Authorization, or a custom header/prefix.
5. Optionally select safe JSON response fields and non-secret request headers.
   The default response contains only the HTTP status. Set a total call allowance,
   then **Review and save policy**. Nothing is saved until you confirm.
6. Choose **Start proxy**, select the local port, then use **Connection guide**
   to connect the application through your trusted gateway.

**Manage services & policies** edits saved policies, pauses/enables services,
rotates app tokens and shows each app's private token-file location. **Manage
secrets** replaces or removes values without revealing them. **Vault settings**
shows custody/backup guidance and lets you open another vault.

Arrow keys or j/k move through menus; Enter selects; Esc cancels or goes back.
Ctrl-U clears a form field and Backspace edits it. Text entry accepts ASCII;
provider URLs with non-ASCII characters should use their encoded form. Paste
requires a terminal supporting bracketed paste (normal modern SSH terminals do).
Pasted newlines do not submit forms. Oversized/unsupported pastes are rejected,
and secret fields remain hidden. Review pages scroll, wrap long URLs/paths and
adapt to terminal size; `NO_COLOR=1` disables color.

The console uses the same policy validation and encrypted vault as the CLI.
It is an owner-local interface, not a remote administration API or a new source
of authority. Keep the Aegis host out of your agent's administrative reach.
Starting a proxy is local only; it does not create a gateway, public URL or
background service. The console owns that child process and stops it on normal
exit, after confirmation. Existing proxies started elsewhere are not managed
or reported as running by this console. For unattended operation, use the
supervisor instructions below. Killing a request in flight can leave an unknown
outcome; reconcile it with the provider before issuing a new request ID.

For automation, all explicit commands remain available. Piped no-argument
invocations print plain usage rather than opening a fullscreen interface.
`aegis tui --state-dir /absolute/folder` explicitly opens a particular vault.
The UI requires an interactive terminal and a non-dumb TERM setting; Windows
and builds without the proxy feature retain their existing CLI behavior.

## Scriptable owner provisioning

Run these commands in the private owner terminal on the Aegis host:

```sh
~/.local/bin/aegis proxy --state-dir "$HOME/.aegis" init
~/.local/bin/aegis proxy --state-dir "$HOME/.aegis" secret-put service-api-key
```

The second command prompts without echo. Never paste the value into a command
argument, chat, source file, or application environment. Automation can feed the
value through a protected stdin pipe with `secret-put NAME --stdin`; stdin is
bounded and only trailing line endings are removed. Secrets must be 8–4096 bytes
and valid HTTP header values. Use a new directory for initialization; existing
state is never replaced.

Save a policy such as this as `service-policy.json`, replacing the example URL
and response pointers with the actual provider's documented interface:

```json
{
  "allowed_secrets": ["service-api-key"],
  "max_calls": 1000,
  "operations": {
    "create-message": {
      "url": "https://api.example.com/v1/messages",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "secrets": {
        "service-api-key": {"header": "Authorization", "prefix": "Bearer "}
      },
      "response_fields": {"message_id": "/id", "state": "/status"}
    }
  }
}
```

```sh
~/.local/bin/aegis proxy --state-dir "$HOME/.aegis" service-add my-app service-policy.json
~/.local/bin/aegis proxy --state-dir "$HOME/.aegis" serve 127.0.0.1:7980
```

`service-add` writes a fresh 256-bit service credential to
`$HOME/.aegis/my-app.token`, mode 0600. Transfer **only this scoped service token**
to the application's host using your private administration channel. Do not copy
the Aegis state directory, `identity.key`, or provider secrets there. One service
can be granted multiple secret references and operations; each service has an
independent token, ACL, enabled state, and durable call counter.

The policy fixes the complete URL, method, header names/prefixes and response
projection. This prevents a caller from redirecting a credential to its own
server, changing Host, requesting another secret, or adding an arbitrary signing
or export operation. Request bodies remain application-controlled JSON. Do not
authorize an endpoint whose body can request credential export, forward privileged
requests elsewhere, or perform operations beyond the service's intended authority.

## Connect the two hosts

Keep Aegis on the owner-only Sprite, outside the agent's administrative reach.
The service listens only on loopback. Route it through an owner-managed HTTPS
reverse proxy or private encrypted tunnel. TLS termination must be on trusted
infrastructure; it must preserve the Authorization header and must not log
headers or bodies. Keep the plaintext loopback port private. An example Caddy
site for an owner-controlled hostname is:

```caddyfile
aegis.example.com {
    reverse_proxy 127.0.0.1:7980
}
```

Provision the hostname/certificate and Sprite routing separately. The installer
does not provision infrastructure or start a public endpoint. A Sprite platform
URL must have authenticated TLS forwarding configured to this loopback service;
merely setting an environment variable does not establish that routing. The
application's Aegis token is still required even on a private network.

To keep the foreground process alive on Linux with systemd, install it for a
dedicated owner-controlled service user and use a unit like this (replace paths):

```ini
[Unit]
Description=Aegis secret injection proxy
After=network-online.target
[Service]
User=aegis
ExecStart=/opt/aegis/aegis proxy --state-dir /var/lib/aegis serve 127.0.0.1:7980
Restart=on-failure
UMask=0077
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aegis
[Install]
WantedBy=multi-user.target
```

On Sprites without systemd, use the platform's process supervisor with the same
foreground command and private state directory. Keep service administration,
snapshots, terminal access, updates and TLS configuration owner-only. An agent
with root/control-plane access to Aegis's host can recover secrets; file modes
and encryption cannot protect against that administrator.

## Application: request secret injection

Send JSON to `POST /v1/proxy` with `Authorization: Bearer <service-token>`:

```json
{
  "request_id": "job-20261018-001",
  "operation": "create-message",
  "inject": ["service-api-key"],
  "body": {"message": "Hello"}
}
```

For a local tunnel, this shell example keeps the service token out of curl's
process arguments (the token remains readable to an agent controlling this app):

```sh
printf 'Authorization: Bearer %s\n' "$(cat "$HOME/.config/my-app/aegis.token")" |
  curl --fail-with-body --header @- --header 'Content-Type: application/json' \
    --data '{"request_id":"job-001","operation":"create-message","inject":["service-api-key"],"body":{"message":"Hello"}}' \
    https://aegis.example.com/v1/proxy
```

The `inject` set must exactly match the operation's configured secret references.
The client cannot change the injection location or destination. A success looks
like `{"status":200,"fields":{"message_id":"msg-123","state":"queued"}}`.
Empty `response_fields` returns only the upstream status. Non-success responses
return only their status: bodies, redirect locations, cookies and headers are
withheld. No redirect is followed, ambient proxy settings are ignored, TLS
certificates are verified, and the HTTP transport does not retry.

The same service and `request_id` may be retried with the exact same operation,
secret references and body: the retained result is returned without another
dispatch. A conflicting request is denied. An interrupted request can return
`upstream_outcome_unknown_do_not_retry_with_new_id`; inspect the provider before
starting any new operation. This is durable at-most-once dispatch for the retained
ID, not an exactly-once guarantee about the provider's side effect.

## Rotation, revocation and recovery

```sh
# Replace the provider secret through the hidden prompt; new requests use it.
aegis proxy --state-dir "$HOME/.aegis" secret-put service-api-key
# Revoke one application's authority immediately for subsequent requests.
aegis proxy --state-dir "$HOME/.aegis" service-disable my-app
# Rotate the scoped token, then privately transfer the new my-app.token file.
aegis proxy --state-dir "$HOME/.aegis" service-rotate my-app
# Review/replace permissions without resetting charged calls or replay history.
aegis proxy --state-dir "$HOME/.aegis" service-set my-app service-policy.json
aegis proxy --state-dir "$HOME/.aegis" service-enable my-app
aegis proxy --state-dir "$HOME/.aegis" status
```

Disabling access cannot recall an already-dispatched request. Call limits count
dispatch intents, including failed/uncertain attempts; increasing `max_calls` is
an owner decision. The encrypted journal is bounded to 10,000 retained IDs and a
4 MiB state envelope; capacity exhaustion fails closed. There is no automatic
pruning that could silently permit an old request to execute again.

The vault uses age X25519 authenticated encryption, a separately stored private
identity, private directory/file modes, cross-process locks, atomic replacement,
and file/directory fsync. The complete state, including credentials, permissions,
call counters and retained results, is encrypted. Secret values have no owner or
agent export command. Owner administration is local CLI only.

Stop the service before backing up the directory. Protect both `identity.key`
and `vault.age` in owner-only encrypted backups; losing the identity loses access.
Recovery restores the **whole matching state**, not just the credential values.
Never restore an old counter/journal snapshot and resume writes without reconciling
later provider effects: rollback can restore spent authority. Backups and Sprite
snapshots retain old credentials even after rotation/deletion. Disk encryption
does not make deleting a file secure erasure. Host root, same-UID processes,
memory inspection and compromised trusted dependencies remain outside this boundary.

## Output and validation boundary

Only selected JSON pointers are released. Known raw/JSON-escaped/base64/hex/percent
encodings of injected secrets are withheld as defense in depth. This is not proof
against arbitrary encoding, splitting, covert channels, or a malicious upstream.
Choose a trusted provider and narrowly scoped response fields; do not select echo,
debug, credential, signing-material or arbitrary request-header fields. Scoped
provider credentials reduce both disclosure and operation authority.

`cargo test --all-features proxy::tests` exercises encrypted persistence,
permissions and links, tamper rejection, ACLs, TLS certificate validation, real
local TLS header injection, response projection, secret echoes, redirects,
rotation/revocation, durable retry behavior and unknown outcomes. These use
disposable fixtures, not an operational provider credential or deployed Sprite.
Run the full `sh scripts/check.sh` before release. A passing local test does not
establish host isolation or third-party provider semantics.

## Dependencies and build cost

The proxy reuses age for authenticated encryption, Hyper/Axum/Tokio for HTTP,
Rustls with the existing AWS-LC backend for TLS, SHA-256 for token hashes and
request fingerprints, and existing zeroize/base64/nix support. The small connector
in this repository supplies the fixed destination, no-redirect, no-retry behavior;
cryptography and HTTP parsing remain established library implementations.

Compared with the previous all-feature lockfile, four packages are added:
`tokio-rustls` (TLS/async adapter), `webpki-roots` (Mozilla CA roots), and Hyper's
`want`/`try-lock` helpers. There is no additional HTTP client framework, password
prompt package, database server, Python runtime, or provider SDK. CA roots are
compiled into the binary and require binary updates as the trust store changes.
The standard library handles private file locking and atomic persistence; existing
nix terminal support hides owner input. `xtask` reuses serde_json and sha2.

Building the proxy requires the Rust toolchain and a native C/C++ build environment
for AWS-LC (including CMake where required by its build). Prebuilt installations
require no compiler or external OpenSSL installation. The default synthetic feature
set remains small; `--features proxy` explicitly enables this functionality.
