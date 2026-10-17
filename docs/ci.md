# Linux continuous integration

[The workflow](../.github/workflows/ci.yml) runs one bounded Ubuntu 24.04 x86_64
job for pull requests, pushes to `main`, and manual dispatches. It uses exact
Rust 1.96.1, matching `rust-toolchain.toml`, with rustfmt and Clippy installed by
the hosted runner's existing rustup. Superseded runs of the same event/ref are
cancelled; each job has a 20-minute timeout.

## Checks and scope

CI fetches the locked Linux dependency graph explicitly, then enables Cargo
offline mode for every check. It mirrors [scripts/check.sh](../scripts/check.sh):
formatting, complete default/all-feature all-target suites, Clippy with warnings
denied, and all-feature rustdoc with warnings denied. Separate default and
all-feature doctest commands cover examples omitted by `--all-targets`; the
starting source has **21 all-feature doctests**. Each quality-check step still
runs if another check fails, without masking the failing result.

No listener tests are skipped: all 21 Unix interface cases are included in each
feature configuration. A successful hosted run would supply Linux regression
evidence for its exact source on the recorded runner, including listener cases
that the restricted development workspace cannot bind. The workflow's existence
is not evidence that a hosted run passed. Cargo offline mode prevents dependency
downloads during checks; it is not a network sandbox for build scripts or tests.

Tests use synthetic fixtures. They do not verify protected human presence,
separate operating-system identities, hostile-agent containment, external
rollback protection, real credentials, live provider calls, production
application delivery, macOS, or Windows. Read the remaining gates in
[verification](verification.md).

## Provenance and permissions

Pull requests test the exact `pull_request.head.sha`, rather than GitHub's
generated merge commit. Push/manual runs test their event SHA. The job checks
`git rev-parse HEAD` against that value and logs both source and event SHAs,
OS/kernel, compiler/Cargo versions, and the lockfile hash. This is head-source
regression coverage, not a separate test of merging with the base branch.

This workflow was prepared from published source
`01ba7ad9628afd1f1783f7b764bd9f2a929c6971`. The 8 October local runtime record in
`verification.md` applies to runtime `1e606c462f14d13e85e5df34e241a6e602bd39c7`;
that runtime's local listener failures remain failures. Earlier private-pilot
passes apply only to their recorded older sources. A later published CI commit
must be checked against its own hosted run and logged source SHA before claiming
a pass. The rolling `ubuntu-24.04` image is not an immutable OS image; the run's
setup log records its actual runner image version.

The only action is official `actions/checkout`, pinned to full commit
`3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1). Its built-in token has only
`contents: read`, and checkout credentials are not persisted for later steps.
There are no repository secrets, third-party toolchain/cache actions, deployment
steps, write scopes, permission changes, or external-service provisioning.

Primary sources checked on 8 October 2026:

- [Official checkout v7.0.1 release](https://github.com/actions/checkout/releases/tag/v7.0.1)
  and [pinned source commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).
- [Checkout inputs and runtime](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml),
  including `persist-credentials`, Node 24, and exact source selection.
- [GitHub workflow hardening](https://docs.github.com/en/actions/reference/security/secure-use)
  and [Ubuntu 24.04 runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).
- [Rustup toolchains](https://rust-lang.github.io/rustup/concepts/toolchains.html)
  and [Cargo test target selection](https://doc.rust-lang.org/cargo/commands/cargo-test.html).
