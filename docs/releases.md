# Downloadable experimental binaries

The [release workflow](../.github/workflows/release.yml) runs when a tag is pushed to GitHub. After every platform passes its native tests, release build and extracted-archive smoke check, it publishes all five downloads together on the repository's [Releases page](https://github.com/NathanaelG1/Aegis/releases). Releases are marked as prereleases while Aegis remains experimental.

## Choose a download

Archive names are `aegis-<tag>-<target>.tar.gz` on Unix and `.zip` on Windows. Each contains one executable, this installation guide, project documentation, licenses and `release.json` with the source commit, package version, target, features, compiler and executable SHA-256.

| OS / CPU | Target | Runtime baseline | Included commands |
| --- | --- | --- | --- |
| Linux x64 | `x86_64-unknown-linux-gnu` | glibc 2.35+ (built/tested on Ubuntu 22.04) | Synthetic CLI, Unix broker/MCP, Sprite demo |
| Linux arm64 | `aarch64-unknown-linux-gnu` | glibc 2.35+ (built/tested on Ubuntu 22.04 arm64) | Synthetic CLI, Unix broker/MCP, Sprite demo |
| macOS Apple Silicon | `aarch64-apple-darwin` | Native runner: macOS 15 | Synthetic CLI, Unix broker/MCP, Sprite demo |
| macOS Intel | `x86_64-apple-darwin` | Native runner: macOS 15 Intel | Synthetic CLI, Unix broker/MCP, Sprite demo |
| Windows x64 | `x86_64-pc-windows-msvc` | Windows 10+ / Server 2022; tested on Server 2022 | `demo`, `synthetic-agent`, help/version |

The Linux downloads use system glibc; Alpine/musl is unsupported. macOS downloads are separate native executables, not a universal binary; older macOS versions are not tested by this workflow. Windows uses the statically linked MSVC runtime. Windows has no Unix socket transport or Sprite service. A downloadable executable does not add those missing interfaces.

## Verify, extract and run

Download your archive and `SHA256SUMS` from the same release. Verify the matching checksum before extraction. On Linux use `sha256sum --ignore-missing --check SHA256SUMS`; on macOS use `shasum -a 256 --ignore-missing --check SHA256SUMS`. On Windows use `Get-FileHash .\aegis-<tag>-x86_64-pc-windows-msvc.zip -Algorithm SHA256` in PowerShell and compare with its line in `SHA256SUMS`.

On Linux or macOS, substitute your tag and target:

```sh
tar -xzf aegis-<tag>-<target>.tar.gz
cd aegis-<tag>-<target>
./aegis --version
./aegis --help
./aegis demo
```

On Windows, extract the ZIP with Explorer or PowerShell's `Expand-Archive`, open PowerShell in the extracted directory, then run:

```powershell
.\aegis.exe --version
.\aegis.exe --help
.\aegis.exe demo
```

No Rust, Cargo, source checkout or administrator installation is required at runtime. Move the executable into a directory on your PATH if desired. The binaries are not distribution-signed or notarized; downloaded macOS and Windows executables may require review through the OS's normal security UI. Checksums detect corruption; they do not provide independent publisher authentication.

For the Linux Sprite installation, use the extracted Linux executable directly:

```sh
./aegis sprite-demo-init --state-dir /home/sprite/aegis-private
./aegis sprite-demo-serve --state-dir /home/sprite/aegis-private --listen 127.0.0.1:7979
```

Follow the included [Sprite guide](sprite-demo.md) for owner/agent credential custody and the owner-managed gateway. Unix archives also include `scripts/sprite_client.py`; Python 3.10+ is required only for that client. The Rust service itself needs no Python. Examples using `cargo` or `target/release/aegis` elsewhere in the documentation describe source builds; substitute the extracted executable for those invocations.

These downloads remain synthetic experiments. They accept no real credentials and do not establish production readiness, protected application delivery or deployed Sprite administrative isolation.

## Publishing a tag

Pull-request CI checks default/all-feature tests and Clippy with warnings denied
on native Linux x86-64/arm64, macOS Intel/Apple Silicon and Windows MSVC runners.
The Windows checks use the release's static-CRT flags. The existing Linux job also
checks documentation. These checks do not build, publish or retag a release;
the tag-triggered release workflow remains separate.

Commit the intended source, lockfile and workflow before tagging. Tag names must contain 1–128 letters, digits, dots, underscores or hyphens, starting with a letter or digit. Prefer `v<package-version>` (for example `v0.1.0-experimental`). The tag identifies the release; `aegis --version` reports the version in `Cargo.toml`, which is also recorded in `release.json`.

```sh
git tag v0.1.0-experimental
git push origin v0.1.0-experimental
```

The workflow installs the toolchain pinned in `rust-toolchain.toml`, uses locked dependencies and native runners, tests default/all features, runs Clippy, verifies the optimized Unix Sprite workflow, then executes the extracted binary's help/version, policy demo and JSON-lines discovery from an empty working directory without Cargo or PATH. Build jobs have read-only repository permissions; only the final publishing job can write a release. It verifies the five archive checksums before creating a draft with all assets and publishing it as a prerelease.

If any platform fails, publication is blocked. Each successful build's archive remains available as an Actions artifact for seven days. A failure after draft creation can leave a draft; inspect/remove that draft before rerunning the publishing job. Existing releases are not overwritten. Tagging and publishing are operator actions; adding this workflow does not create a tag or release by itself.
