#!/bin/sh
# Native release installer. Owner-controlled GitHub releases are the trust root.
set -eu
umask 077
repo=NathanaelG1/Aegis
case "$(uname -s)" in
  Linux) platform=unknown-linux-gnu ;;
  Darwin) platform=apple-darwin ;;
  *) echo 'Use the Windows ZIP from GitHub Releases on Windows.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) cpu=x86_64 ;;
  aarch64|arm64) cpu=aarch64 ;;
  *) echo 'Unsupported CPU architecture.' >&2; exit 1 ;;
esac
version=${AEGIS_VERSION:-}
if [ -z "$version" ]; then
  # Releases API includes prereleases; GitHub /latest does not.
  version=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/$repo/releases?per_page=20" |
    sed -n 's/.*"tag_name": *"\([A-Za-z0-9._-]*\)".*/\1/p' | head -n 1)
fi
case "$version" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) echo 'Set AEGIS_VERSION to a published release tag.' >&2; exit 1 ;; esac
test "${#version}" -le 128
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
archive="aegis-$version-$cpu-$platform.tar.gz"
base="https://github.com/$repo/releases/download/$version"
curl --proto '=https' --tlsv1.2 -fsSL "$base/$archive" -o "$work/$archive"
curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
awk -v name="$archive" '$2 == name { print }' "$work/SHA256SUMS" > "$work/selected.sha256"
test "$(wc -l < "$work/selected.sha256" | tr -d ' ')" = 1
(
  cd "$work"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum --check selected.sha256; else shasum -a 256 --check selected.sha256; fi
  tar -xzf "$archive"
)
binary="$work/aegis-$version-$cpu-$platform/aegis"
if ! "$binary" --help | grep -q 'proxy --state-dir'; then
  echo 'This release predates the secret proxy. Publish a release containing this change, then set AEGIS_VERSION to that tag.' >&2
  exit 1
fi
destination=${AEGIS_BIN_DIR:-"$HOME/.local/bin"}
mkdir -p "$destination"
install -m 755 "$binary" "$destination/aegis"
printf 'Installed %s to %s/aegis\nOpen guided setup: %s/aegis\n' "$version" "$destination" "$destination"
case ":$PATH:" in
  *":$destination:"*) printf 'You can also run: aegis\n' ;;
  *) printf 'Add %s to your shell PATH to launch it as aegis.\n' "$destination" ;;
esac
