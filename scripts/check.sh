#!/bin/sh
# Run from the repository root. Uses the pinned local toolchain and lockfile.
set -eu
cargo fmt --check
cargo test --locked --offline --all-targets
cargo test --locked --offline --all-features --all-targets
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --offline --all-features --no-deps
