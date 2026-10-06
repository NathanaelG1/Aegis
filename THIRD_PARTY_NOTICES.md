# Third-party notices

The [MIT license](LICENSE) applies to first-party Aegis source and documentation. Dependencies retain their original copyright notices, attribution and license terms. Their source or binaries are not vendored in this repository; Cargo obtains the selected packages from their upstream registry sources.

[Cargo.lock](Cargo.lock) pins dependency resolution. The [dependency inventory](docs/dependency-inventory.json) records exact package versions, declared SPDX/license expressions, enabled features and registry source for the observed macOS arm64 configurations: 19 packages by default and 128 with the optional storage spike. These declarations are an inventory, not a completed legal/advisory audit. Preserve upstream license/notice files when redistributing dependency source or packaged binaries; any such packaging needs a per-target notice review.

Direct dependencies are serde 1.0.228 (MIT OR Apache-2.0), serde_json 1.0.145 (MIT OR Apache-2.0), getrandom 0.2.17 (MIT OR Apache-2.0), Unix nix 0.29.0 (MIT), and optional age 0.11.1 (MIT OR Apache-2.0). Public API/documentation references and attribution are maintained in [design references](docs/design-provenance.md). No first-party license replaces third-party obligations.
