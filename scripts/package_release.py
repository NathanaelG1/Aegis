#!/usr/bin/env python3
"""Package a native Cargo release, then execute the extracted download in isolation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "x86_64-unknown-linux-gnu": "sprite-demo",
    "aarch64-unknown-linux-gnu": "sprite-demo",
    "x86_64-apple-darwin": "sprite-demo",
    "aarch64-apple-darwin": "sprite-demo",
    "x86_64-pc-windows-msvc": "",
}


def smoke_test(directory, executable, version, features):
    binary = (directory / executable).resolve()
    # An empty working directory and no PATH/HOME/Cargo variables ensure that the
    # packaged CLI does not depend on the checkout or a runtime Rust installation.
    clean_env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    with tempfile.TemporaryDirectory(prefix="aegis-run-") as working:
        def run(*args, input=""):
            result = subprocess.run(
                [str(binary), *args], input=input, text=True, capture_output=True,
                cwd=working, env=clean_env, timeout=30, check=True,
            )
            return result.stdout

        if f"aegis {version} (synthetic-only)" not in run("--version"):
            raise RuntimeError("packaged executable has an unexpected version")
        help_text = run("--help")
        if "synthetic-agent" not in help_text:
            raise RuntimeError("packaged executable lacks CLI help")
        if ("sprite-demo-serve" in help_text) != (features == "sprite-demo"):
            raise RuntimeError("packaged executable has unexpected Sprite features")
        demo = run("demo")
        if "provider dispatches=1 remaining_uses=19" not in demo:
            raise RuntimeError("packaged policy demo did not complete")
        request = {"version": 1, "action": {"method": "discover_operations"}}
        response = json.loads(run("synthetic-agent", input=json.dumps(request) + "\n"))
        if response["error"] is not None or not response["result"]:
            raise RuntimeError("packaged JSON-lines agent discovery failed")
        if list(Path(working).iterdir()):
            raise RuntimeError("packaged CLI unexpectedly wrote working-directory files")


def package(tag, target, features):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag):
        raise ValueError("release tags must use 1-128 letters, digits, dots, underscores or hyphens")
    if features != TARGETS[target]:
        raise ValueError("release features must match the documented platform build")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    executable = "aegis.exe" if "windows" in target else "aegis"
    source = ROOT / "target" / target / "release" / executable
    name = f"aegis-{tag}-{target}"
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aegis-package-") as temporary:
        staging = Path(temporary) / name
        staging.mkdir()
        shutil.copy2(source, staging / executable)
        if executable == "aegis":
            (staging / executable).chmod(0o755)
        for filename in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "SECURITY.md"):
            shutil.copy2(ROOT / filename, staging / filename)
        shutil.copytree(ROOT / "docs", staging / "docs")
        (staging / "INSTALL.md").write_text(
            "# Run Aegis\n\n"
            "Run `./aegis --help` on Linux/macOS or `.\\aegis.exe --help` in Windows PowerShell.\n"
            "Run `./aegis demo` (Windows: `.\\aegis.exe demo`) for the synthetic policy demo.\n\n"
            "See [installation and platform limits](docs/releases.md) for checksums, "
            "runtime requirements and Sprite setup. No Rust installation is required.\n"
        )
        if features:
            (staging / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/sprite_client.py", staging / "scripts/sprite_client.py")
        metadata = {
            "tag": tag, "package_version": version, "target": target,
            "features": features.split(",") if features else [],
            "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "rustc": subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip(),
            "binary_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "distribution_signed": False,
        }
        (staging / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if executable.endswith(".exe"):
            archive = dist / f"{name}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for entry in sorted(staging.rglob("*")):
                    if entry.is_file():
                        output.write(entry, entry.relative_to(staging.parent))
        else:
            archive = dist / f"{name}.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(staging, arcname=name)
        extracted = Path(temporary) / "extracted"
        extracted.mkdir()
        if executable.endswith(".exe"):
            with zipfile.ZipFile(archive) as packaged:
                packaged.extractall(extracted)
        else:
            with tarfile.open(archive) as packaged:
                packaged.extractall(extracted, filter="data")
        extracted_binary = extracted / name / executable
        if hashlib.sha256(extracted_binary.read_bytes()).hexdigest() != metadata["binary_sha256"]:
            raise RuntimeError("archive extraction changed the executable")
        smoke_test(extracted / name, executable, version, features)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    # Text mode translates LF to CRLF on Windows; checksum manifests are read
    # by the Linux publish job and must use the same bytes on every platform.
    archive.with_name(archive.name + ".sha256").write_bytes(
        f"{checksum}  {archive.name}\n".encode("ascii")
    )
    print(f"Packaged and verified {archive.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--features", required=True)
    args = parser.parse_args()
    package(args.tag, args.target, args.features)
