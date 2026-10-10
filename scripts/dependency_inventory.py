"""Produce target/feature-specific dependency evidence, without audit claims.

Run from the root: python3 scripts/dependency_inventory.py
No package installation or network calls: Cargo metadata uses --offline --locked.
"""
import json
import argparse
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
host = next(line.split(": ", 1)[1] for line in subprocess.check_output(["rustc", "-vV"], cwd=ROOT, text=True).splitlines() if line.startswith("host: "))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", default=host, help="Metadata target only; this does not build or test that platform")
parser.add_argument("--output", default=str(ROOT / "docs" / "dependency-inventory.json"), help="Inventory destination; use a distinct name to retain earlier platform evidence")
parser.add_argument("--signing", action="store_true", help="Also record optional signing and combined feature graphs")
parser.add_argument("--application-slot", action="store_true", help="Also record vault-only and fixed application-slot feature graphs")
args = parser.parse_args()
TARGET = args.target
output = {"target": TARGET, "selection": "cargo tree normal/build/dev graph; not a compilation attestation", "configurations": {}}
configurations = [("default", []), ("storage-spike", ["--features", "storage-spike"])]
if args.signing or args.application_slot:
    configurations.append(("signing-spike", ["--features", "signing-spike"]))
if args.application_slot:
    configurations += [("vault-spike", ["--features", "vault-spike"]), ("application-slot", ["--features", "application-slot"])]
if args.signing or args.application_slot:
    configurations.append(("all-features", ["--all-features"]))
for name, extra in configurations:
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", TARGET, *extra,
    ], cwd=ROOT))
    packages = {package["id"]: package for package in metadata["packages"]}
    # Metadata resolution can contain packages not selected for compilation.
    # Use Cargo's target/feature tree for selection and feature evidence instead
    # of recursively treating every resolved node as part of the active graph.
    tree = subprocess.check_output([
        "cargo", "tree", "--locked", "--offline", "--target", TARGET,
        "--edges", "normal,build,dev", "--no-dedupe", "--prefix", "none",
        "--format", "{p}|{f}", *extra,
    ], cwd=ROOT, text=True)
    reached = {}
    for line in tree.splitlines():
        display, features = line.split("|", 1)
        match = re.match(r"^(\S+) v(\S+)(?: |$)", display)
        if not match:
            raise ValueError(f"Unsupported cargo tree package display: {display}")
        matches = [key for key, package in packages.items()
                   if (package["name"], package["version"]) == match.groups()]
        if len(matches) != 1:
            raise ValueError(f"Ambiguous cargo tree package identity: {display}")
        reached.setdefault(matches[0], set()).update(filter(None, features.split(",")))
    output["configurations"][name] = sorted([
        {"name": packages[key]["name"], "version": packages[key]["version"],
         "license": packages[key]["license"], "features": sorted(reached[key]),
         "rust_version": packages[key]["rust_version"],
         "source": packages[key]["source"]}
        for key in reached if packages[key]["source"] is not None
    ], key=lambda item: (item["name"], item["version"]))
path = pathlib.Path(args.output)
path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
print("Wrote target-specific dependency inventory:", path)
for name, packages in output["configurations"].items():
    print(name, "dependency packages:", len(packages))
