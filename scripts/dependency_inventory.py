"""Produce target/feature-specific dependency evidence, without audit claims.

Run from the root: python3 scripts/dependency_inventory.py
No package installation or network calls: Cargo metadata uses --offline --locked.
"""
import json
import argparse
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
host = next(line.split(": ", 1)[1] for line in subprocess.check_output(["rustc", "-vV"], cwd=ROOT, text=True).splitlines() if line.startswith("host: "))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", default=host, help="Metadata target only; this does not build or test that platform")
parser.add_argument("--output", default=str(ROOT / "docs" / "dependency-inventory.json"), help="Inventory destination; use a distinct name to retain earlier platform evidence")
parser.add_argument("--signing", action="store_true", help="Also record optional signing and combined feature graphs")
args = parser.parse_args()
TARGET = args.target
output = {"target": TARGET, "configurations": {}}
configurations = [("default", []), ("storage-spike", ["--features", "storage-spike"])]
if args.signing:
    configurations += [("signing-spike", ["--features", "signing-spike"]), ("all-features", ["--all-features"])]
for name, extra in configurations:
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", TARGET, *extra,
    ], cwd=ROOT))
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    reached = set()
    pending = [metadata["resolve"]["root"]]
    while pending:
        package_id = pending.pop()
        if package_id in reached:
            continue
        reached.add(package_id)
        pending.extend(nodes[package_id]["dependencies"])
    output["configurations"][name] = sorted([
        {"name": packages[key]["name"], "version": packages[key]["version"],
         "license": packages[key]["license"], "features": nodes[key]["features"],
         "rust_version": packages[key]["rust_version"],
         "source": packages[key]["source"]}
        for key in reached if packages[key]["source"] is not None
    ], key=lambda item: (item["name"], item["version"]))
path = pathlib.Path(args.output)
path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
print("Wrote target-specific dependency inventory:", path)
for name, packages in output["configurations"].items():
    print(name, "dependency packages:", len(packages))
