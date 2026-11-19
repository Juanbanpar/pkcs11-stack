#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Inspect intended registry packages without publishing or requiring prerequisites."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
intended = {"pkcs11-locator", "pkcs11-runtime", "pkcs11-client", "pkcs11-rustls-adapter", "pkcs11ctl"}
metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"], cwd=root))
for package in metadata["packages"]:
    name = package["name"]
    if name not in intended:
        if package["publish"] != []:
            raise SystemExit(f"Desktop publication must remain disabled: {name}")
        continue
    if package["publish"] == [] or package["license"] != "MIT OR Apache-2.0":
        raise SystemExit(f"Incorrect publication/license policy: {name}")
    for field in ["description", "repository", "documentation", "readme", "keywords", "categories"]:
        if not package.get(field):
            raise SystemExit(f"Missing {field}: {name}")
    for dependency in package["dependencies"]:
        if dependency.get("path") and dependency["req"] == "*":
            raise SystemExit(f"Missing registry dependency version: {name} -> {dependency['name']}")
    listing = subprocess.check_output(["cargo", "package", "-p", name, "--list", "--locked", "--allow-dirty"], cwd=root, text=True)
    files = set(listing.splitlines())
    required = {"Cargo.toml", "README.md", "LICENSE-MIT", "LICENSE-APACHE", "src/main.rs" if name == "pkcs11ctl" else "src/lib.rs"}
    if not required <= files:
        raise SystemExit(f"Missing package contents: {name}: {required-files}")
    for file in files:
        path = Path(file)
        if any(part in {"target", ".git", "corpus", "artifacts"} for part in path.parts) or path.suffix in {".pin", ".key", ".pem", ".db", ".sql", ".sqlite", ".so", ".dll", ".dylib", ".crate"}:
            raise SystemExit(f"Unexpected sensitive/generated package file: {name}: {file}")
    directory = Path(package["manifest_path"]).parent
    for license in ["LICENSE-MIT", "LICENSE-APACHE"]:
        if (directory / license).read_bytes() != (root / license).read_bytes():
            raise SystemExit(f"License differs from workspace: {name}: {license}")
    for fixture in (directory / "tests/fixtures").rglob("*"):
        if fixture.is_file() and name in {"pkcs11ctl", "pkcs11-rustls-adapter"}:
            original = root / "crates/pkcs11-client/tests/fixtures" / fixture.relative_to(directory / "tests/fixtures")
            if fixture.read_bytes() != original.read_bytes():
                raise SystemExit(f"Public fixture drift: {fixture}")
    print(f"{name} {package['version']}: metadata, {len(files)} listed files, licenses and public fixtures verified")
print("Inspection only: registry build verification and publish --dry-run remain separate release-review gates.")
