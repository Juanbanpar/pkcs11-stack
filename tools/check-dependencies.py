#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check workspace architecture against the actual locked Cargo graph."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
members = set(metadata["workspace_members"])
allowed = {
    "pkcs11-locator": set(),
    "pkcs11-runtime": {"pkcs11-locator"},
    "pkcs11-client": {"pkcs11-runtime", "pkcs11-locator"},
    "pkcs11ctl": {"pkcs11-client", "pkcs11-locator"},
    "pkcs11-desktop": {"pkcs11-client"},
    "pkcs11-rustls-adapter": {"pkcs11-runtime", "pkcs11-locator"},
}
for ident in members:
    name = packages[ident]["name"]
    direct = {packages[d]["name"] for d in nodes[ident]["dependencies"]}
    siblings = {packages[d]["name"] for d in nodes[ident]["dependencies"] if d in members}
    if not siblings <= allowed[name]:
        raise SystemExit(f"Forbidden sibling dependencies for {name}: {siblings - allowed[name]}")
    if "cryptoki" in direct and name != "pkcs11-runtime":
        raise SystemExit(f"Only runtime may directly consume cryptoki: {name}")
    if name == "pkcs11ctl" and "pkcs11-client" not in direct:
        raise SystemExit("CLI must reuse client")
    if name == "pkcs11-desktop" and "pkcs11-client" not in direct:
        raise SystemExit("Desktop must reuse client")
    visited, pending = set(), [ident]
    while pending:
        current = pending.pop()
        if current not in visited:
            visited.add(current)
            pending.extend(nodes[current]["dependencies"])
    transitive = {packages[d]["name"] for d in visited}
    if name != "pkcs11-desktop" and {"pkcs11-desktop", "iced"} & transitive:
        raise SystemExit(f"Desktop dependency outside desktop: {name}")
    if name != "pkcs11-rustls-adapter" and {"rustls", "rustls-pki-types", "rustls-webpki"} & transitive:
        raise SystemExit(f"TLS dependency outside adapter: {name}")
    if name != "pkcs11ctl" and {"pkcs11ctl", "clap"} & transitive:
        raise SystemExit(f"CLI dependency in a library: {name}")
    if name == "pkcs11-desktop":
        for dependency in visited:
            package = packages[dependency]["name"]
            features = set(nodes[dependency]["features"])
            if package == "iced" and ("tokio" in features or "thread-pool" not in features):
                raise SystemExit("Desktop must use the thread-pool executor")
            if package in {"iced", "iced_winit", "winit"} and "x11" in features:
                raise SystemExit(f"X11 backend enabled in {package}; Linux desktop requires Wayland")
            if package == "iced_fonts" and features - {"default", "advanced_text"} != {"lucide"}:
                raise SystemExit(f"Unexpected desktop icon fonts: {features}")
            if package == "iced_aw" and features != {"badge", "spinner"}:
                raise SystemExit(f"Unexpected desktop component features: {features}")
    if name == "pkcs11-locator" and "cryptoki" in transitive:
        raise SystemExit("Locator cannot depend on cryptoki")
    production, pending = set(), [ident]
    while pending:
        current = pending.pop()
        if current not in production:
            production.add(current)
            pending.extend(d["pkg"] for d in nodes[current]["deps"]
                           if any(k["kind"] in (None, "build") for k in d["dep_kinds"]))
    testing_tools = {"proptest", "libfuzzer-sys"} & {packages[d]["name"] for d in production}
    if testing_tools:
        raise SystemExit(f"Testing tools in production dependencies for {name}: {testing_tools}")
production = subprocess.check_output(
    ["cargo", "tree", "-p", "pkcs11-rustls-adapter", "--locked",
     "--no-default-features", "--edges", "normal,build", "--prefix", "none", "--format", "{p}"],
    cwd=root, text=True,
)
production_names = {line.split()[0] for line in production.splitlines() if line}
if {"ring", "aws-lc-rs", "aws-lc-sys"} & production_names:
    raise SystemExit("Adapter production dependencies must not select a software TLS provider")
print("Workspace dependency boundaries, desktop features and provider-free adapter verified")
