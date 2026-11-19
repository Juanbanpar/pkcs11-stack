#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Require explicit review of changes to the audit exceptions."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parent.parent
policies = {
    ".cargo/audit.toml": {"RUSTSEC-2023-0071", "RUSTSEC-2026-0387", "RUSTSEC-2026-0385"},
    "tools/provider-locks/.cargo/audit.toml": {"RUSTSEC-2026-0459"},
}
for name, expected in policies.items():
    policy = tomllib.loads((root / name).read_text())
    actual = policy.get("advisories", {}).get("ignore", [])
    if set(actual) != expected or len(actual) != len(expected):
        raise SystemExit(f"Audit exceptions changed without a policy review: {name}")
    if set(policy.get("output", {}).get("deny", [])) != {"unsound", "yanked"}:
        raise SystemExit(f"Audit denial policy changed: {name}")
    print(f"{name}: accepted exceptions {', '.join(sorted(expected))}")
