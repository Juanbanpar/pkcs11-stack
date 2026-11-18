#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Validation only: no publication, tags, deployment or repository setting changes.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
    '')
        [[ $# == 0 ]] || exit 2
        cargo fmt --all -- --check
        cargo fmt --manifest-path fuzz/Cargo.toml -- --check
        cargo check --workspace --all-targets --locked
        cargo clippy --workspace --all-targets --locked -- -D warnings
        cargo test --workspace --locked
        RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
        python3 tools/check-dependencies.py
        python3 tools/check-advisories.py
        cargo audit --file Cargo.lock
        cargo audit --file fuzz/Cargo.lock
        (cd tools/provider-locks && cargo audit --file kryoptic.Cargo.lock)
        python3 tools/check-packages.py
        cargo check -p pkcs11-rustls-adapter --lib --no-default-features --locked
        cargo check -p pkcs11-rustls-adapter --lib --features tls12 --locked
        ;;
    --packages)
        [[ $# == 1 ]] || exit 2
        python3 tools/check-packages.py
        cargo package -p pkcs11-locator --locked
        ;;
    --providers)
        [[ $# == 1 ]] || exit 2
        : "${PKCS11_TEST_MODULE:?Set the pinned SoftHSM module}"
        : "${PKCS11_TEST_KDF_MODULE:?Set the pinned KDF Kryoptic module}"
        : "${PKCS11_TEST_PQC_MODULE:?Set the pinned PQC Kryoptic module}"
        bash tools/test-softhsm.sh
        bash tools/test-ml-dsa.sh
        bash tools/test-ml-kem.sh
        bash tools/test-kem-hkdf.sh
        bash tools/test-pqc-kryoptic.sh
        ;;
    *) echo 'Usage: check-release-readiness.sh [--packages|--providers]' >&2; exit 2 ;;
esac
