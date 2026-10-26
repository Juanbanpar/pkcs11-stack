#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PKCS11_TEST_MODULE:?Set PKCS11_TEST_MODULE to the ML-DSA SoftHSM build; see tests/README.md}"
: "${PKCS11_TEST_KDF_MODULE:?Set PKCS11_TEST_KDF_MODULE to the Kryoptic build; see tests/README.md}"
cargo test --workspace --locked
bash tools/test-softhsm.sh
bash tools/test-ml-dsa.sh
bash tools/test-ml-kem.sh
bash tools/test-hkdf.sh
bash tools/test-kem-hkdf.sh
