#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
: "${PKCS11_TEST_KDF_MODULE:?Set the pinned Kryoptic KDF module}"
if [[ ! -f "$PKCS11_TEST_KDF_MODULE" || $(basename "$PKCS11_TEST_KDF_MODULE") != libkryoptic_pkcs11.so ]]; then
    echo 'Use the trusted pinned Kryoptic module.' >&2; exit 2
fi
source tools/softhsm-store.sh
# Both configurations below refer only to this newly created temporary directory.
export KRYOPTIC_CONF="$scratch/kryoptic.conf"
cat > "$KRYOPTIC_CONF" <<CONFIG
[[slots]]
slot = 0
dbtype = "sqlite"
dbargs = "$scratch/token.sql"
CONFIG
export PKCS11_ENVELOPE_ISOLATED=1 PKCS11_ENVELOPE_DIR="$scratch"
cargo test -p pkcs11-client --test envelope_interop --locked -- --ignored --test-threads=1
