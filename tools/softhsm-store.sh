#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Sourced by the isolated SoftHSM test runners from the workspace root.
# Only use a trusted SoftHSM library. All token initialization targets the new
# temporary SOFTHSM2_CONF below, never an operator's existing token directory.
module=${PKCS11_TEST_MODULE:-}
if [[ -z "$module" ]]; then
    for candidate in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        if [[ -f "$candidate" ]]; then module=$candidate; break; fi
    done
fi
if [[ -z "$module" || ! -f "$module" || "$(basename "$module")" != libsofthsm2.so ]]; then
    echo 'Set PKCS11_TEST_MODULE to a trusted libsofthsm2.so.' >&2
    exit 1
fi
module=$(realpath "$module")
util=$(command -v "${SOFTHSM2_UTIL:-softhsm2-util}")
util=$(realpath "$util")
export SOFTHSM2_UTIL="$util"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-stack.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/tokens"
export SOFTHSM2_CONF="$scratch/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<CONFIG
directories.tokendir = $scratch/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
CONFIG
export PKCS11_TEST_MODULE="$module"
export PKCS11_TEST_ISOLATED=1
