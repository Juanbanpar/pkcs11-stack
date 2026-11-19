#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 1 || ( "$1" != --unit && "$1" != --providers && "$1" != --all ) ]]; then
    echo 'Usage: tools/test.sh --unit | --providers | --all' >&2
    exit 2
fi

if [[ $1 != --unit ]]; then
    : "${PKCS11_TEST_MODULE:?Set PKCS11_TEST_MODULE to the pinned SoftHSM module; see tests/README.md}"
    : "${SOFTHSM2_UTIL:?Set SOFTHSM2_UTIL to the pinned SoftHSM utility; see tests/README.md}"
    : "${PKCS11_TEST_PQC_OPENSSL:?Set PKCS11_TEST_PQC_OPENSSL to the pinned SoftHSM OpenSSL; see tests/README.md}"
    : "${PKCS11_TEST_KRYOPTIC_MODULE:?Set PKCS11_TEST_KRYOPTIC_MODULE to the pinned Kryoptic module; see tests/README.md}"
    : "${PKCS11_TEST_KRYOPTIC_OPENSSL:?Set PKCS11_TEST_KRYOPTIC_OPENSSL to the pinned Kryoptic OpenSSL; see tests/README.md}"
fi

if [[ $1 != --providers ]]; then
    echo 'Running provider-independent tests'
    cargo test --workspace --locked
fi
if [[ $1 != --unit ]]; then
    echo 'Running packaged SoftHSM compatibility tests'
    env -u PKCS11_TEST_MODULE -u SOFTHSM2_UTIL \
        -u PKCS11_TEST_REQUIRE_EC_MULTIPART -u PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2 \
        PKCS11_TEST_SKIP_EDDSA=1 ./tools/test-softhsm.sh
    echo 'Running upstream SoftHSM classical and ML-DSA tests'
    PKCS11_TEST_SKIP_EDDSA=0 PKCS11_TEST_REQUIRE_EC_MULTIPART=1 \
        PKCS11_TEST_REQUIRE_RSA_OAEP_SHA2=1 ./tools/test-softhsm.sh
    ./tools/test-ml-dsa.sh
    echo 'Running Kryoptic provider tests'
    ./tools/test-kryoptic.sh
fi

case $1 in
    --unit) echo 'Passed provider-independent tests (--unit)' ;;
    --providers) echo 'Passed all provider suites (--providers)' ;;
    --all) echo 'Passed provider-independent tests and all provider suites (--all)' ;;
esac
