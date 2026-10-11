#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Called by test-softhsm.sh after provisioning, before tests replace fixture keys.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
[[ ${PKCS11_TEST_ISOLATED:-} == 1 ]]
work=$(mktemp -d "${TMPDIR:-/tmp}/pkcs11-examples.XXXXXXXX")
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
printf '12345678\n' > "$work/pin"

binary() {
    python3 - "$work/build.json" "$1" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    item = json.loads(line)
    if (item.get("reason") == "compiler-artifact"
            and item["target"]["name"] == sys.argv[2]
            and "example" in item["target"]["kind"]
            and item.get("executable")):
        print(item["executable"])
        break
else:
    raise SystemExit("example executable not found")
PY
}

case ${1:-} in
client)
    [[ -d ${PKCS11_CLIENT_TEST_DIR:-} ]]
    cargo build -p pkcs11-client --examples --locked --message-format=json > "$work/build.json"
    sign=$(binary sign)
    bound_sign=$(binary bound_sign)
    key='pkcs11:token=stage5-test;object=rsa;type=private'
    certificate='pkcs11:token=stage5-test;object=rsa;type=cert'
    printf 'application example message\n' > "$work/message"
    "$sign" "$PKCS11_TEST_MODULE" "$key" "$work/pin" "$work/message" > "$work/signature"
    openssl dgst -sha256 -verify "$PKCS11_CLIENT_TEST_DIR/01-public.pem" \
        -signature "$work/signature" "$work/message"
    "$bound_sign" "$PKCS11_TEST_MODULE" "$key" "$certificate" "$work/pin" "$work/message" > "$work/bound"
    openssl dgst -sha256 -verify "$PKCS11_CLIENT_TEST_DIR/01-public.pem" \
        -signature "$work/bound" "$work/message"
    if "$bound_sign" "$PKCS11_TEST_MODULE" "$key" \
        'pkcs11:token=stage5-test;object=wrong;type=cert' "$work/pin" "$work/message" \
        > "$work/rejected" 2> "$work/error"; then
        echo 'Example accepted a mismatched certificate' >&2; exit 1
    fi
    [[ ! -s "$work/rejected" ]]
    ;;
tls)
    [[ -d ${PKCS11_TLS_TEST_DIR:-} ]]
    cargo build -p pkcs11-rustls-adapter --examples --locked --message-format=json > "$work/build.json"
    server=$(binary tls_server)
    client=$(binary tls_client)
    start_server() {
        rm -f -- "$work/address"
        timeout 45s "$server" "$PKCS11_TEST_MODULE" 'pkcs11:token=stage7-test' \
            'pkcs11:token=stage7-test;object=server-rsa;type=private' \
            "$PKCS11_TLS_TEST_DIR/server-rsa.der" "$PKCS11_TLS_TEST_DIR/ca.der" \
            "$work/pin" localhost "$work/address" "$@" > "$work/server.log" 2>&1 &
        server_pid=$!
        for ((attempt = 0; attempt < 200; attempt++)); do
            if [[ -f "$work/address" ]] && IFS= read -r address < "$work/address" && [[ -n "$address" ]]; then
                return
            fi
            if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
            sleep 0.1
        done
        cat "$work/server.log" >&2
        echo 'TLS example server did not become ready' >&2
        exit 1
    }
    start_server
    "$client" "$address" localhost "$PKCS11_TLS_TEST_DIR/ca.der"
    wait "$server_pid"; server_pid=
    start_server "$PKCS11_TLS_TEST_DIR/ca.der"
    "$client" "$address" localhost "$PKCS11_TLS_TEST_DIR/ca.der" \
        "$PKCS11_TEST_MODULE" 'pkcs11:token=stage7-test' \
        'pkcs11:token=stage7-test;object=client-rsa;type=private' \
        "$PKCS11_TLS_TEST_DIR/client-rsa.der" "$PKCS11_TLS_TEST_DIR/ca.der" "$work/pin"
    wait "$server_pid"; server_pid=
    # A verifier must reject both an absent client identity and an unrelated root.
    for rejection in missing-client wrong-root; do
        if [[ "$rejection" == missing-client ]]; then
            start_server "$PKCS11_TLS_TEST_DIR/ca.der"
            root="$PKCS11_TLS_TEST_DIR/ca.der"
        else
            start_server
            root="$PKCS11_TLS_TEST_DIR/other-ca.der"
        fi
        if "$client" "$address" localhost "$root" > "$work/client.log" 2>&1; then
            echo "TLS example accepted $rejection" >&2; exit 1
        fi
        server_status=0
        wait "$server_pid" || server_status=$?
        if [[ "$server_status" == 0 || "$server_status" == 124 || "$server_status" == 137 ]]; then
            echo "TLS example server did not reject $rejection normally (exit $server_status)" >&2; exit 1
        fi
        server_pid=
    done
    ;;
*) echo 'Usage: test-examples.sh client|tls (through the isolated runner)' >&2; exit 2 ;;
esac
echo "Application examples passed: $1"
