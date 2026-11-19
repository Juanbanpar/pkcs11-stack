#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Sourced by disposable provider builders, after scratch and prefix are set.
provider_tools=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
provider_rust=1.99.0
openssl_commit=45e844fa2a14ec92d146bd8f5778ac130b6625fb
kryoptic_commit=f997876ff40740992ff3b51d92665e08ac4fbfc2
fetch() {
    git init "$scratch/$1"
    git -C "$scratch/$1" fetch --depth 1 "$2" "$3"
    git -C "$scratch/$1" checkout --detach FETCH_HEAD
    test "$(git -C "$scratch/$1" rev-parse HEAD)" = "$3"
}
build_openssl() {
    fetch openssl https://github.com/openssl/openssl.git "$openssl_commit"
    (
        cd "$scratch/openssl"
        ./Configure --prefix="$prefix/openssl" --libdir=lib no-shared no-tests no-docs -fPIC
        make -j2
        make install_sw
    )
    record_openssl
}
install_provider_lock() {
    # Upstream has no lockfile. Never resolve a fresh graph during these builds.
    cp "$provider_tools/provider-locks/kryoptic.Cargo.lock" Cargo.lock
    cargo +"$provider_rust" --version
    rustc +"$provider_rust" --version
}
record_openssl() {
    install -m 644 "$scratch/openssl/LICENSE.txt" "$prefix/openssl/LICENSE.txt"
    python3 - "$prefix/openssl" "$openssl_commit" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'pkcs11-build.json').write_text(json.dumps({'source':sys.argv[2],'libcrypto_sha256':hashlib.sha256((root/'lib/libcrypto.a').read_bytes()).hexdigest()},indent=2)+'\n')
PY
}
verify_openssl() {
    python3 - "$1" "$openssl_commit" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); data=json.loads((root/'pkcs11-build.json').read_text())
if data['source']!=sys.argv[2] or data['libcrypto_sha256']!=hashlib.sha256((root/'lib/libcrypto.a').read_bytes()).hexdigest():
    raise SystemExit('OpenSSL provenance mismatch; rebuild with a pinned provider script')
PY
}
record_provider() {
    local name=$1 commit=$2 artifact=$3 profile=$4
    python3 - "$prefix" "$name" "$commit" "$artifact" "$openssl_commit" "$provider_rust" "$provider_tools/provider-locks/kryoptic.Cargo.lock" "$profile" <<'PY'
import hashlib,json,pathlib,subprocess,sys
prefix,name,commit,artifact,openssl,rust,lock,profile=sys.argv[1:]
data={'profile':profile,'provider':name,'source':commit,'openssl_source':openssl,'artifact_sha256':hashlib.sha256(pathlib.Path(artifact).read_bytes()).hexdigest(),'cc':subprocess.check_output(['cc','--version'],text=True).splitlines()[0]}
if name=='kryoptic':
    data.update(rust_toolchain=rust,cargo_lock_sha256=hashlib.sha256(pathlib.Path(lock).read_bytes()).hexdigest())
pathlib.Path(prefix,'provider-build.json').write_text(json.dumps(data,indent=2)+'\n')
PY
}
