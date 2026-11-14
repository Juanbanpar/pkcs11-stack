# Testing

Run commands from the repository root. Provider runners create temporary token
stores and remove them on exit. Use only the specified trusted software providers;
never point these runners at hardware or an existing token store. Provider tests
do not establish formal algorithm validation or hardware compatibility.

## Unit and documentation tests

No PKCS#11 module is required. Native desktop build dependencies are listed in the
[desktop guide](../crates/pkcs11-desktop/README.md#build-and-run).

```sh
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
python3 tools/check-dependencies.py
```

Tests cover URI parsing/redaction, ambiguity, signing plans, certificate verification,
CLI output/exit codes and TLS encoding. Compile-fail examples check owner lifetimes.
ML-DSA software tests use OpenSSL public fixtures, including malformed encodings
and the regression described by GHSA-5x2r-hc65-25f9.

## Full provider suite

Build the three pinned, unmodified providers once:

```sh
bash tools/build-pqc-softhsm.sh /absolute/path/to/softhsm-pqc
./tools/build-kem-hkdf-provider.sh /absolute/path/to/kdf-provider
./tools/build-pqc-kryoptic-provider.sh /absolute/path/to/pqc-kryoptic

PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util \
PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
PKCS11_TEST_KDF_OPENSSL=/absolute/path/to/kdf-provider/openssl/bin/openssl \
PKCS11_TEST_PQC_MODULE=/absolute/path/to/pqc-kryoptic/libkryoptic_pkcs11.so \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/pqc-kryoptic/openssl/bin/openssl \
./tools/test.sh
```

Install OpenSC (`pkcs11-tool`) and OpenSSL. Provider builds also require Git,
C/C++, Make, Perl, Autoconf, Automake, Libtool, Clang/libclang, pkg-config and SQLite
development files; Kryoptic needs stable Rust. Builds link pinned OpenSSL 3.5.9
without replacing system OpenSSL or changing its library search path. Kryoptic's
source is pinned, but its Cargo dependencies resolve at build time because upstream
supplies no lockfile.

`tools/test.sh` runs unit/doctests, SoftHSM, ML-DSA, ML-KEM and KEM/HKDF suites.
Set `PKCS11_TEST_PQC_MODULE` to include SLH-DSA/hash-PQC/Montgomery; without it that
lane is reported as not run. Missing required mechanisms/parameter sets fail the
selected suite. Desktop backend tests run without opening a window.

## SoftHSM integration

Install SoftHSM, OpenSC and OpenSSL, then run:

```sh
./tools/test-softhsm.sh
# Override another SoftHSM installation:
PKCS11_TEST_MODULE=/path/to/libsofthsm2.so \
SOFTHSM2_UTIL=/path/to/softhsm2-util ./tools/test-softhsm.sh
```

| Area | Coverage |
| --- | --- |
| Lifecycle/authentication | Discovery, USER/SO roles, object mutations, pools, recovery and key replacement |
| Classical crypto | RSA/EC signing, OAEP, digest/MAC/AES, EdDSA, ECDH and RFC 3394 |
| Generation | ECDH curves, AES sizes/permissions, duplicate identities and public/secret export boundaries |
| Applications | CLI, headless desktop worker and [signing/TLS examples](../docs/examples.md); independent OpenSSL verification |
| AES-GCM | 12 NIST CAVP vectors across AES sizes, empty/nonaligned input and AAD, corruption rejection, session invalidation and output preservation |

`PKCS11_TEST_REQUIRE_EC_MULTIPART=1` requires combined multipart ECDSA support.
Packaged SoftHSM and the pinned upstream build differ in multipart ECDSA, SHA-2
OAEP and ML-DSA support; the PQC build can run both classical and ML-DSA suites.

## PQC provider compatibility

Use the providers built above for individual suites:

```sh
PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/softhsm-pqc/openssl/bin/openssl \
./tools/test-ml-dsa.sh

PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/kdf-provider/openssl/bin/openssl \
./tools/test-ml-kem.sh
```

`PKCS11_TEST_PQC_OPENSSL` selects an ML-DSA/ML-KEM-capable OpenSSL executable,
defaulting to `openssl`; missing support fails. ML-KEM uses Kryoptic because
SoftHSM advertises incorrect key bounds. No source patch or runtime metadata
workaround is applied.

| Suite | Coverage |
| --- | --- |
| ML-DSA | All parameter sets; generation, policy, context authentication, binding, replacement keys, empty messages and 255-byte contexts |
| ML-DSA interoperability | OpenSSL verification of SPKI/signatures; deterministic signing; certificate-file/token verification and CLI file preservation |
| ML-KEM | All parameter sets; permissions, bounds, RW requirements, duplicate secret IDs, expected parameters and ciphertext lengths |
| ML-KEM public keys | RFC 9935/FIPS 203 validation, import/export, ambiguous IDs, private-object refusal and independent OpenSSL decoding |
| Secret agreement | HMAC challenges compare full token-held secrets without export, including implicit rejection of altered ciphertext |
| TLS PQC | ML-DSA server/mutual TLS 1.3 with ML-DSA issuer and X25519MLKEM768 using application-selected AWS-LC |
| TLS failures | Missing verifiers, policy rejection before credentials, classical-only peers, trust, TLS 1.2, exhaustion and key replacement |

The adapter's production dependency graph selects no software crypto provider.

## Persistent ML-KEM and HKDF

```sh
PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
PKCS11_TEST_KDF_OPENSSL=/absolute/path/to/kdf-provider/openssl/bin/openssl \
./tools/test-kem-hkdf.sh
```

The runner uses disposable Kryoptic SQLite storage and requires both mechanisms.
It compares SHA-256/384/512 against OpenSSL, including empty salt/context and maximum
SHA-256 output. Tests reject unsuitable bases, lengths, RO sessions and duplicate
IDs; inspect output permissions and export refusal; and compare derived AES keys
without reading secret values. Test-only known-answer keys permit HMAC comparison.

Each ML-KEM parameter set feeds HKDF-SHA256 and AES-GCM, checking altered ciphertext/
context and all AES output sizes. Hybrid tests combine independent P-256 ECDH and
ML-KEM-768 secrets with HKDF-SHA512, check component order/context, reject unsuitable
inputs and verify temporary-key destruction. CLI exchange/file preservation and
headless desktop flows use the same token-held profiles.

## SLH-DSA, HashSLH-DSA, HashML-DSA and Montgomery

```sh
PKCS11_TEST_PQC_MODULE=/absolute/path/to/pqc-kryoptic/libkryoptic_pkcs11.so \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/pqc-kryoptic/openssl/bin/openssl \
./tools/test-pqc-kryoptic.sh
```

The all-features Kryoptic build enables SLH-DSA, HashSLH-DSA, HashML-DSA, ML-DSA,
ML-KEM, ECDH, Montgomery and SQLite. Tests cover independent OpenSSL SLH-DSA
verification, hash-PQC messages/caller digests, HashSLH-only generation, validated
public import and X25519/X448 agreement checked with matching AES-GCM keys.
Runtime/client, CLI and headless desktop workflows are included.

## Dependency advisories

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --file Cargo.lock
cargo audit --file fuzz/Cargo.lock
```

Vulnerabilities, unsoundness notices and yanked packages fail; unmaintained-package
notices are warnings. The [audit configuration](../.cargo/audit.toml) documents
advisory-specific exceptions for software public-key verification/parsing. Reassess
exceptions before adding software private-key operations or changing those dependency
families. Token private-key operations remain the provider's responsibility.

## Property tests and fuzzing

```sh
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-locator --test properties --locked
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-rustls-adapter --lib encoding::properties --locked
```

Retain minimized failures as regression tests. The [fuzz guide](../fuzz/README.md)
covers sanitizers, corpus management and replay. CI also tests crates independently,
minimum Rust versions and pure tests on Linux, Windows and macOS; provider/fuzz
lanes run on Linux.
