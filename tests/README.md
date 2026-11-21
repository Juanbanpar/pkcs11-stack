# Testing

Run commands from the repository root. Provider runners create temporary token
stores and remove them on exit. Use only the specified trusted software providers;
never point these runners at hardware or an existing token store. Provider tests
do not establish formal algorithm validation or hardware compatibility.

## Compatibility scope

| Check | What it establishes |
| --- | --- |
| Unit and documentation tests | API and CLI behavior without a provider, including independent public test fixtures |
| Provider integration | Operations and failure handling exercised with the software builds in the [compatibility matrix](../docs/oasis-compatibility.md#provider-tests) |
| Windows and macOS CI | Workspace compilation and CLI file-preservation tests |
| Headless desktop tests | UI and worker behavior exercised without a live window or physical HSM |

Use the [SoftHSM quickstart](../docs/quickstart.md) for a first signing operation
with the distribution's software token. The full suite below tests additional
profiles with pinned builds.

## Unit and documentation tests

No PKCS#11 module is required. Native desktop build dependencies are listed in the
[desktop guide](../crates/pkcs11-desktop/README.md#build-and-run).
```sh
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
./tools/test.sh --unit
```

Tests cover URI parsing/redaction, ambiguity, signing plans, certificate verification,
CLI output/exit codes and TLS encoding. Compile-fail examples check owner lifetimes.
ML-DSA software tests use OpenSSL public fixtures, including malformed encodings
and the regression described by GHSA-5x2r-hc65-25f9.

## Full provider suite

Install packaged SoftHSM for compatibility testing and build the two pinned,
unmodified providers:

```sh
./tools/build-pqc-softhsm.sh /absolute/path/to/softhsm-pqc
./tools/build-kryoptic-provider.sh /absolute/path/to/kryoptic

export PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so
export SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util
export PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/softhsm-pqc/openssl/bin/openssl
export PKCS11_TEST_KRYOPTIC_MODULE=/absolute/path/to/kryoptic/libkryoptic_pkcs11.so
export PKCS11_TEST_KRYOPTIC_OPENSSL=/absolute/path/to/kryoptic/openssl/bin/openssl

./tools/test.sh --providers
# Run provider-independent and provider tests in one pass
./tools/test.sh --all
```

Install OpenSC (`pkcs11-tool`), OpenSSL, Git, a C/C++ compiler, Make, Perl,
Autoconf, Automake, Libtool, Clang/libclang, pkg-config, and SQLite development
headers. Kryoptic needs `rustup toolchain install 1.99.0 --profile minimal`.
The builders use OpenSSL 3.5.9 and Python 3 for build provenance. Kryoptic
uses the committed lockfile.

To reuse the OpenSSL build from the pinned SoftHSM build, set
`KRYOPTIC_OPENSSL_SOURCES=/absolute/path/to/softhsm-pqc/openssl` when building
Kryoptic. The builder checks the manifest and library hash. Set
`PKCS11_TEST_KRYOPTIC_OPENSSL` to the reused installation's executable.

Both provider modes require packaged SoftHSM, pinned SoftHSM with multipart
ECDSA and SHA-2 OAEP, and the combined Kryoptic profile. A missing or
insufficient provider fails the run. Desktop backend tests run without a window.

## SoftHSM integration

For a partial provider run, install SoftHSM, OpenSC and OpenSSL:

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
The packaged compatibility run skips EdDSA for SoftHSM 2.6.1's incorrect key
bounds. Ed25519 and Ed448 remain mandatory on the pinned upstream build.
If the system OpenSSL blocks SHA-1 signature verification, set
`PKCS11_TEST_OPENSSL` to the pinned OpenSSL executable for this partial run.

## PQC provider compatibility

With the provider environment above, CI and targeted local runs can invoke
the ML-DSA or Kryoptic runners directly:

```sh
./tools/test-ml-dsa.sh
./tools/test-kryoptic.sh
```

`PKCS11_TEST_PQC_OPENSSL` selects the OpenSSL executable for ML-DSA.
Kryoptic reuses its module across three independently provisioned SQLite
stores for ML-KEM, derivation and PQC/Montgomery tests. ML-KEM uses Kryoptic because
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

## Test ownership

| Crate | Primary coverage |
| --- | --- |
| Locator | URI parsing, normalization, redaction and matching |
| Runtime | Provider mechanisms, exhaustive parameter sets, permissions, sensitive attributes, authentication and session recovery |
| Client | Typed application workflows, policy propagation, object identity, certificates, import and export |
| CLI | Argument and policy mapping, JSON and exit codes, file handling and output preservation |
| Desktop | State, workers, authentication, lifecycle and representative provider workflows |
| rustls adapter | Credential selection, handshakes, TLS trust and authentication failures |

The client ML-DSA suite verifies token signatures with OpenSSL for all three
parameter sets. The CLI retains one OpenSSL check with context-specific
authentication and verifies certificate-file and token-certificate workflows,
both bound and unbound, for every parameter set. The client's exported SPKI is
decoded by OpenSSL before certificate issuance. The later client export is
compared byte for byte to that same SPKI.

ML-KEM public-key interchange, hybrid temporary-object cleanup, SLH-DSA
interoperability, EdDSA encoding and TLS, classical signing, and AES-GCM
authentication and file preservation exercise distinct boundaries. These cases
remain covered alongside the runtime known-answer and permission checks.

## Persistent ML-KEM and HKDF

This part of the Kryoptic runner requires both ML-KEM and HKDF.
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

The combined Kryoptic build also enables SLH-DSA, HashSLH-DSA, HashML-DSA,
ML-DSA, ECDH and Montgomery. Tests cover independent OpenSSL SLH-DSA
verification, hash-PQC messages/caller digests, HashSLH-only generation, validated
public import and X25519/X448 agreement checked with matching AES-GCM keys.
Runtime/client, CLI and headless desktop workflows are included.

## Dependency advisories

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --file Cargo.lock
cargo audit --file fuzz/Cargo.lock
(cd tools/provider-locks && cargo audit --file kryoptic.Cargo.lock)
```

Vulnerabilities, unsoundness notices and yanked packages fail the audit.
Unmaintained-package notices are warnings. See the
[advisory policy](../SECURITY.md#dependency-advisories) for reviewing exclusions.

## Property tests and fuzzing

```sh
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-locator --test properties --locked
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-rustls-adapter --lib encoding::properties --locked
```

Retain minimized failures as regression tests. The [fuzz guide](../fuzz/README.md)
covers sanitizers, corpus management and replay. Linux CI runs the full workspace
and provider suites. Windows and macOS compile all targets and run representative
CLI file-handling tests. The workspace also compiles all targets on Rust 1.88.
Stable CI checks the adapter's standalone production configurations.
