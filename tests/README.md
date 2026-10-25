# Testing

Run unit, property and documentation tests without a PKCS#11 module:

```sh
cargo test --workspace --locked
python3 tools/check-dependencies.py
```

Tests cover URI parsing and redaction, selection ambiguity, ownership, signing
plans, certificate verification, CLI input/output, and TLS signature encoding.
ML-DSA software tests use public OpenSSL fixtures without a provider. They cover
message/context mismatches, malformed SPKI/certificates and repeated-hint signature
encodings, including the regression described by GHSA-5x2r-hc65-25f9.
Compile-fail examples check that modules, sessions and objects cannot be used
outside their owner lifetimes.

## SoftHSM integration

Install SoftHSM, OpenSC and OpenSSL, then run:

```sh
./tools/test-softhsm.sh
```

The runner creates temporary token storage and removes it on exit. It provisions
nonextractable RSA/EC keys, runs the ignored integration tests and
[signing/TLS examples](../docs/examples.md), and verifies signatures independently
with OpenSSL. It covers authentication, object mutations, pool recovery, key
replacement, and server/mutual TLS. Generation tests check all three ECDH curves
and AES sizes, permissions, duplicate identities, public export and rejected secret
export. ECDH agreement, AES encryption and RFC 3394 round trips verify generated
key use without exporting private material. CLI and desktop tests cover the new
generation choices, rejected option combinations, permissions and export rules.
Desktop tests also exercise generated ECDH and wrapping keys through the worker.
Use this runner only with SoftHSM, never an existing token store or a hardware module.

For another SoftHSM installation:

```sh
PKCS11_TEST_MODULE=/path/to/libsofthsm2.so SOFTHSM2_UTIL=/path/to/softhsm2-util ./tools/test-softhsm.sh
```

Set `PKCS11_TEST_DESKTOP=1` to include desktop backend integration without opening
a window.

Set `PKCS11_TEST_REQUIRE_EC_MULTIPART=1` to require combined multipart ECDSA support.
CI tests both packaged SoftHSM and a pinned upstream build with that support.

### PQC provider compatibility

Build the pinned OpenSSL 3.5.9 and SoftHSM sources with ML-DSA and ML-KEM enabled,
then run the classical workflows and the required PQC tests:

```sh
bash tools/build-pqc-softhsm.sh /absolute/path/to/softhsm-pqc
PKCS11_TEST_REQUIRE_PQC=1 \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/softhsm-pqc/openssl/bin/openssl \
PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util \
./tools/test-softhsm.sh
```

Building requires Git, a C/C++ toolchain, Make, Perl, Autoconf, Automake and
Libtool. OpenSSL uses static PIC libraries, so the test module does not require
changes to the system OpenSSL installation or library search path.

The `pqc-provider` CI job requires ML-DSA-44/65/87 signing and verification, context
handling, rejection of altered messages, and ML-KEM-512/768/1024 encapsulation and
decapsulation. It checks ciphertext/signature sizes and nonextractability of
private keys and shared secrets. A one-block AES round trip proves the KEM secrets
agree without exporting them. Missing mechanisms or entry points fail the job.

The pinned SoftHSM revision reports ML-KEM private-key lengths as mechanism bounds,
contrary to PKCS#11 3.2 sections 6.68.4/5. The build script applies a two-line source
correction to the isolated provider. Compatibility tests check public-key byte
bounds; runtime rejects incorrect metadata without a vendor-specific fallback.

Typed ML-KEM tests cover all parameter sets, key permissions, allowed mechanisms,
read-only sessions, duplicate secret IDs, expected-parameter checks and ciphertext
lengths. HMAC challenges compare full token-held secrets without extracting them,
including the different secret produced for altered same-length ciphertext.
Public-key tests check RFC 9935 DER and FIPS 203 coefficient validation, import
exported keys and use them for the secret-agreement checks. OpenSSL independently
decodes the exported SPKI. Private public-key objects are refused, and duplicate
IDs remain ambiguous. Client tests cover persistent secret inspection/deletion, export refusal, explicit
session closure and semantic error categories.

Runtime/client tests also require typed ML-DSA generation, capability checks,
policy rejection before checkout, context authentication, signature verification,
session recovery after mismatches, and detection of a changed parameter set under
a reused selector. Certificate binding verifies a probe and each subsequent
signature in software, rejects wrong certificates, and detects replacement keys
even when the selector and parameter set are unchanged. Software verification
also covers empty messages and 255-byte binary contexts. Exported SPKI keys and
token signatures are verified through the pinned OpenSSL command-line tool,
including always-authenticate keys. CLI tests generate all three parameter sets,
export SPKI, bind certificates, sign with context authentication and verify using
both certificate files and token certificates. They check deterministic signing,
empty messages, binary contexts, mismatches and output preservation/cleanup.

`PKCS11_TEST_PQC_OPENSSL` selects an OpenSSL executable with ML-DSA support; it
defaults to `openssl`. Missing support fails the tests. These checks do not
establish formal algorithm validation or hardware compatibility.

The TLS PQC tests use an application-selected AWS-LC provider for peer and local
signature verification, record encryption and key exchange. All three ML-DSA
parameter sets authenticate servers and clients with token-held keys, including
an always-authenticate key. An ML-DSA issuer signs the certificate chain and the
handshake negotiates X25519MLKEM768. Negative cases cover unsupported verifiers,
policy rejection before credential acquisition, trust failures, TLS 1.2,
exhausted pools and replacement keys. The adapter's production graph still
selects no software crypto provider.

## HKDF provider compatibility

Install NSS softoken (`libnss3` on Debian/Ubuntu, `nss-softokn` on Fedora), then run:

```sh
./tools/test-hkdf.sh
# Override the module location when needed:
PKCS11_TEST_HKDF_MODULE=/absolute/path/to/libsoftokn3.so ./tools/test-hkdf.sh
```

The runner uses a temporary working directory and ordinary NSS initialization
without a database or login. All test keys are volatile session objects. The
`hkdf-provider` CI job requires CKM_HKDF_DERIVE and checks RFC 5869 SHA-256 cases
1 and 3, including empty salt/info and changed context. HMAC comparisons verify
derived sensitive, nonextractable keys without reading their values.

This covers the native HKDF mechanism with public RFC vectors. The typed API
requires hash-length input under the PKCS#11 profile; it is tested separately below.

## Persistent ML-KEM and HKDF

Build the pinned Kryoptic and OpenSSL sources, then run runtime/client/CLI tests:

```sh
./tools/build-kem-hkdf-provider.sh /absolute/path/to/kdf-provider
PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
./tools/test-kem-hkdf.sh
```

Building requires stable Rust, Git, Clang/libclang headers, a C/C++ toolchain,
Make, Perl, pkg-config and SQLite development files. The module statically links
the pinned OpenSSL 3.5.9. Kryoptic's source revision is pinned; its upstream Cargo
dependencies are resolved at build time because upstream does not supply a lockfile.
`PKCS11_TEST_KDF_OPENSSL` selects the independent OpenSSL HKDF reference command.

The runner creates a temporary Kryoptic SQLite store and removes it on exit.
Use it only with Kryoptic. No existing token store is opened or reset.
The `kem-hkdf-provider` CI job requires both mechanisms, without skipping missing
support. It compares SHA-256/384/512 results against OpenSSL using public
hash-length inputs, including empty salt/context and maximum SHA-256 output.
Tests inspect output permissions, reject unsuitable bases, wrong hash lengths,
read-only sessions and duplicate output IDs, and check client export refusal.

For ML-KEM-512/768/1024, each sender/receiver secret feeds typed HKDF-SHA256 on the
same token. AES challenge comparisons verify matching derived keys and different
results for altered ciphertext/context. Generic known-answer outputs are compared
using HMAC after temporarily enabling signing on disposable test keys. No token
secret value is read; all sessions close before the next module lifecycle.

The same provider also requires P-256 ECDH, concatenation and HKDF-SHA512 for
application hybrid derivation. Tests compare independent peers, reversed component
order, changed context and public known-answer inputs; inspect output permissions;
reject unsuitable inputs; and check that temporary combined secrets are destroyed.
CLI tests exchange RFC 9935 public keys, persist public ciphertext, derive matching
keys and preserve existing output files. A separate native lifecycle verifies CLI
key agreement using AES challenges.

## AES-GCM provider compatibility

The SoftHSM and Kryoptic runners require AES-GCM with a 96-bit nonce and 128-bit
tag. Runtime fixtures select 12 NIST CAVP known-answer vectors across AES-128/192/256,
including empty input/AAD and non-block-aligned messages. Tests reject changes to
nonce, AAD, ciphertext and tag, and verify failed-session invalidation without
returning plaintext. They also cover RO execution, permissions, allowed mechanisms,
wrong key classes/types, generated keys and request/output redaction.

Client tests cover typed requests, bounded preflight, private export refusal and
checked closure. CLI and desktop file tests cover explicit nonce/AAD parameters,
raw-format round trips, tampered inputs, empty messages, output preservation and
no plaintext release on authentication failure. Desktop forms reject stale
choices/pickers and clear parameters on submission or navigation. Kryoptic additionally exercises ML-KEM → HKDF → AES-GCM for all
three KEM parameter sets and an application hybrid-derived AES key. These tests do
not constitute algorithm validation.

## Dependency advisories

CI audits both lockfiles with cargo-audit 0.22.2. Run from the repository root:

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --file Cargo.lock
cargo audit --file fuzz/Cargo.lock
```

Vulnerabilities, unsoundness notices and yanked packages fail the check.
Unmaintained-package notices remain visible as warnings. The repository's
[Cargo audit configuration](../.cargo/audit.toml) lists advisory-specific exceptions
for software public-key verification/parsing paths. Reassess these exceptions
before adding software private-key operations or changing the affected dependency
families. Token-side private-key operations remain in the provider's scope.

## Property tests and fuzzing

Increase the case count or choose a seed to reproduce a property failure:

```sh
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-locator --test properties --locked
PROPTEST_RNG_SEED=42 PROPTEST_CASES=4096 cargo test -p pkcs11-rustls-adapter --lib encoding::properties --locked
```

Keep minimized failures as regression tests. The [fuzz guide](../fuzz/README.md)
provides sanitizer runs, corpus management and artifact replay commands.

CI checks the workspace and each crate independently, tests minimum Rust versions,
and runs pure tests on Linux, Windows and macOS. SoftHSM and fuzzing run on Linux.
