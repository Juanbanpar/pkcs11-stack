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
replacement, and server/mutual TLS. Use this runner only with SoftHSM, never an
existing token store or a hardware module.

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
