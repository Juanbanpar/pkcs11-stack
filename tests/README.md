# Testing

Run unit, property and documentation tests without a PKCS#11 module:

```sh
cargo test --workspace --locked
python3 tools/check-dependencies.py
```

Tests cover URI parsing and redaction, selection ambiguity, ownership, signing
plans, certificate verification, CLI input/output, and TLS signature encoding.
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

These checks do not establish formal algorithm validation or hardware compatibility.

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
