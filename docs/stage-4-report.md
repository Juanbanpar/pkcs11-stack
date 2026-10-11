# Stage 4: pooled sessions, recovery, capability planning and signing

Historical Stage 4 snapshot. Current dependency and behavior corrections are in the
[September 25 review](implemented-stage-review.md). The vendored test commands below
apply to the original snapshot only.

Completed 2026-09-06. Stage 4 is implemented in `pkcs11-runtime`. The five selected
crate names are unchanged, including `pkcs11-client`. Original project code and
documentation remain MIT OR Apache-2.0. The application client, CLI workflows and
rustls adapter are subsequent milestones and remain scaffold-only.

## Delivered behavior

- A bounded token/mode-scoped pool with nonblocking exhaustion, concurrent exclusive
  RAII leases, healthy return, discard, session recreation and authentication on
  checkout. PKCS#11 calls do not run under the accounting mutex.
- Stable typed private/public key and certificate references. Signing resolves a
  fresh session-bound handle and rediscovers metadata on every call. No handles are
  cached. Failed signing/search calls and panic unwinding prevent session reuse.
- Capability snapshots and pure planning based on actual mechanisms, signing flags,
  size bounds, RSA modulus size or named EC curve, CKA_SIGN, CKA_ALLOWED_MECHANISMS,
  always-authenticate status, operation parameters and policy.
- Explicit message versus digest input; token-only, permitted software fallback and
  software-only message hashing policies. Runtime SHA-2 uses sha2 0.10.9.
- RSA PKCS#1 v1.5, RSA-PSS with explicit salt/MGF1 parameters, and ECDSA on
  P-256/P-384/P-521. SHA-256/384/512 are supported. RSA outputs retain modulus width;
  ECDSA retains PKCS#11 fixed-width `r || s`, with protocol conversion outside runtime.
- Context-specific authentication for combined multipart RSA signing. Missing PINs
  fail before init; a failed context login causes session discard, with no retry.
- Public-only metadata reads: optional token SPKI, RSA public modulus/exponent and
  EC parameters/point. Independently selected certificate references expose DER.

Main implementation: [pool](../crates/pkcs11-runtime/src/pool.rs),
[signing and key metadata](../crates/pkcs11-runtime/src/signing.rs),
[session ownership](../crates/pkcs11-runtime/src/session.rs),
[typed errors](../crates/pkcs11-runtime/src/error.rs).
See the [runtime usage examples](../crates/pkcs11-runtime/README.md) and
[ADR 0007](adr/0007-signing-and-pooling.md) for the API and decisions.

## Dependency defect found and fixed locally

The real restricted-key test exposed incorrect decoding of nonempty
CKA_ALLOWED_MECHANISMS in cryptoki 0.12.0: a byte length was used as an element count,
allowing an out-of-bounds read. A Cargo source override selects the published crate
with one modified source file. The replacement decoder uses bounded native-endian
byte chunks, rejects incomplete elements and avoids alignment assumptions.

The [vendor record](../vendor/README.md) includes the source archive checksum,
upstream revision, exact change, regression command and removal criteria. Upstream
Apache-2.0 source/notices are retained; it is excluded from workspace membership.
Original local modifications are MIT OR Apache-2.0. No new FFI layer was introduced,
and no upstream issue or PR was submitted. This is not a complete upstream audit.

## Validation executed locally

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --locked` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --locked --quiet` | 33 ordinary tests and 8 doctests passed; 2 software-token tests ignored by default |
| `cargo +1.85.0 check --workspace --all-targets --locked` | Passed |
| `cargo +1.85.0 test --workspace --locked --quiet` | Same workspace tests passed |
| Vendored cryptoki bounded-decoder regressions | 2 passed |
| `./tools/test-softhsm.sh` with explicit local tool paths | Both software-token suites passed on stable Rust |
| `bash -n tools/test-softhsm.sh` | Passed |
| Cargo metadata, original-source SPDX and local Markdown links | Passed |

The [pure planner tests](../crates/pkcs11-runtime/tests/planning.rs) cover all three
digest mappings/lengths, message/hash policy boundaries, unsupported mechanisms,
key type/size/sign restrictions, mechanism flags/bounds, allowed mechanisms,
algorithm/digest/curve policy, PSS salt/MGF constraints and context-auth limitations.
Compile-fail examples enforce module/session, pool/module and object/lease lifetimes.

The [signing acceptance suite](../crates/pkcs11-runtime/tests/signing_softhsm.rs)
creates nonextractable keys in fresh disposable storage and checks:

- Three simultaneous leases and signing workers, distinct generations, immediate
  exhaustion at capacity and healthy reuse afterward.
- Forced session destruction/recreation and successful use of the same key selector,
  plus module finalization/reinitialization with that selector.
- Token-wide logout followed by explicit authenticated checkout, failed-PIN capacity
  recovery, failed context-login discard, and panic cleanup.
- RSA PKCS#1 v1.5, PSS and ECDSA through message, software-hashed and prehashed paths
  with SHA-256/384/512; all three named EC curves.
- PSS salts of zero, 20 bytes, digest length and the SHA-256/2048-bit maximum of 222
  bytes. Independent verification uses the requested salt and MGF1 digest.
- An actual nonempty allowed-mechanisms restriction, a CKA_SIGN=false key, negative
  protected-path capability and combined RSA PKCS#1/PSS always-authenticate signing.
- Token selector mismatch after session recreation.

OpenSSL independently verifies each successful signature and rejects an altered
message. Test-only ECDSA conversion supplies DER to that verifier; it is not runtime
behavior. OpenSSL is an external test executable, not a Rust dependency/backend.
The Stage 3 discovery/lifecycle suite also passes unchanged.

Local reproduction used:

```sh
cargo test --manifest-path vendor/cryptoki-0.12.0/Cargo.toml \
  --lib allowed_mechanisms --locked

PKCS11_TEST_MODULE=/tmp/pkcs11-stage3-softhsm/root/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/tmp/pkcs11-stage3-softhsm/root/usr/bin/softhsm2-util \
  ./tools/test-softhsm.sh
```

Those `/tmp` tool locations are local extracted packages, not required repository
paths. On a normal installation the script discovers SoftHSM and uses `softhsm2-util`
from PATH. It sets a private temporary SOFTHSM2_CONF, provisions only disposable
storage and removes it on exit. Existing operator tokens are not modified.

CI now includes the decoder regressions and expands the isolated software-token
job to signing/OpenSSL verification. No remote CI run was observed. This directory
has no Git repository metadata, so no commit was created.

## Limits and next milestone

Software-token validation does not establish hardware interoperability, hot-unplug
behavior or positive protected-authentication-path support. Recovery replaces bad
sessions, without automatically migrating slots, reconnecting modules, retrying
signatures or accepting changed token identities. Token metadata is not cryptographic
proof against substitution with identical metadata. External owners and token-wide
logout remain application coordination concerns.

Cryptoki 0.12 cannot interleave login into its single-part signing call. Raw/prehashed
and ECDSA requests for always-authenticate keys therefore fail before execution;
combined multipart RSA is supported and tested. Advertisements do not guarantee
every vendor parameter combination; backend errors remain authoritative. There is
no software private-key fallback.

Public metadata is not certificate trust or key association. No certificate parser,
automatic SPKI construction/extraction or implicit association was introduced.
Message/digest buffers are not zeroizing containers; PINs remain borrowed secrets,
and signing input Debug does not print input bytes.

Next milestone: Stage 5, the ergonomic `pkcs11-client` API. It has not started.
