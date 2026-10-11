# Review of implemented stages

Completed 2026-09-25. Scope: revisit Stages 1–4 using the supplied September 6 chat
export, stage reports, ADRs and source. The locator and runtime were reviewed;
client, CLI and rustls adapter remain future milestones. Crate names,
MIT OR Apache-2.0 licensing, Rust 1.85 and the existing dependency boundaries remain.

## Corrections

1. **Retired the temporary cryptoki fork.** Required cryptoki 0.12.1, removed the
   source override, vendored crate, workspace exclusion, obsolete ignore entry and
   vendored-only CI command. The lockfile changes only cryptoki's version/source/
   checksum. Released decoding uses bounded native-endian chunks and rejects
   incomplete elements, matching the removed safety fix. SoftHSM acceptance now
   checks actual empty, single and multiple CKA_ALLOWED_MECHANISMS lists, allowed
   signing and rejection of a disallowed combined mechanism. See
   [dependency provenance](../vendor/README.md) and the
   [upstream fix](https://github.com/parallaxsecond/rust-cryptoki/pull/368).
2. **Enforced invalid session state across the API.** Previously a failed signing
   operation blocked only further signing: `info`, discovery, resolution, login and
   logout could still run on the suspect session. All session-backed operations
   now share the health gate. Search, object metadata and token-identity failures
   invalidate the session; subsequent calls return `Error::Closed`. Explicit close
   still attempts cleanup. Ordinary incorrect-PIN login can still be reported and
   handled on a standalone session without an implicit retry. Tests reproduce a
   failed context login, then verify rejection across the API and pool replacement.
3. **Enabled combined ECDSA context authentication.** The planner previously
   rejected ECDSA unconditionally for CKA_ALWAYS_AUTHENTICATE. Combined SHA-2/ECDSA
   mechanisms support init, context login, update and final, using the existing
   execution path. Pure tests cover all three digests and curves, token hashing
   policies and rejection of raw/digest alternatives. See
   [OASIS mechanism semantics](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html).
4. **Shared authentication and search handling.** Ordinary and context login use
   the same protected-path capability and token-identity checks. Context login now
   reads current capability instead of trusting the discovery snapshot. Search
   handling is shared by generic discovery and persistent-reference resolution.
   Signing borrows caller input when no transformation is needed, avoiding a full
   message copy while preserving software-hash and DigestInfo behavior.
5. **Updated development and validation paths.** The SoftHSM runner discovers
   Fedora and aarch64 Debian locations. CI tests both packaged SoftHSM and a pinned
   upstream build that must successfully sign with all three combined ECDSA/SHA-2
   mechanisms. Current documentation reflects the behavior and dependency cleanup;
   historical stage reports are explicitly marked.

Both the new planner test and the invalid-session integration assertions failed
against the original implementation before the fixes. Existing locator tests and
RFC grammar checks did not expose a defect requiring locator source changes.

## Validation

The host has Rust but no `cc`. Builds ran in an isolated Fedora 44 Podman container,
with GCC, SoftHSM and OpenSSL installed only there. Stable Rust was 1.97.1; the MSRV
lane used 1.85.0. OpenSSL 3.5.8 independently verified signatures and rejected
altered messages. The disposable container was removed after validation.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --locked` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --locked` | 34 ordinary tests and 8 doctests passed; 2 token suites ignored by default |
| Rust 1.85.0 locked check and workspace tests | Passed with the same test counts |
| `./tools/test-softhsm.sh`, packaged SoftHSM 2.7.0 | Both suites passed on stable and Rust 1.85 |
| Strict multipart ECDSA, pinned upstream SoftHSM | Both suites passed; all three SHA-2/ECDSA context-authenticated signatures independently verified |
| Shell syntax, local Markdown links and dependency/source checks | Passed |

SoftHSM 2.7 advertises combined ECDSA but disables multipart operations in
[its signing implementation](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/src/lib/SoftHSM.cpp).
The packaged-provider suite therefore checks its exact SignUpdate failure,
invalidated session and replacement; this is not counted as successful ECDSA
context authentication. Positive coverage used unmodified upstream commit
[884cb38f3d2012a0447bd5f50dbd29c429987c41](https://github.com/softhsm/SoftHSMv2/commit/884cb38f3d2012a0447bd5f50dbd29c429987c41),
built with OpenSSL. CI pins that same revision.

To require positive multipart coverage with an appropriately capable SoftHSM build:

```sh
PKCS11_TEST_MODULE=/absolute/prefix/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/prefix/bin/softhsm2-util \
PKCS11_TEST_REQUIRE_EC_MULTIPART=1 \
RUST_TEST_NOCAPTURE=1 ./tools/test-softhsm.sh
```

The workflow was updated but no remote CI execution was observed. This directory
has no Git metadata, so no commit or PR was created. The pre-edit source snapshot
is retained locally at `/tmp/pkcs11-stack-before-review.tar.gz`.

## Remaining boundaries

- Raw/prehashed always-authenticate requests still fail before signing. Cryptoki
  0.12.1 has no safe single-part signing continuation after a separate context
  login. Removing this limit needs an upstream API extension; no new unsafe FFI
  or replacement local dependency patch was introduced.
- Module advertisements are not proof of working parameter combinations or
  multipart support. Backend failures propagate without automatic signature or
  PIN retries, software-private-key fallback or provider-specific runtime bypasses.
- Hardware interoperability, hot unplug and positive protected-path authentication
  remain unverified. Metadata identity is not proof against an identically labeled
  replacement token. Existing module ownership and token-wide logout coordination
  requirements still apply.
- Client workflows, operational CLI commands and TLS integration remain the next
  stages, as requested. This pass adds no production provisioning, certificate
  trust or implicit key/certificate association behavior.
