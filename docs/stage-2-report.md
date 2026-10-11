# Stage 2: pkcs11-locator

Historical Stage 2 completion record. For current runtime work, see
[Stage 3](stage-3-report.md).

Implemented the hardware-independent locator milestone. The runtime, client, CLI
and rustls adapter remain scaffold-only. No module loading or Stage 3 work was
introduced. Crate names remain as requested and original material remains
MIT OR Apache-2.0.

## Implementation

- `src/uri.rs`: validated URI storage, construction, typed errors, object classes,
  deterministic rendering, protected query values and explicit secret serialization.
- `src/codec.rs`: strict component-specific percent decoding and deterministic
  encoding, with binary IDs and zeroizing decode buffers.
- `src/matcher.rs`: separate discovered identities and borrowed selector views;
  complete module/slot/token/object matching through `ResourceIdentity`.
- `tests/locator.rs`: 22 public-API integration tests with no external token.
- Crate README: two compiling examples and explicit parsing/matching/secret policies.

The URI retains vendor attributes and empty constraints. Unknown path criteria
prevent matching, whereas unknown query data is retained and ignored by built-in
matching. Standard duplicates and invalid grammar fail with typed errors that
never include input. Binary CKA_ID never passes through a UTF-8 conversion.

Debug and Display redact PIN values and sources. Full serialization requires
`to_secret_uri`, which returns SecretString; access requires ExposeSecret.
The serialization buffer reserves its encoded size before secrets are written.
No PIN-source interpretation, file access, command execution or module loading
occurs. Caller-owned input and copies made after explicit exposure remain the
caller's responsibility.

## Design decisions and limits

[ADR 0002](adr/0002-object-identity.md) now records the Stage 2 API and policies.
A complete match must include all discovery context. Per-level selector views
are explicitly partial, and no API resolves ambiguity by selecting the first
candidate. URI-to-URI equivalence and resource uniqueness are not claimed.

Text matching is exact UTF-8 without implicit normalization. Fixed-width metadata
padding is removed from discovered fields only. Module paths use platform-specific
absolute-path validation and exact matching; discovery will later resolve whether
a path denotes a file or directory. Slot IDs fit u64 here; a runtime must check
the native module's CK_ULONG range. Duplicate vendor query values retain their
order. Arbitrary vendor query values are not treated as PINs in URI Display.

The README describes every policy for duplicate/unknown attributes, empty values,
unknown classes, malformed escapes, text, binary data and serialization.
No dependencies were added. Cargo metadata verified that locator still depends
only on secrecy, zeroize and thiserror and has no direct or transitive dependency
on cryptoki, runtime, rustls or clap.

## Verification

Passed locally on stable Rust 1.97.0:

```sh
cargo test -p pkcs11-locator
cargo clippy -p pkcs11-locator --all-targets -- -D warnings
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Passed on the declared minimum Rust 1.85.0:

```sh
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
```

Both toolchains pass 22 integration tests and two documentation examples. Tests
include all 256 ID bytes, UTF-8 and byte limits, malformed grammar, every metadata
constraint, full-context matching, missing/empty distinction, authentication
conflicts, all formatting surfaces and parser/builder round trips. Bounded input
sweeps cover 1,728 short path strings and 432 query strings without adding a test
framework dependency. The initial missing test-crate documentation warning was
fixed; no lint checks were weakened. Existing stable/MSRV CI will run these tests
without a PKCS#11 implementation. Remote CI was not executed in this workspace.

## Sources reviewed

RFC 7512 sections 2.3–2.7 and 3 were revisited for syntax, construction and matching:
[specification](https://www.rfc-editor.org/rfc/rfc7512.txt).
The [p11-kit URI API](https://p11-glue.github.io/p11-glue/p11-kit/manual/p11-kit-URIs.html)
was reviewed as a behavioral reference for unknown-constraint matching. The
implementation and tests are independently authored; two short RFC URI examples
are attributed in the test source. No reference implementation code was copied.

Next milestone: Stage 3, pkcs11-runtime foundation. It has not started.
