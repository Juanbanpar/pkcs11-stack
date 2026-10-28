# Local cryptoki changes

Source: the published `cryptoki` 0.12.1 crate, upstream commit
[`ae5285f13458f16aa1b83491bd4db00cf332820c`](https://github.com/parallaxsecond/rust-cryptoki/tree/ae5285f13458f16aa1b83491bd4db00cf332820c/cryptoki).
The Apache-2.0 license and upstream copyright notices are retained.
Cargo's registry marker and VCS metadata files and the upstream lockfile are omitted.
Published crate SHA-256:
`625cf4599c43d69a16996ce2573fc80745a0b0300c962f0bfa11d55b6cab2b2d`.

Local changes:

- `src/session/object_management.rs`: add per-attribute bounded reads, and reject
  returned lengths exceeding allocated buffers before decoding, including when a
  provider incorrectly returns success. Existing reads use the same length checks.
- `src/object.rs`: decode validation versions from exactly two bytes, rejecting
  short and oversized values instead of indexing unchecked bytes.

- `src/object.rs`: preserve unknown numeric object, key, certificate, profile,
  validation and validation-authority types. Display vendor key types numerically
  instead of the literal `key_type`. Native metadata fixtures check decoding,
  malformed lengths and runtime/client policy boundaries.

- `src/object.rs`: decode `CKA_VALIDATION_VENDOR_URI` as its named attribute
  type, matching its existing encoding and byte-value representation.

- `src/mechanism/mod.rs`, `src/object.rs`: add parameterless full-tag
  SHA-512/224, SHA-512/256 and SHA3-224/256/384/512 HMAC mechanisms,
  matching key types and metadata names.

- `src/object.rs`: correct SHA-384, SHA-512 and SHA-224 HMAC key-type IDs;
  they previously reused the SHA-256 HMAC constant.

- `src/session/signing_macing.rs`: complete initialized single-part signing into
  caller-bounded storage without an output-length query or allocation.

- `src/mechanism/hkdf.rs`: bind borrowed salt to the parameter lifetime and
  return an empty slice for absent/empty info without constructing a slice from NULL.

- `src/mechanism/mod.rs`: add typed RFC 5649 `AES_KEY_WRAP_KWP` using its
  standard ID and default IV, without aliasing deprecated `AES_KEY_WRAP_PAD`.

- `src/mechanism/mod.rs`: preserve all numeric `CK_MECHANISM_TYPE` values,
  including identifiers without named execution variants. This also preserves
  unknown entries when decoding `CKA_ALLOWED_MECHANISMS` and `CKA_KEY_GEN_MECHANISM`.
- `src/mechanism/mod.rs`: add typed fixed-output SHA-512/224, SHA-512/256 and
  SHA3-224/256/384/512 digest mechanisms.
- `src/session/digesting.rs`: complete initialized single-part or multipart
  digests into an exactly sized buffer, with no native length query or retry;
  reject incorrect returned lengths.
- `src/context/slot_token_management.rs`: collect mechanism conversions without
  silently filtering errors.
- `src/context/mod.rs`, `src/context/interface.rs`, `src/error/mod.rs`: select
  known standard interfaces explicitly, validate pointers/versions/lifecycle
  functions, expose selection metadata, and support exact-version loading.
  Known 3.x version fields returned through C_GetFunctionList are retained for
  diagnostics, but only the legacy prefix is read and exposed.
  Automatic fallback accepts unavailable-interface responses, not general or
  host-memory failures. Regression fixtures use independent OASIS headers for
  each supported layout (`runtime/tests/interfaces.rs`).
- `src/session/signing_macing.rs`: expose single-part completion after explicit
  initialization so context login can occur before signing, without reinitializing.
- `src/session/decryption.rs`: expose bounded single-part completion after
  explicit initialization and context login. Output storage uses SecretBox before
  the native call so failed plaintext buffers zeroize as well as successful ones.
- `src/mechanism/mod.rs`: add combined SHA-224 RSA-PSS with native PSS
  parameters and named reverse conversions for SHA-224 signature/hash IDs.
- `src/mechanism/mod.rs`, `src/mechanism/rsa.rs`: add the twelve SHA-3 RSA/ECDSA
  signature mechanisms and four distinct SHA-3 MGF1 IDs, with named display,
  reverse conversion and native PSS parameter serialization.
- `rustfmt.toml`: retain upstream's 2021 formatting independently of the workspace.

The workspace uses this path dependency, including from the separate fuzz
workspace. Typed execution remains restricted by runtime planning and provider
capabilities. The PKCS#11 provider remains authoritative for mechanism validity.

Regression coverage is in runtime `tests/mechanisms.rs`, `tests/softhsm.rs` and
`tests/aes_gcm_provider.rs`. The provider suite compares discovery with native
SoftHSM output and exercises mixed allowed-mechanism lists. Return to a registry
dependency when an upstream release preserves these values and passes the tests.
