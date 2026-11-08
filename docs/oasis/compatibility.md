# OASIS PKCS#11 compatibility guide

This guide explains how `pkcs11-stack` relates to OASIS PKCS#11 2.40, 3.0, 3.1
and 3.2. It is deliberately narrower than a claim of conformance. Three layers
must agree before an operation is useful:

1. the OASIS standard defines the mechanism or function;
2. the published upstream dependency can represent and execute it safely;
3. the connected provider advertises it and permits it for the selected key and
   session.

This project can only provide the first two layers and a typed application path.
Provider behaviour is established by provider tests, never by compilation.

## Interface negotiation

`pkcs11-runtime` uses published `cryptoki` 0.12.1. That release already:

- requests the 3.2 interface through `C_GetInterface`;
- falls back to the 3.0 function list, then to the legacy 2.40
  `C_GetFunctionList`;
- stores the largest known function-list layout and exposes
  `is_fn_supported(Function)`;
- reports library metadata through `C_GetInfo`.

`Module::function_availability()` and `Module::supports_function()` expose the
selected list without invoking a function. The runtime never calls a function
because its name exists in the 3.2 specification.

The exact selected interface version is not exposed by published `cryptoki`
0.12.1. The runtime therefore reports:

- `C_GetInfo` Cryptoki/library versions (library metadata);
- per-function availability from the selected function list (interface
  behaviour).

It does not invent an interface-version selector. A module that implements only
legacy entry points still works through the upstream fallback.

## Supported families and operations

The following are implemented with published APIs and have runtime/client/CLI
coverage. Provider support is separate.

| Family | Implemented operations | Notes |
|---|---|---|
| RSA | key generation, PKCS#1 v1.5 and PSS sign/verify, OAEP encrypt/decrypt | SHA-1/224/256/384/512 combined mechanisms where upstream exposes them |
| ECDSA | key generation, sign/verify | P-256/P-384/P-521 |
| ECDH | key-pair generation, raw derivation, SHA-2 KDF profiles | token-held secrets only |
| EdDSA | upstream types available | not yet exposed by this branch |
| Montgomery | upstream key-generation types available | not yet exposed by this branch |
| AES | key generation, ECB/CBC/CBC-PAD, GCM single-part, CMAC, RFC 3394 wrap/unwrap | CBC/CBC-PAD added here; GCM and KW already existed |
| DES/3DES | upstream types available | not exposed by this branch; legacy only |
| SHA-1/SHA-2 | single-part and multipart digest | SHA-3 is upstream-blocked |
| HMAC | full-tag SHA-1/SHA-2 single-part and multipart | general-length and SHA-3 are upstream-blocked |
| SP 800-108 | counter, feedback, double-pipeline; HMAC-SHA-1/2 and AES-CMAC PRFs | added here |
| HKDF | extract-and-expand, token-held salt | already existed |
| ML-KEM | key generation, encapsulation, decapsulation, public import/export | already existed |
| ML-DSA | key generation, sign/verify, public export | already existed |
| SLH-DSA | key generation, sign/verify, public export, CLI generation/signing | added here; provider verification is pending |
| Objects | create, read, update, destroy, discover, copy (upstream), generate, wrap/unwrap, import certificate/data/public key | RSA/EC public-key import added here |
| Sessions | authentication, protected path, multipart operations, signature-first verification, cancellation (upstream types absent) | cancellation is upstream-blocked |

## Known upstream blockers

Published `cryptoki` 0.12.1 has no typed `MechanismType` conversion or
`Mechanism` variant for these standard mechanisms. The project does not use raw
FFI, a fork, duplicated bindings or a replacement engine to work around them.

| Area | Blocked identifiers |
|---|---|
| AEAD | `CKM_AES_CCM`, `CKM_CHACHA20_POLY1305`, `CKM_AES_XTS` |
| Key wrap | `CKM_AES_KEY_WRAP_KWP` (RFC 5649) |
| Password KDF | `CKM_PKCS5_PBKD2` |
| SHA-3 | `CKM_SHA3_*`, `CKM_SHA3_*_HMAC*`, `CKM_SHA3_*_RSA_*`, `CKM_ECDSA_SHA3_*` |
| SHA-512/t | `CKM_SHA512_224*`, `CKM_SHA512_256*`, `CKM_SHA512_T*` |
| General MAC | `CKM_*_HMAC_GENERAL`, `CKM_AES_CMAC_GENERAL` |
| Legacy | DSA, DH, RC2/RC4, IDEA, CAST, Blowfish, SSL/TLS PRF and most vendor families |
| Cancellation | no typed `C_SessionCancel` wrapper |
| Bounded output | no caller-bounded single-part/multipart completion |
| Interface selector | no public selected-interface metadata |

The full per-identifier list is in `coverage.md` and `inventory.json`. The
`UPSTREAM_BLOCKED` status means "cannot be executed without violating the
no-fork/no-raw-FFI constraints", not "the standard omits it".

## Implemented but not yet exposed or verified

| Item | State | Reason |
|---|---|---|
| EdDSA (Ed25519/Ed448) | upstream representable, not exposed | needs explicit key-kind/certificate handling across runtime/client/rustls |
| Montgomery (X25519/X448) | upstream representable, not exposed | same |
| HashML-DSA / HashSLH-DSA | upstream representable, not exposed | prehash parameter plumbing and policy not added in this branch |
| SLH-DSA CLI verification | client/runtime only | the CLI verification path is certificate-based; SLH-DSA certificates are not supported |
| Message-based AES-GCM | upstream representable, not exposed | bounded message-process ownership needs a dedicated API |
| Public-key import | implemented for RSA/named EC | SPKI validation, purpose policy and duplicate-ID checks |
| SLH-DSA provider verification | implemented, unverified on a provider | no unmodified provider build completed in the validation environment; an unmodified Kryoptic/OpenSSL build was attempted but failed at the OpenSSL link step |
| DSA/DH/legacy ciphers | upstream representable in part, not exposed | security policy and lack of typed variants |

## Provider evidence

The following runs were executed for this branch:

| Provider | Build | Tests | Result |
|---|---|---|---|
| SoftHSM | 2.7.0 (unmodified) | `tools/test-softhsm.sh`, including digest/HMAC/AES-CMAC/AES-CBC known answers, token RSA/ECDSA verification, CLI workflows, MAC key generation and public-key import | pass |
| SoftHSM PQC | pinned OpenSSL 3.5.9 + SoftHSM build (unmodified) | `tools/test-ml-dsa.sh` (runtime, client, CLI, TLS, desktop) | pass |
| Kryoptic | pinned SP 800-108 build (unmodified) | `tools/test-kem-hkdf.sh`, including KBKDF determinism/usable-output and CLI derivation tests | pass |
| Kryoptic | pinned build (unmodified) | `tools/test-ml-kem.sh` (runtime, client, desktop) | pass |
| All above | pinned provider builds | `./tools/test.sh` with the provider environment | pass |

The SoftHSM run covers RSA/EC signing, OAEP, AES-GCM, RFC 3394 wrap, HKDF, ML-DSA,
ML-KEM, TLS and the new digest/MAC/AES block operations. The Kryoptic run covers
ML-KEM, ECDH, HKDF, hybrid exchange, SP 800-108 and the related CLI/desktop
workflows.

Provider builds are disposable and unmodified. No provider source patch is part
of this branch. A provider that lacks a mechanism produces an explicit
`Unsupported*` error; it is never silently downgraded.

## Security boundaries

- Private and secret keys remain on the token. The runtime reads only public
  attributes and never exports private material.
- No software fallback exists for token-bound operations.
- `CKA_ALLOWED_MECHANISMS`, `CKA_SIGN`/`VERIFY`/`ENCRYPT`/`DECRYPT`/`DERIVE`,
  context authentication and provider flags are checked before execution.
- AEAD plaintext is returned only after authentication and exact-length checks.
- Failed operations mark the session unhealthy; it is not returned to the pool.
- State-changing operations are not retried.
- Decryption output is zeroizing and redacted in `Debug`.

## What this is not

This branch does not claim complete OASIS 3.2 support. It claims:

- every identifier in the locked 3.2 headers is represented in the inventory;
- every executable mechanism has a published upstream path;
- every executed operation has a runtime capability check;
- the listed providers pass the listed tests;
- every remaining gap is `UPSTREAM_BLOCKED`, not implemented, or not yet
  provider-verified, as recorded in `coverage.md`.
