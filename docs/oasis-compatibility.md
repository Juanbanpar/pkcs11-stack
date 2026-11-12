# OASIS PKCS#11 compatibility

`pkcs11-stack` targets PKCS#11 2.40, 3.0, 3.1 and 3.2 through the published
`cryptoki` 0.12.1 API. This is a support matrix, not a claim of formal OASIS
conformance. A mechanism is listed as implemented only when the runtime, client,
CLI and, where applicable, desktop have a typed path through the published API.

## Interface negotiation

`cryptoki` requests the 3.2 interface, then the 3.0 function list, then the
legacy 2.40 list. The runtime exposes per-function availability and library
metadata. It does not invent a selected-interface selector because the published
API does not expose one.

## Implemented mechanisms

| Family | Operations | Notes |
|---|---|---|
| RSA | key generation, PKCS#1 v1.5/PSS sign/verify, OAEP encrypt/decrypt | SHA-1/224/256/384/512; SHA-1 and SHA-224 are opt-in |
| ECDSA | key generation, sign/verify | P-256/P-384/P-521; SHA-1 and SHA-224 are opt-in |
| ECDH | key-pair generation, raw derivation, SHA-2 KDF profiles | token-held secrets only |
| EdDSA | Ed25519/Ed448 generation, sign/verify, import/export | pure original-message profile; context authentication is blocked |
| Montgomery | X25519/X448 generation, import/export, ECDH derivation | `CKD_NULL`, X9.63 and SP 800-56A SHA-2 KDFs |
| AES | key generation, ECB/CBC/CBC-PAD, GCM single-part, CMAC, RFC 3394 wrap/unwrap | caller-managed nonce for GCM |
| SHA-1/SHA-2 | single-part and multipart digest | SHA-3 is blocked upstream |
| HMAC | full-tag SHA-1/SHA-2 single-part and multipart | general-length MACs are blocked upstream |
| SP 800-108 | counter, feedback and double-pipeline | HMAC-SHA-1/2 and AES-CMAC PRFs |
| HKDF | extract-and-expand with token-held salt | SHA-1/224/256/384/512 |
| ML-KEM | generation, encapsulation, decapsulation, public import/export | RFC 9935 SPKI |
| ML-DSA | generation, sign/verify, public export | explicit parameter sets, context and hedging |
| HashML-DSA | sign/verify with SHA-2/SHA-3/SHAKE message profiles; SHA-2 caller digests | provider-tested on Kryoptic |
| SLH-DSA | generation, sign/verify, public export | provider-tested on Kryoptic; independent OpenSSL verification |
| HashSLH-DSA | sign/verify with SHA-2/SHA-3 message profiles; SHA-2 caller digests | dedicated HashSLH-only key generation |
| Objects | create/read/update/destroy/discover, generate, wrap/unwrap, import/export | RSA/EC/EdDSA/Montgomery public-key import |
| Sessions | authentication, protected path, multipart operations, session pooling | cancellation is blocked upstream |

### Application surfaces

`Runtime` is the typed execution layer. `Client`, `CLI` and `Desktop` are
application surfaces. A dash means no typed application operation; it does not
imply that the provider lacks the mechanism.

| Operation | Runtime | Client | CLI | Desktop |
|---|---|---|---|---|
| Module/token discovery | Yes | Yes | Yes | Yes |
| Session authentication and pooling | Yes | Yes | Yes | Yes |
| Object discovery and metadata read | Yes | Yes | Yes | Yes |
| Key/certificate generation and import | Yes | Yes | Yes | Yes |
| Object delete and public export | Yes | Yes | Yes | Yes |
| Object relabel | Yes | Yes | Yes | — |
| Token and PIN administration | Yes | Yes | Yes | Yes |
| Random bytes | Yes | Yes | Yes | Yes |
| RSA key generation | Yes | Yes | Yes | Yes |
| RSA PKCS#1 v1.5 / PSS sign and verify | Yes | Yes | Yes | Yes |
| RSA-OAEP encryption/decryption | Yes | Yes | — | Yes |
| ECDSA key generation, sign, verify | Yes | Yes | Yes | Yes |
| ECDH key generation | Yes | Yes | Yes | Yes |
| Raw ECDH derivation | Yes | Yes | — | Yes |
| EdDSA key generation, sign, verify | Yes | Yes | Yes | Yes |
| Montgomery key generation and derivation | Yes | Yes | Yes | Yes |
| AES key generation | Yes | Yes | Yes | Yes |
| AES-ECB / CBC / CBC-PAD | Yes | Yes | Yes | — |
| AES-GCM single-part | Yes | Yes | Yes | Yes |
| AES-CMAC | Yes | Yes | Yes | — |
| AES key wrap/unwrap | Yes | Yes | — | Yes |
| SHA-1/SHA-2 digest, single-part and multipart | Yes | Yes | Yes | — |
| HMAC, single-part and multipart | Yes | Yes | Yes | — |
| HKDF extract-and-expand | Yes | Yes | Yes | Yes |
| SP 800-108 counter/feedback/double-pipeline | Yes | Yes | Yes | — |
| ML-KEM generation, encapsulation/decapsulation | Yes | Yes | Yes | Yes |
| ML-DSA generation, sign, verify | Yes | Yes | Yes | Yes |
| HashML-DSA sign, verify | Yes | Yes | Yes | Yes |
| SLH-DSA generation, sign, verify | Yes | Yes | Yes | Yes |
| HashSLH-DSA sign, verify | Yes | Yes | Yes | Yes |
| Public-key import | Yes | Yes | Yes | Yes |
| Certificate import/export | Yes | Yes | Yes | Yes |
| Cancellation | — | — | — | — |
| Message-based AES-GCM | — | — | — | — |

## Upstream-blocked

These identifiers or operations cannot be implemented through published
`cryptoki` 0.12.1 without a fork, raw FFI, duplicated bindings or unsafe code.

| Area | Blocked identifiers or capability |
|---|---|
| AEAD | `CKM_AES_CCM`, `CKM_CHACHA20_POLY1305`, `CKM_AES_XTS` |
| Key wrap | `CKM_AES_KEY_WRAP_KWP` |
| Password KDF | `CKM_PKCS5_PBKD2` |
| SHA-3/SHAKE | `CKM_SHA3_*`, SHA-3/SHAKE HMAC, RSA and ECDSA combinations |
| SHA-512/t | `CKM_SHA512_224*`, `CKM_SHA512_256*`, `CKM_SHA512_T*` |
| General MAC | `CKM_*_HMAC_GENERAL`, `CKM_AES_CMAC_GENERAL` |
| Cancellation | no typed `C_SessionCancel` wrapper |
| Bounded output | no caller-bounded single-part or multipart completion |
| Message-based AEAD | no parameterless message-init AES-GCM variant and no bounded message completion |
| Initialized single-part signing | no single-part completion after explicit `sign_init`; context-authenticated EdDSA is rejected |
| Interface metadata | no public selected-interface selector |
| Legacy | DSA, DH, RC2/RC4, IDEA, CAST, Blowfish, most PBE and vendor mechanisms |

Context-authenticated EdDSA is rejected at generation and signing. SLH-DSA
context authentication remains provider-dependent and was not exercised by the
pinned provider lane.

## Provider evidence

| Provider | Build | Coverage |
|---|---|---|
| SoftHSM | 2.7.0, unmodified | classical signing/OAEP, digest/HMAC/AES, SHA-1/SHA-224 opt-in, EdDSA, TLS, CLI and desktop workflows, public-key import |
| SoftHSM PQC | pinned OpenSSL 3.5.9 + SoftHSM, unmodified | ML-DSA runtime/client/CLI/TLS/desktop |
| Kryoptic | pinned SP 800-108 build, unmodified | ML-KEM, ECDH, HKDF, hybrid exchange, CLI/desktop derivation |
| Kryoptic | pinned all-features build, unmodified | SLH-DSA, HashSLH-DSA, HashML-DSA, Montgomery, ML-KEM, ECDH, HKDF, CLI/desktop workflows |
| NSS | optional lane | no NSS module was available in this environment |

Provider stores are temporary. Provider builds are unmodified; no provider patch
is part of this repository.

## Security boundaries

- Private and secret keys remain on the token; no key value is logged or exported.
- There is no software fallback for token-bound operations.
- Authentication, usage flags, `CKA_ALLOWED_MECHANISMS`, session permissions and
  provider capabilities are checked before execution.
- AEAD plaintext is released only after authentication and exact-length checks.
- Failed or incomplete operations do not return sessions to the pool.
- State-changing operations are not retried.
