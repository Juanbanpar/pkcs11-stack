# Testing

The default test command includes unit, property, documentation and provider tests,
including ML-DSA, ML-KEM, hybrid key exchange and the desktop backend. Build the
trusted software providers once, then run:

```sh
bash tools/build-pqc-softhsm.sh /absolute/path/to/softhsm-pqc
./tools/build-kem-hkdf-provider.sh /absolute/path/to/kdf-provider
PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/softhsm-pqc/openssl/bin/openssl \
PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
./tools/test.sh
```

Install SoftHSM, OpenSC, OpenSSL and Python 3 for the runners below. Provider
builds additionally require Git, a C/C++ toolchain, Make, Perl, Autoconf, Automake,
Libtool, Clang/libclang, pkg-config and SQLite development files. Desktop requires
its normal native build dependencies. All token stores are temporary. Missing
PQC support fails the relevant suite; no PQC or desktop opt-in flag is used.

Run unit, property and documentation tests without a PKCS#11 module:

```sh
cargo test --workspace --locked
python3 tools/check-dependencies.py
```

Tests cover URI parsing and redaction, selection ambiguity, ownership, signing
plans, certificate verification, CLI input/output, and TLS signature encoding.
Mechanism metadata retains standard, unknown and vendor-defined numeric IDs.
ML-DSA software tests use public OpenSSL fixtures without a provider. They cover
message/context mismatches, malformed SPKI/certificates and repeated-hint signature
encodings, including the regression described by GHSA-5x2r-hc65-25f9.
Compile-fail examples check that modules, sessions and objects cannot be used
outside their owner lifetimes.

## OASIS compatibility coverage

The target interface range is 2.40 with Errata 01, 3.0, 3.1 and 3.2. This is a
consumer application; advertised mechanisms do not imply executable algorithms
or formal conformance. Coverage is recorded per capability below.

| Capability | Status | Frontends and evidence |
| --- | --- | --- |
| Known interface negotiation and exact version selection | Implemented | Runtime/client; CLI `--interface-version`; desktop displays automatic selection. Native Unix ABI fixtures compile against all four official header sets. |
| Null/mismatched interface rejection and unavailable-interface fallback | Implemented | Native Unix fixtures cover lifecycle pointers, provider failures, interface-only modules, multiple interfaces and known 3.x version fields on legacy tables. |
| Context authentication for raw/prehashed and combined RSA/ECDSA signing | Implemented | Runtime/client/CLI/desktop; independent OpenSSL verification on disposable SoftHSM keys, including missing/wrong PIN and recovery checks. |
| Native RSA/ECDSA verification | Implemented | Runtime/client; CLI `verify-token`; desktop public-key verification. Provider tests check signature/digest profiles, permission/allow-list rejection, mismatches and session reuse; OpenSSL independently verifies the test signatures. |
| Context-authenticated RSA-OAEP decryption | Implemented | Runtime/client; CLI OAEP commands; desktop context credentials. OpenSSL interoperability runs on the required SHA-2 OAEP provider lane. Failed RSA-OAEP and AES-GCM plaintext buffers zeroize. |
| Fixed-output SHA-2/SHA-3 token digests | Implemented | Runtime single-part/multipart, client reader, CLI and desktop file hashing. OpenSSL comparisons cover ten hashes; native fixtures exercise flags, missing pointers, bounded output and failure/discard paths. Reader tests cover interruption, bounds and read failure. |
| Optional public metadata and validation diagnostics | Implemented | Runtime/client bounded public inspection, CLI public-metadata and desktop profiles/validation snapshots; same-session flag API and explicit fresh-session CLI diagnostic. Unknown IDs/bits are preserved, and reported validation state is not a trust decision. |
| Opaque numeric object metadata | Implemented | Runtime/client preserve unknown object/key/certificate/profile/validation IDs; CLI/desktop retain mixed listings and show numeric class/key types. Independent 3.2-header fixtures on a legacy table cover native-width maxima, malformed lengths and provider errors; typed operation/export/import restrictions remain. |
| Explicit session cancellation | Implemented | Runtime/client `cancel_operations` and consuming digest guards. Only CKR_OK restores reuse; failed updates cannot be repaired, and drop does not cancel implicitly. Kryoptic/provider and independent header fixtures cover the lifecycle. |
| Remaining operation expansion, metadata compatibility and explicit legacy policy | Pending | The function inventory and remaining M3/L1 tasks below define scope, dependencies and acceptance tests. |
| Encryption-purpose RSA generation | Implemented | Runtime/client/CLI/desktop; key permissions, size/identity bounds, duplicate IDs, RO rejection, export policy and OAEP use of generated keys. |
| Explicit SHA-2 OAEP/MGF1 digests and binary labels | Implemented | Runtime/client/CLI/desktop; all nine digest combinations interoperate with OpenSSL through 2.40. Tests cover empty/binary/bounded labels, plaintext limits, mismatches, context authentication and output preservation. |
| Validated RSA/EC public-key import | Implemented | Client validation and runtime component templates; CLI/desktop explicit purpose. Tests cover all three curves, RSA verification/encryption, malformed/restricted inputs, permissions, duplicate IDs, RO rejection, normalization and unchanged same-ID private keys through the 2.40 interface. |
| SHA-224 signatures | Implemented | RSA PKCS#1 v1.5, RSA-PSS and ECDSA with explicit runtime policy and CLI/desktop choices. Native 2.40-header encodings, OpenSSL fixtures and SoftHSM round trips; existing policy defaults and TLS schemes remain unchanged. |
| SHA-3 signatures | Implemented | SHA3-224/256/384/512 with RSA PKCS#1 v1.5, RSA-PSS and ECDSA. Independent 3.0-header parameter/DigestInfo checks, OpenSSL fixtures and pinned SoftHSM combined/raw/prehashed operations; client/CLI/desktop selection and existing cipher/KDF restrictions. |
| Remaining classical algorithm expansion | Pending | Tasks C4–C5 below track deferred context/prehash, agreement and algorithm profiles. |
| Explicit ECDH SHA-2 KDFs and output purposes | Implemented | Runtime/client/CLI/desktop; Kryoptic tests cover ANSI X9.63 and SP 800-56A SHA-256/384/512, all three curves, AES output and 64-byte generic output followed by HKDF. OpenSSL supplies independent ECDH/HKDF calculations. |
| HKDF extract-only and expand-only | Implemented | Runtime/client/CLI/desktop; SHA-256/384/512, hash-length derivation-only PRKs, explicit stages and rejected disabled parameters. Existing calls still extract and expand. OpenSSL checks each stage; client/CLI/desktop compare separate and combined derivation. |
| HKDF token-held salt keys | Implemented | Runtime/client/CLI/desktop; extraction and combined derivation use native CKF_HKDF_SALT_KEY, same-session resolution and sensitive, nonextractable generic/HKDF salt keys of 1–4096 bytes with derivation permission. Kryoptic outputs match OpenSSL for all three hashes and short/hash-length/long salts. Client/CLI/desktop compare token and byte salts. Native fixtures check exact fields without value reads, permissions, lengths and failed-session handling. |
| Full/general SHA-2/SHA-3 HMAC | Implemented | Runtime/client/CLI/desktop; ten SHA-224/256/384/512, SHA-512/224, SHA-512/256 and SHA3-224/256/384/512 profiles, generic and matching typed keys, bounded full/general tags with a half-hash minimum, algorithm-restricted generic key generation, permission rejection and reusable mismatches. SoftHSM/Kryoptic results match OpenSSL, including shorter Kryoptic keys. Kryoptic exercises all ten profiles; SoftHSM exercises its advertised subset. The pinned Kryoptic advertises 0/0 generic-generation bounds; full-tag generation is rejected there and exercised on SoftHSM. Native fixtures check every general length, all ten mechanism IDs/parameter layouts, generation templates, missing pointers, flags and malformed outputs. CLI/desktop check explicit tag selection, stale profiles, reusable mismatches and output preservation. General-only generation templates are fixture-tested; the pinned providers do not expose compatible general-HMAC generation capabilities. HMAC key-type IDs have round-trip regressions. |
| Full/general AES-CMAC generation and verification | Implemented | Runtime/client/CLI/desktop; AES-128/192/256 and OpenSSL comparisons, authentication-only key generation, RO use, permission and allow-list rejection, verification mismatches and output preservation. Native fixtures check entry points, flags, fixed output bounds and failed-session handling. General CMAC uses explicit native 8–16-byte parameters with all three AES sizes, independent OpenSSL prefix comparisons, general-only key generation, exact-length verification, permission rejection and stale frontend profiles. Kryoptic requires both profiles; SoftHSM retains its advertised full-tag profile. Independent 2.40 fixtures check CK_MAC_GENERAL_PARAMS and bounded output failures. |
| SP 800-108 counter/feedback HMAC-SHA-2 | Implemented | Runtime/client/CLI/desktop; HMAC-SHA-256/384/512, 32-bit big-endian counter and output bit length, separator and one output key. Feedback uses an omitted or hash-length public IV. Kryoptic results match OpenSSL for all AES sizes and generic outputs through 4096 bytes, empty/binary/maximum label/context and generic/typed bases. Native fixtures verify both native layouts, null iteration fields and omitted IVs, counter placement, bit-based bounds, permissions and failure health. Frontends check mode selection, IV validation/clearing, output agreement and stale selections. |
| Remaining symmetric algorithms, MACs and KDF expansion | Pending | Existing AES-GCM, explicit KW/KWP, constrained HKDF and ECDH profiles. GMAC, SP 800-108 double-pipeline mode/other PRFs and PBKDF2 remain pending. |
| AES-KW/KWP key transfer | Implemented | Runtime/client/CLI/desktop; explicit selection and default IVs. Kryoptic/OpenSSL comparisons cover all AES wrapping/target sizes, output permissions, trust/extractability rejection, RO/duplicate-ID rejection, mismatches and tampering. SoftHSM retains the KW workflow. No deprecated PAD alias or fallback. |
| HashML-DSA, SLH-DSA and additional TLS signatures | Pending | Existing pure ML-DSA and ML-KEM profiles remain supported. |
| Legacy algorithm execution | Pending | No legacy opt-in or algorithms are enabled yet. |

The native fixtures require a C99 compiler (`cc`) on Unix and run with the normal
runtime tests. They exercise independent function-table layouts and are not
cryptographic provider tests. Windows builds compile the Rust interfaces; native
fixture execution there is not covered by this runner.

### Function inventory and operation acceptance tests

This inventory covers all functions in the pinned [official headers](../crates/pkcs11-runtime/tests/fixtures/headers/README.md):
68 in 2.40, 92 in both 3.0 and 3.1, and 104 in 3.2. Compare function contracts
with [the 3.2 specification, section 5](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.pdf).
"Used" means at least one supported runtime workflow calls the function; it does
not promise a generic wrapper, every mechanism, or provider conformance. Pointer
presence and numeric mechanism recognition alone do not count as implementation.

The 59 functions used by current workflows are:

| Workflow | Functions | Implementation / evidence |
| --- | --- | --- |
| Lifecycle and interface selection | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`, `C_GetInterface` | Runtime `module.rs`, binding `context/interface.rs`; `interfaces.rs` tests all four header layouts. |
| Slot/token/mechanism discovery and initialization | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_InitToken` | Runtime `module.rs`; native mechanism comparisons and disposable-token administration tests. |
| Owned sessions and authentication | `C_OpenSession`, `C_CloseSession`, `C_GetSessionInfo`, `C_Login`, `C_Logout`, `C_InitPIN`, `C_SetPIN` | Runtime `session.rs`, `administration.rs`, `pool.rs`; USER/SO/context roles, protected path, cleanup and identity tests. |
| Object discovery, explicit reads and mutations | `C_CreateObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` | Runtime `session.rs`, `administration.rs`; client import/inspection and frontend stale-selection tests. |
| Single-part encryption/decryption | `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt` | OAEP and AES-GCM modules; OpenSSL comparisons, context login and failed-plaintext zeroization. |
| Single/multipart public-data hashing | `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestFinal` | Runtime `digest.rs`, client reader; native failure fixtures and OpenSSL comparisons. |
| Single-part signatures/MACs | `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify` | RSA/ECDSA, EdDSA, ML-DSA, HMAC and CMAC modules; permission, mismatch, context-login and output-bound tests. |
| Selected generation, derivation and key transfer | `C_GenerateKey`, `C_GenerateKeyPair`, `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey` | Generation, ECDH/HKDF/SP800-108 and AES-KW/KWP modules; templates, duplicate IDs, RO rejection and provider comparisons. |
| Multipart signatures and MACs | `C_SignUpdate`, `C_SignFinal`, `C_VerifyUpdate`, `C_VerifyFinal` | Runtime/client exclusive full/general HMAC and AES-CMAC guards, plus RSA PKCS#1/PSS and named-curve ECDSA guards; zeroizing 64 KiB client readers. Independent 2.40/3.0/3.1/3.2 fixtures cover parameters, missing multipart pointers, independent permissions, fixed output, failures, explicit cancellation and abandoned sessions. SoftHSM/Kryoptic tags agree with OpenSSL across chunk boundaries and empty input; Kryoptic requires all ten HMAC hashes, general profiles, large readers and confirmed cancellation followed by new MACs. Pure ML-DSA signing now exposes exclusive guards and client readers; all three parameter sets, hedge modes and empty/255-byte contexts are checked against single-part token verification and RustCrypto. OpenSSL independently verifies streamed signatures for all three sets and a 256 KiB chunked reader. All ML-DSA signing output is caller-bounded. Classical signing follows token/software hashing policy with bounded output and context login after init; OpenSSL and client certificate checks cover all eight digests and empty/chunked/large input. Kryoptic ECDSA confirms cancellation and same-pool-session reuse. EdDSA streaming remains provider-gated; ML-DSA streaming verification uses the signature-first API in O6. |
| O3 Implemented: explicit cancellation | `C_SessionCancel` | Runtime/client explicit flags and consuming digest guards. Independent 2.40/3.0/3.1/3.2 fixtures check exact/combined/empty flags, table/pointer gates, unsupported stubs, partial cancellation failure, pending/error results, no legacy fallback, discarded failures and confirmed pool reuse. Kryoptic proves active digest cancellation followed by a new digest; legacy providers require closure. |
| Provider random generation | `C_GenerateRandom` | Runtime `session.rs`, client `random.rs`; length, permission and unavailable-provider tests. |
| ML-KEM | `C_EncapsulateKey`, `C_DecapsulateKey` | Runtime/client ML-KEM, CLI/desktop exchange; required Kryoptic lane. |
| O5 Implemented: session validation diagnostics | `C_GetSessionValidationFlags` | Runtime/client same-session last-operation query; CLI fresh-session diagnostic. `session_validation.c` checks all selected interface versions, missing pointer, unsupported stub, zero, opaque bits, independent session state and fatal provider errors. No certification/trust inference. |
| O6 Implemented: ML-DSA signature-first verification | `C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal` | Runtime/client explicit single-part and exclusive streaming workflows, with zeroizing 64 KiB readers. Independent 3.2 headers check argument order, context/signature lifetimes, exact selected-table/pointer gates, independent public-key permissions, empty input, completed mismatches and init/update/final/read/drop failures. Explicit cancellation uses the standard NULL-mechanism init and tests no generic/legacy fallback. Required Kryoptic tests cover all ML-DSA parameter sets, contexts, hedge modes, independent RustCrypto/OpenSSL verification, large readers and cancellation followed by reuse of the same pooled session. |
| O2 Partial: bounded multipart AES-GCM | `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal` | Runtime/client exclusive guards and zeroizing 64 KiB readers with explicit plaintext budgets through 16 MiB. Independent 2.40/3.0/3.1/3.2 headers check GCM parameters, direction-specific permissions/pointers, output bounds, split tags, budget errors, pending/error results, failed/abandoned sessions and explicit cancellation. Native update plaintext stays in zeroizing quarantine until final authentication; later failures wipe it. SoftHSM NIST vectors cover all AES key sizes and chunk boundaries; client readers cover empty and 1,000,003-byte input. CLI `--multipart` file/stdin workflows preserve single-part defaults and gate output on authentication, checked closure and finalization; injected native cleanup failures release no output. Kryoptic requires cancellation followed by new operations and reuse of the same pooled session. |

The remaining 45 functions are classified below. **Planned** means a concrete
extension to an existing workflow; **deferred** needs the stated use case or
provider/design gate; **excluded** conflicts with the current application boundary.
These are application scope decisions, not statements that OASIS forbids a function.
Versions identify the earliest table in the supported range, not a mechanism's
minimum usable provider interface.

| ID / status | First table | Functions | Acceptance criteria or scope gate |
| --- | --- | --- | --- |
| O1 Partial: streaming signatures/MACs | 2.40 | Covered above | Runtime/client implement native full/general HMAC and AES-CMAC, RSA PKCS#1/PSS and named-curve ECDSA streaming, plus pure ML-DSA signing streams. Classical guards/readers preserve hashing policy, context login, bounded output and completed-mismatch reuse, with read/update/final/drop failure tests. Remaining: pure EdDSA multipart support with an implementing provider and CLI/desktop file workflows. ML-DSA streaming verification is implemented in O6; the older verification API is single-part for that mechanism. Preserve existing single-part APIs. |
| O2 Partial: streaming encryption | 2.40 | Covered above | Bounded AES-GCM guards/readers are implemented, with authenticated plaintext release only after finalization, zeroizing quarantine, explicit input budgets and native/provider failures covered. CLI file/stdin workflows implement explicit multipart selection and checked output commit; native fixtures inject session-close/finalization failures. Remaining: desktop multipart file integration and a bounded staging design for a larger-file profile. Single-part execution remains the CLI default. |
| O4 Planned: named-user login | 3.0 | `C_LoginUser` | Explicit username/role/PIN input, redacted diagnostics, protected-path and token-wide authentication rules. Test wrong username/PIN, SO/RO conflicts and unavailable tables/pointers; no fallback to anonymous `C_Login` or second authentication attempt. |
| O7 Deferred: message-based AEAD | 3.0 | `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal`, `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`, `C_MessageDecryptFinal` | Agree on an explicit message/nonce/AAD contract and find a provider supporting it. Test multiple messages per initialization, distinct nonces, tag/output bounds, finalization, failure cleanup and authenticated output release. Existing single-part GCM remains independently supported. |
| O8 Deferred: message-based signatures/MACs | 3.0 | `C_MessageSignInit`, `C_SignMessage`, `C_SignMessageBegin`, `C_SignMessageNext`, `C_MessageSignFinal`, `C_MessageVerifyInit`, `C_VerifyMessage`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`, `C_MessageVerifyFinal` | Require a concrete batched-message use case and provider. Test per-message parameters/authentication, exact tag/signature lengths, mismatches, process finalization and stale-session rejection. |
| O9 Deferred: authenticated key transfer | 3.2 | `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated` | Define the supported AEAD wrapping profile and nonce/AAD transport. Native/provider tests must cover integrity failure, trust and wrapping templates, duplicate output IDs, output permissions and cleanup. Do not introduce private-key import implicitly. |
| O10 Deferred: asynchronous sessions | 3.2 | `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin` | Separate explicit async-session design retaining buffers/keys/module until completion or confirmed cancellation; test pending/completion/join races and shutdown. Current synchronous sessions do not request `CKF_ASYNC_SESSION`. |
| O11 Deferred: interface/event diagnostics | 2.40 / 3.0 | `C_WaitForSlotEvent`, `C_GetInterfaceList` | Explicit diagnostic or hotplug requirement first. Test nonblocking no-event behavior, removal/reinsertion, identity revalidation and shutdown; interface enumeration must preserve unknown names/versions without interpreting their table layouts. |
| O12 Deferred: additional object management | 2.40 | `C_CopyObject`, `C_GetObjectSize` | Copy needs an explicit object-class/template policy and new identity, with copyability, RO, permission non-escalation and duplicate-ID tests. Size reporting must distinguish unavailable from zero and not describe storage size as key strength. |
| O13 Deferred: state serialization / combined pipelines | 2.40 | `C_GetOperationState`, `C_SetOperationState`, `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` | Require a real resumable/combined workflow and a design for potentially sensitive state, same-token key binding, exclusive ownership and both operation lifetimes. No generic state export or pipeline API is currently promised. |
| O14 Deferred: signature recovery | 2.40 | `C_SignRecoverInit`, `C_SignRecover`, `C_VerifyRecoverInit`, `C_VerifyRecover` | Legacy-policy review and an actual interoperability requirement before adding recovery mechanisms; no implicit raw-RSA or deprecated-mechanism enablement. |
| O15 Excluded: global session teardown | 2.40 | `C_CloseAllSessions` | Would close sessions outside the current owner/pool. Retain checked closure of owned sessions. |
| O16 Excluded: secret digestion / host RNG seeding | 2.40 | `C_DigestKey`, `C_SeedRandom` | No workflow for publishing digests of token-held secrets or injecting host RNG seed material. Providers requiring seeding remain unsupported until an explicit entropy-source contract is designed. |
| O17 Excluded: legacy parallel-function control | 2.40 | `C_GetFunctionStatus`, `C_CancelFunction` | No legacy parallel-function mode; neither is a replacement for session cancellation. |

### Metadata and classical algorithm backlog

The following tasks replace the broad operation/metadata and classical-algorithm
entries above. Existing typed metadata reads are already available through
`Object::read_attributes` and `ManagementSession::inspect`; missing frontend
presentation is separate from missing binding support.

| ID / priority | Concrete gap | Acceptance tests |
| --- | --- | --- |
| M1 Implemented | Unknown numeric object/key/certificate/profile/validation/authority IDs survive inspection and display; mixed discovery retains familiar and unfamiliar objects. | `opaque_metadata.c` uses independent 3.2 headers with a legacy table. Runtime/client/CLI/desktop tests cover unknown standard/vendor values and native-width maxima. Short/oversized scalars and provider errors invalidate runtime sessions. Signing, verification, MAC, cipher, derivation and typed key export/import still reject unsupported types. Raw public certificate/data export remains available; unsupported RFC 7512 classes have no locator. |
| M2 Implemented | Shared client public metadata profile for unique IDs, public-key-info, profile objects/IDs, validation objects/attributes and object validation flags. CLI `public-metadata` and desktop inspection share the profile. | Independent 3.2 headers on a legacy table cover available/empty/sensitive/type-invalid/unavailable metadata, the 65,536-byte boundary, oversized/changing lengths, malformed scalar/version/SPKI values and provider failures. Unknown algorithm SPKI remains inspectable without enabling execution. Optional fields are queried without table-version gates; browser summaries defer ordinary key metadata until selection. Limits also cover identity reads during selection. Native length errors invalidate sessions; malformed DER is a client validation error. RFC 7512 selectors and CKA_ID association remain unchanged; URI metadata is never fetched and does not establish trust. |
| M3 Deferred | Nested array/template metadata, including wrapping/derivation templates, needs a bounded typed inspection contract. | Independent headers must verify array flags, element layout and length arithmetic; malformed/nested/provider-changing lengths must not become unbounded allocations. Preserve sensitive/invalid status without reading secret values. Native providers remain authoritative for operation templates. |
| C1 Implemented | SHA-224 RSA PKCS#1 v1.5, RSA-PSS and ECDSA signing/verification, defined in the 2.40 headers. | `sha224.c` checks exact 28-byte digest/DigestInfo, combined IDs, native PSS layout with independent MGF/salt, raw/prehashed/combined paths, context login order, permission rejection, malformed output and provider failure. OpenSSL fixtures cover RSA/PSS and P-256/P-384/P-521; SoftHSM covers runtime/client/CLI/desktop signing and verification. Explicit policy enables SHA-224; existing default digests, binding preference and TLS schemes remain unchanged. OAEP/HKDF/ECDH/SP800-108 reject SHA-224 in this profile. |
| C2 Implemented | SHA3-224/256/384/512 RSA PKCS#1 v1.5, RSA-PSS and ECDSA signing/verification (3.0 mechanisms). | `signature_encodings.rs` shares authentication, permissions, output and provider-failure checks across SHA-224 and SHA-3. `sha3.c` uses independent corrected 3.0 headers and fixed abc vectors; exact digest/DigestInfo, combined IDs, native PSS layout and four distinct MGF IDs are checked through a legacy table. OpenSSL fixtures cover RSA/PSS and P-256/P-384/P-521; SoftHSM checks combined token, software-hashed and caller-prehashed signing/native verification. Software verification rejects equal-length SHA-2 message profiles for SHA-3 signatures. Client binding/options and CLI/desktop choices require explicit policy/selection, retain defaults, and recheck live capabilities. OAEP/HKDF/ECDH/SP800-108 reject SHA-3 in existing profiles; TLS schemes are unchanged. |
| C3 Implemented | Pure Ed25519 and Ed448 with generation, public metadata/import/export, signatures, certificate binding and frontend choices (3.0 mechanisms). | RFC 8032 empty-message vectors and independent OpenSSL certificates/signatures; strict RFC 8410 SPKI parsing and canonical public-point/signature checks. Independent 3.0-header fixtures check RFC 8410 OID versus RFC 8032 curve-name parameter forms, field-bit bounds, permissions, missing pointers, bounded output, authentication order and session failure behavior. SoftHSM exercises both curves, empty messages, public import/export, mismatches, always-authenticate, certificate binding and replacement-key rejection. CLI/desktop expose separate pure-message choices and reject classical hashing/context parameters. |
| C4 Deferred | EdDSA context/prehash variants; Montgomery X25519/X448 agreement; further ECDH KDFs and digest profiles. | Explicit per-variant parameter and input contracts, independent vectors and an implementing provider. Never emulate prehash EdDSA by signing a digest with the pure mechanism. Agreement needs public-input/noncontributory-key handling, protected outputs and HKDF interoperability without secret extraction. |
| C5 Deferred | Other standard digests/MACs such as BLAKE2b or parameterized SHA-512/t, additional AEAD such as AES-CCM/ChaCha20-Poly1305, and additional RSA/EC key-transfer constructions. | Choose a concrete profile and provider before expanding the app. Specify output/nonce/AAD/key permissions and independent vectors. Token digest discovery alone does not prove a combined signature, KDF or TLS profile exists. |
| L1 Planned policy review | Explicit legacy opt-in and an enumerated interoperability requirement for each legacy algorithm. Existing defaults remain restricted. | Default-deny tests across libraries/frontends, explicit requested operation/profile, no downgrade after provider rejection, and independent verification for every enabled legacy profile. Presence in an older standard is not itself a reason to enable an algorithm. |

`validation_metadata.c` now exercises `CKA_VALIDATION_VENDOR_URI` through a
legacy function table compiled with independent 3.2 headers. It checks present,
empty, type-invalid and sensitive values plus provider-failure session health.
`newer_metadata_attribute_ids_round_trip` covers the named public/profile/validation
attribute IDs. The vendor-URI reverse conversion and M1 numeric preservation are
implemented. `public_metadata.c` adds bounded optional/profile/validation coverage;
`session_validation.c` checks O5 through independently compiled layouts. These
synthetic fixtures test metadata and lifecycle behavior, not provider certification.

The upstream SoftHSM CI lane sets `PKCS11_TEST_REQUIRE_EDDSA=1` for both pure
EdDSA curves, including CLI/desktop provider workflows. It also sets
`PKCS11_TEST_REQUIRE_SHA3_SIGNATURES=1` and
requires all SHA-3 signature profiles across runtime/client/CLI/desktop. The
packaged lane retains its existing provider subset; header and offline OpenSSL
fixture tests cover every SHA-3 digest independently of provider availability.

Signature streaming fixtures compile against all four supported header versions.
They check context-login order, native PSS parameters, DigestInfo/digest bytes,
missing raw/multipart pointers, hashing-policy selection before init, output bounds,
protected paths, failed/abandoned operations and explicit cancellation. The upstream
lane requires combined ECDSA multipart success; packaged 2.7.0 rc1 advertises combined
ECDSA but rejects updates. That rejection must discard its session, while explicitly
selected software hashing remains tested. A client binding test deliberately replaces
the rsa key; streaming tests use the untouched wrong-key fixture and its own matching
certificate. The Kryoptic build's ecc_min feature supplies ECDSA for cancellation and
pool-reuse proof; RSA cancellation is checked by independent native fixtures.

C1–C3 are implemented. C4/C5 require choosing an explicit profile and provider;
L1 requires a concrete legacy interoperability requirement. Keep additions in
signed atomic runtime/client and frontend commits with native/provider evidence.
O3 is implemented for the currently supported synchronous operation classes.
O1 MAC and classical signature streaming follow the exclusive digest guard and
cancellation tests. Pure ML-DSA signing streams are implemented with independent
3.2 parameter-layout and failure fixtures, legacy/current table selection, and
compile-fail context/ownership checks. O6 implements signature-first ML-DSA
verification, including streaming readers and operation-specific cancellation.
Kryoptic's generic session cancellation does not clear its separate signature-first
operation slot; NULL-mechanism C_VerifySignatureInit terminates it explicitly under
section 5.15.7. Provider tests require a new verification and same-generation pool
reuse after cancellation.
The pinned SoftHSM source supports ML-DSA signing updates but explicitly disables
EdDSA multipart operations. EdDSA streams remain provider-gated; frontend file
workflows remain planned. O2 implements bounded AES-GCM multipart workflows and
client readers. CLI `--multipart` supports files/stdin with checked output commit;
larger-file staging and desktop multipart integration remain open.
Keep unconfirmed operations discarded on legacy providers. GMAC, additional
SP800-108 modes/PRFs, PBKDF2, HashML-DSA/SLH-DSA and TLS extensions remain separate
backlog items in the coverage table. Provider gaps do not justify implicit software
fallback or weakening existing metadata/permission checks.

Completing any row requires meaningful negative/failure tests, the applicable
independent-header/provider lane, existing-profile regressions, MSRV/format/lint
checks and frontend stale-selection/output tests where a frontend is affected.
Hardware interoperability, native Windows ABI execution and real-provider general
HMAC key generation remain validation gaps, not completed features. This inventory
is not an exhaustive mechanism-by-mechanism conformance claim.

## SoftHSM integration

Install SoftHSM, OpenSC, OpenSSL and Python 3, then run:

```sh
./tools/test-softhsm.sh
```

The runner creates temporary token storage and removes it on exit. It provisions
nonextractable RSA/EC keys, runs the ignored integration tests and
[signing/TLS examples](../docs/examples.md), and verifies signatures independently
with OpenSSL. It covers authentication, object mutations, pool recovery, key
replacement, and server/mutual TLS. Generation tests check all three ECDH curves
and signing-only RSA/EC permissions. Mechanism discovery is compared with a
native SoftHSM query; mixed allowed-mechanism lists preserve permitted GCM use
and reject keys that allow only other mechanisms. Generation tests also check AES
sizes, permissions, duplicate identities, public export and rejected secret
export. ECDH agreement, AES encryption and RFC 3394 round trips verify generated
key use without exporting private material. CLI and desktop tests cover the new
generation choices, rejected option combinations, permissions and export rules.
Desktop tests also exercise generated ECDH and wrapping keys through the worker.
Use this runner only with SoftHSM, never an existing token store or a hardware module.

For another SoftHSM installation:

```sh
PKCS11_TEST_MODULE=/path/to/libsofthsm2.so SOFTHSM2_UTIL=/path/to/softhsm2-util ./tools/test-softhsm.sh
```

Desktop backend integration runs without opening a window.

Set the historical `PKCS11_TEST_REQUIRE_EC_MULTIPART=1` flag to require all three
combined ECDSA context-authentication profiles; signing now uses single-part
completion after initialization and context login.
CI tests packaged SoftHSM and a pinned upstream build with multipart ECDSA,
SHA-2 OAEP and ML-DSA enabled. The upstream run reuses one provider build for
classical and ML-DSA workflows.

### PQC provider compatibility

The ML-DSA runner uses pinned, unmodified OpenSSL 3.5.9 and SoftHSM sources.
The ML-KEM and KDF runners use the unmodified Kryoptic build, which also enables
ML-DSA for required signature-first verification tests:

```sh
bash tools/build-pqc-softhsm.sh /absolute/path/to/softhsm-pqc
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/softhsm-pqc/openssl/bin/openssl \
PKCS11_TEST_MODULE=/absolute/path/to/softhsm-pqc/lib/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/absolute/path/to/softhsm-pqc/bin/softhsm2-util \
./tools/test-ml-dsa.sh

PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
PKCS11_TEST_PQC_OPENSSL=/absolute/path/to/kdf-provider/openssl/bin/openssl \
./tools/test-ml-kem.sh
```

Building requires Git, a C/C++ toolchain, Make, Perl, Autoconf, Automake and
Libtool. OpenSSL uses static PIC libraries, so the test module does not require
changes to the system OpenSSL installation or library search path.

The `softhsm-integration` and `kryoptic-integration` CI jobs require ML-DSA-44/65/87 and
ML-KEM-512/768/1024 across the libraries, CLI and desktop. TLS tests also require
hybrid key exchange. Missing mechanisms, parameter sets or entry points fail.
SoftHSM's advertised ML-KEM bounds are incorrect, so ML-KEM runs on Kryoptic;
no provider source patch or runtime metadata workaround is applied. Signature-first
ML-DSA tests run in the same Kryoptic lane, with all three parameter sets and a
1,000,003-byte client reader. RustCrypto covers empty and nonempty messages with
empty, binary 255-byte and ASCII contexts; OpenSSL also verifies the nonempty ASCII
context cases. Its pkeyutl command rejects zero-byte oneshot input, so empty-message
verification uses the native and RustCrypto paths.

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
including always-authenticate keys. Signing-stream checks also cover all hedging
modes, deterministic equivalence, empty/255-byte contexts, and a 256 KiB reader
with short/Interrupted reads. The provider stress input stays bounded because
SoftHSM formats its accumulated ML-DSA message on every update, even with debug
logging disabled. This does not establish provider memory or throughput bounds.
CLI tests generate all three parameter sets,
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

## Persistent ML-KEM and HKDF

Build the pinned Kryoptic and OpenSSL sources, then run runtime/client/CLI/desktop tests:

```sh
./tools/build-kem-hkdf-provider.sh /absolute/path/to/kdf-provider
PKCS11_TEST_KDF_MODULE=/absolute/path/to/kdf-provider/libkryoptic_pkcs11.so \
./tools/test-kem-hkdf.sh
```

Building requires stable Rust, Git, Clang/libclang headers, a C/C++ toolchain,
Make, Perl, pkg-config and SQLite development files. The module statically links
the pinned OpenSSL 3.5.9. Kryoptic's source revision is pinned; its upstream Cargo
dependencies are resolved at build time because upstream does not supply a lockfile.
`PKCS11_TEST_KDF_OPENSSL` selects the independent OpenSSL HKDF/KBKDF reference command.

The runner creates a temporary Kryoptic SQLite store and removes it on exit.
Use it only with Kryoptic. No existing token store is opened or reset.
The helper enables SP 800-108 alongside ML-KEM, HKDF and the other tested mechanisms.
The `kryoptic-integration` CI job requires these mechanisms without skipping missing
support. It compares SHA-256/384/512 results against OpenSSL using public
hash-length inputs, including empty salt/context and maximum SHA-256 output.
Separate extraction and expansion are checked independently against OpenSSL for
all three digests; client, CLI and desktop tests compare staged and combined
AES derivation and reject inputs for disabled stages.
Tests inspect output permissions, reject unsuitable bases, wrong hash lengths,
read-only sessions and duplicate output IDs, and check client export refusal.

The Kryoptic runner also requires CKM_AES_CMAC_GENERAL. Runtime, client, CLI and
desktop tests cover all 8–16-byte general tags on AES-128/192/256 keys. Runtime
and CLI results match the prefixes of independent OpenSSL CMAC outputs. Both
full-only and general-only generation templates are inspected; each rejects the
other native profile. Native fixtures compile against the independent 2.40
headers and check parameter widths, permissions, missing pointers, verification
mismatches and malformed output handling. SoftHSM keeps full-tag coverage.

Counter/feedback SP 800-108 tests compare native HMAC-SHA-256/384/512 outputs with
OpenSSL KBKDF using a 32-bit counter, separator and sum-of-keys bit length. Feedback
checks omitted and hash-length IVs for all three digests; invalid IVs are rejected
before native calls. The original counter-mode API/CLI defaults are preserved. Tests
cover all AES output sizes, multi-block generic outputs through 4096 bytes,
empty/binary/maximum label/context, generic and matching typed bases, permissions,
read-only sessions and duplicate IDs. Client, CLI and desktop independently
compare AES-GCM results with runtime-derived reference keys. A native fixture
checks parameter layout, bit-based mechanism bounds and failed-session behavior.

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

The SoftHSM runner tests AES-GCM with a 96-bit nonce and 128-bit tag. Runtime
fixtures select 12 NIST CAVP known-answer vectors across AES-128/192/256,
including empty input/AAD and non-block-aligned messages. Tests reject changes to
nonce, AAD, ciphertext and tag, and verify failed-session invalidation without
returning plaintext. They also cover RO execution, permissions, allowed mechanisms,
wrong key classes/types, generated keys and request/output redaction.

Client tests cover typed requests, bounded preflight, private export refusal and
checked closure. CLI and desktop file tests cover explicit nonce/AAD parameters,
raw-format round trips, tampered inputs, empty messages, output preservation and
no plaintext release on authentication failure. Desktop forms reject stale
choices/pickers and clear parameters on submission or navigation. Kryoptic additionally exercises ML-KEM → HKDF → AES-GCM for all
three KEM parameter sets and an application hybrid-derived AES key.

Multipart provider tests reuse the NIST vectors with empty, one-byte, block-boundary
and 64 KiB chunks. Client readers cover all AES key sizes with empty and
1,000,003-byte messages, short/Interrupted reads, tampering and checked closure.
Kryoptic tests cancellation in both directions followed by new operations and
reuse of the same pooled session. Its native decryption updates return partial
plaintext; SoftHSM withholds output until finalization. The runtime quarantines
any native update output, checks the configured budget and exact final length,
and releases plaintext only after authentication. Independent-header fixtures
cover both output behaviors, malformed lengths, short buffers, early/final native
failures, discarded operations, split tags and unavailable multipart pointers.
Runtime unit tests inspect scratch storage to verify immediate wiping after an
update error, including plaintext from earlier successful updates. CLI fixtures
also check explicit multipart selection with missing single-part pointers, legacy
and 3.2 interfaces, stdin, regular-file bounds, input aliases, reserved-file cleanup,
read errors, and withholding output on authentication/session-close/finalization
failure. SoftHSM tests require all AES key sizes, empty and 1,000,003-byte messages,
single-part/multipart interoperability, stdin/stdout, tampering and stdin overrun.
These tests do not constitute algorithm validation.

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
