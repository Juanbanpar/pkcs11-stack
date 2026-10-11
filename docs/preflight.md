# Stage 0 upstream preflight

Checked 2026-09-05. Release sources were downloaded from crates.io and inspected
outside the workspace. No implementation code was copied. Findings below guide
later milestones; no PKCS#11 module or software token was loaded during Stage 1.

## Released dependencies

[ADR 0006](adr/0006-licensing.md) records versions, declared MSRVs, licenses and
consumers for all seven important direct dependencies. The selected Rust minimum
is 1.85. The following current interfaces were inspected, not inferred from old
release examples:

- cryptoki 0.12.0: `Pkcs11::new`, `initialize(CInitializeArgs)`, explicit consuming
  `finalize`, session close/drop, USER/SO/context-specific login, attribute and
  mechanism discovery, object lookup, and single/multipart signing. Safe loading
  exists, so the skeleton needs no unsafe escape hatch. `CInitializeArgs::new`
  accepts locking flags; the reserved-pointer constructor is unsafe and is not
  part of this workspace's initial scope. [Context source](https://docs.rs/crate/cryptoki/0.12.0/source/src/context/mod.rs),
  [session source](https://docs.rs/crate/cryptoki/0.12.0/source/src/session/mod.rs),
  [signing source](https://docs.rs/crate/cryptoki/0.12.0/source/src/session/signing_macing.rs).
- `Pkcs11` clones share loaded-library state, but do not establish a coordinated
  initialization/finalization owner. Sessions are Send, not Sync, and close on
  Drop unless explicitly configured otherwise. Dropping the context is not a
  substitute for explicit C_Finalize. Exclusive leases and shutdown coordination
  therefore remain runtime responsibilities. [ADR 0003](adr/0003-session-ownership.md)
  records the always-authenticate gap in one-shot signing.
- rustls 0.23.43: `SigningKey`, `Signer`, `CertifiedKey`, `ResolvesServerCert` and
  `ResolvesClientCert` support external signing. Signer input is an unhashed
  message. Client resolution has issuer hints and offered schemes; server
  resolution receives ClientHello. `SigningKey::public_key` optionally exposes
  SPKI. [Signing API](https://docs.rs/rustls/0.23.43/rustls/sign/index.html),
  [server resolver](https://docs.rs/rustls/0.23.43/rustls/server/trait.ResolvesServerCert.html),
  [client resolver](https://docs.rs/rustls/0.23.43/rustls/client/trait.ResolvesClientCert.html).
- rustls-pki-types 1.15.1 separates `CertificateDer`, `SubjectPublicKeyInfoDer`
  and `PrivateKeyDer`. Token references are not private-key DER. The adapter's
  direct certificate-type dependency does not leak rustls into generic crates.
  [API](https://docs.rs/rustls-pki-types/1.15.1/rustls_pki_types/).
- secrecy 0.10.3 provides `SecretBox`, `SecretString` and explicit `ExposeSecret`,
  with redacted Debug and zeroization on drop. zeroize 1.9.0 provides `Zeroize`
  and `Zeroizing` for owned temporary buffers. Neither retroactively erases copies
  created by callers, formatting or allocation. No secret-bearing API exists yet.
  [secrecy](https://docs.rs/secrecy/0.10.3/secrecy/),
  [zeroize](https://docs.rs/zeroize/1.9.0/zeroize/).
- thiserror 2.0.20 derives typed Error implementations and retains underlying
  sources via source/from attributes. Do not put raw PIN-bearing input into
  errors. clap 4.6.6's builder API suffices for CLI help/version, so its derive
  feature is not enabled. [thiserror](https://docs.rs/thiserror/2.0.20/thiserror/),
  [clap builder tutorial](https://docs.rs/clap/4.6.6/clap/_tutorial/index.html).

## Specification findings

[PKCS#11 v3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.pdf)
was used as the v3.x baseline, not a claim that all modules implement it.
Sections 5.4 and 5.6 require attention to shutdown versus active calls and
shared USER/SO login state. Context-specific reauthentication follows operation
initialization (section 4.9). Protected authentication uses a null PIN after
checking the token flag. Removal invalidates operational state; handles must be
rediscovered. Mechanism discovery alone is insufficient: key permissions and
CKA_ALLOWED_MECHANISMS constrain usage. RSA-PSS specifies hash, MGF and salt
length parameters; ECDSA represents r and s as fixed-width concatenated integers,
which requires explicit conversion for TLS. These constraints reinforce the
runtime/adapter split and require future device tests.

[RFC 7512](https://www.rfc-editor.org/rfc/rfc7512.html), sections 2.3–2.7 and 6,
requires dedicated syntax and matching semantics: path attributes use semicolons,
query attributes use ampersands, and CKA_ID is binary. Reject duplicate path
attributes; distinguish omitted selectors from present empty values. Treat unknown
path constraints conservatively. URI comparison needs attribute-specific
normalization, not raw string equality. `pin-source` and `pin-value` together
should be rejected. Parsing an external PIN source must not itself execute a
command or fetch a secret. Normal formatting must redact `pin-value`.

[p11-kit URI API](https://p11-glue.github.io/p11-glue/p11-kit/manual/p11-kit-URIs.html)
separates parse/format from object/token/module matching and marks unrecognized
URI parts so matching fails rather than silently broadening selection. Its C API
is a behavioral reference; it is not a runtime dependency or a Rust API template.

## Reference ecosystem

| Reference inspected | Finding and consequence |
| --- | --- |
| [OpenSC pkcs11-tool manual](https://github.com/OpenSC/OpenSC/blob/master/doc/tools/pkcs11-tool.1.xml) | Scope extends beyond signing to PIN/token administration, object templates, mechanisms, wrapping, derivation and thread tests. This supports a CLI that directly consumes runtime. No option compatibility is promised. |
| [libp11 README](https://github.com/OpenSC/libp11) | Wraps PKCS#11 for applications and OpenSSL integration; its locking and session pooling show why shared lifecycle is substantial infrastructure. Do not copy its ownership model or API. |
| [OpenSSL PKCS#11 provider configuration](https://github.com/openssl-projects/pkcs11-provider/blob/main/docs/provider-pkcs11.7.md) | OpenSSL-specific controls include login behavior, session/PIN caching and vendor quirks. Those concerns inform later runtime policy, but OpenSSL dispatch and URI-in-PEM conventions do not belong in this design. |
| [OxiCrypto PKCS#11 adapter 0.3.0](https://docs.rs/crate/oxicrypto-adapter-pkcs11/0.3.0) | Documents cryptoki-backed sessions, a pool and optional rustls signing. Its broad provider surface is outside this project's initial TLS scope. Its README claims rustls lacks Ed25519 schemes, contradicted by rustls 0.23.43's `SignatureScheme::ED25519`; do not inherit that assumption. Its first-byte ECDSA format heuristic is also unsuitable: raw r can begin with 0x30. Use known mechanism/curve encoding. |

References are evidence, not proof of correctness or permission to copy. Direct
license compatibility and third-party fixture/vector policy are in ADR 0006.
No software-token or real-hardware interoperability has been tested. API and
behavioral findings must be rechecked before the corresponding functional stage.
