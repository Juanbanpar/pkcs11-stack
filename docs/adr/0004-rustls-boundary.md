# ADR 0004: rustls ends at the adapter

Status: implemented in Stage 7. Original decision: 2026-09-05; implementation: 2026-09-26.

## Decision

`pkcs11-rustls-adapter` alone depends on rustls. No rustls types, SignatureScheme,
TLS errors or credential-selection rules may appear in locator, runtime, client or
ctl. Support the released rustls 0.23 line, selected version 0.23.43, rather than
unreleased code or a matrix of compatibility shims.

The initial integration protects long-lived authentication private keys. The
application selects its ordinary software CryptoProvider for cipher suites,
record AEAD, hashing, HKDF, ephemeral exchange, peer verification and randomness.
The adapter neither implements a complete CryptoProvider nor installs a global
provider. Its production rustls dependency has default features disabled, with
`std` and optional `tls12`. Tests explicitly select ring.

The September 27 review adds `server_config_builder`, which restricts a clone of
the application's provider to cipher suites for the enabled protocol versions.
It retains suite preference order and returns rustls's ordinary builder for trust
and resolver configuration. In rustls 0.23.43, disabled TLS 1.3 suites can otherwise
admit an incompatible RSA credential for a TLS 1.2-only server when the client
offers ECDSA-only TLS 1.2 suites. Applications using rustls builders directly must
apply the same suite restriction. This adds no provider choice or trust policy to
the adapter.

## Interfaces inspected

Current `SigningKey` and `Signer` require Debug + Send + Sync. `choose_scheme`
returns an optional boxed Signer. `Signer::sign` receives an unhashed message and
returns scheme-specific signature bytes. `CertifiedKey` combines a certificate
chain and an Arc signing key; custom `ResolvesServerCert` and `ResolvesClientCert`
implement server and mTLS selection. Client selection receives issuer hints and
signature schemes. Keep token references out of `PrivateKeyDer`.

The adapter translates peer schemes into generic runtime requests. Runtime owns
mechanism/capability planning, message-versus-digest semantics and explicit policy
on software hashing. Availability must intersect token mechanisms, mechanism
metadata, key type/size/curve, key attributes, allowed mechanisms and policy;
the adapter adds TLS constraints. Subject-key information, never the issuer's
certificate signature algorithm, informs the key's capabilities.

Convert PKCS#11 ECDSA r || s to TLS DER in the adapter unless a later generic
signature representation deliberately changes that boundary. Use known mechanism
and curve widths, not first-byte format guessing. RSA-PSS hash, MGF and salt
parameters must be explicit. Requiring Send + Sync does not make a cryptoki
session shareable: signers must acquire exclusive runtime session access.

## Consequences

Stage 7 implements `Credential`, server and client resolvers, and runtime-owned
pools sharing `Arc<Module>`. A binding probe and every later signature are verified
against an immutable leaf with the supplied provider. Scheme selection includes
provider public-key verification support. Credential callbacks run once per
operation, never during resolver/scheme selection; PINs are not retained.

Server routing uses explicit SAN-checked DNS names, with a default only for absent
SNI. Client routing checks schemes and configured-chain issuer hints. Chain trust,
time and usage validation remain normal rustls peer-verification policy. Restricted
RSA-PSS SPKI and EdDSA are not supported. Ring-based acceptance rejects P-521 because
that provider lacks its verifier. Full server/mTLS handshakes, failure cases and
ownership checks are recorded in the [Stage 7 report](../stage-7-report.md).
No hardware assurance follows from software-token tests. Source: [rustls 0.23.43 custom-key
manual](https://docs.rs/rustls/0.23.43/rustls/manual/howto/index.html) and
[Signer API](https://docs.rs/rustls/0.23.43/rustls/sign/trait.Signer.html).
