# Stage 7 completion report

Completed locally on 2026-09-27 in Fedora 44, with Rust 1.97.1 and the minimum
supported Rust 1.85.0. The [accepted specification](stage-7-spec.md) is implemented.
The Stage 6 CLI dependency model remains unchanged; its proposed client-only
refactor is deferred.

## Delivered behavior

`pkcs11-rustls-adapter` now supplies rustls signing keys/signers and server/client
certificate resolvers. Applications provide a runtime pool, explicit private-key
selector, leaf-first DER chain, signing policy, credential source and software
crypto provider. No token private key is exported into `PrivateKeyDer`.

Loading proves the key/leaf association by signing a domain-separated probe. Every
TLS signature is verified against the retained leaf, so replacing a key behind an
unchanged selector fails closed. Subject public-key information determines key
capabilities independently of the certificate issuer's signature algorithm.

TLS scheme choice intersects peer offers, key type/curve, runtime planning/policy
and provider verification support. RSA-PSS sets matching hash/MGF and digest-sized
salt. RSA PKCS#1 v1.5 is available for TLS 1.2; rustls excludes it in TLS 1.3.
ECDSA maps P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512, converting fixed-width
PKCS#11 signatures to canonical DER. Runtime receives messages and retains control
of token/software hashing policy. Restricted RSA-PSS SPKI, EdDSA and SHA-1 are not
implemented. Provider support may narrow the scheme set further.

Server resolution validates registered DNS names against leaf SANs, preserves
application ordering among compatible keys and treats unknown SNI as a miss. An
explicit default applies only to absent SNI. Client resolution uses offered schemes
and DER issuer-name hints from the configured chain. Empty hints allow any
compatible configured identity. Trust roots, chain ordering, dates and usage
policy remain the application's responsibility through normal rustls verification.

Credential sources run once per binding/signing operation, not during resolution
or scheme selection. Returned USER/context PINs are zeroizing and are not cached.
Context authentication is explicit. Signing is synchronous, takes one exclusive
runtime lease and does not retry authentication or an uncertain operation. Pool
exhaustion returns immediately; suspect sessions are discarded.

## Ownership and dependencies

Runtime adds `SessionPool::new_owned(Arc<Module>, ...)`, preserving borrowed APIs
and their compile-fail guarantees. Owned sessions retain the initialization owner
until after raw session closure. The existing pool handles capacity, authentication,
health and recovery; no independent pool, worker, unsafe self-reference, leaked
reference or second initialization was added. Explicit shutdown drops consumers
and pools before unwrapping the final module Arc and calling `finalize`.

The adapter remains independent of client and CLI. Runtime remains the only direct
cryptoki consumer. Production selects no software TLS provider; default features
support TLS 1.3, with opt-in `tls12`. Tests select ring explicitly. The dependency
checker now rejects TLS dependencies outside the adapter and software provider
selection in the adapter's production graph. Cargo.lock changes only dependency
edges: no package version was added, removed or updated. Licensing metadata and
MSRV were checked; details are in [ADR 0006](adr/0006-licensing.md).

## Validation

Passed locally:

- Formatting, workspace check, all-target Clippy with warnings denied, and dependency
  boundary checks.
- 48 ordinary tests on Rust 1.97.1 and Rust 1.85.0, including adapter scheme/policy/
  provider intersection, ECDSA DER encoding and credential redaction.
- Twelve documentation tests on both toolchains, including six compile-fail
  ownership checks and the new server configuration example.
- Separate production adapter builds with default features disabled and with
  `tls12`, plus a production dependency graph containing neither ring nor aws-lc.
- All five isolated SoftHSM suites on stable with packaged SoftHSM 2.7.0.
- All five suites on stable with pinned upstream SoftHSM commit
  `884cb38f3d2012a0447bd5f50dbd29c429987c41`, built using OpenSSL and without GOST.
  The strict runtime lane verified all three combined ECDSA context-authentication
  mechanisms. The packaged provider's known multipart limitation remains explicit.
- All five packaged SoftHSM suites on Rust 1.85.0.

The TLS suite verifies all eight generated private keys are sensitive and
nonextractable. It completes a 24-handshake TLS 1.2/1.3 matrix: RSA/P-256/P-384 and
always-authenticate RSA servers, each with no client authentication, an RSA client,
and an EC client. Each success exchanges application data in both directions.
Additional successes cover PKCS#1-only TLS 1.2, absent SNI with an explicit default,
and two concurrent mutual-TLS handshakes.

Negative cases cover PKCS#1-only TLS 1.3, incompatible schemes/curves, P-521 with
ring, empty chains, mismatched key/certificate binding, unknown SNI, SAN registration
mismatch, wrong trust roots, unrelated client issuer hints, missing required client
certificates, missing context credentials, unavailable credential source and a bad
context PIN. Callback counters verify no hidden retry and no acquisition during
scheme selection. Exhaustion and explicit discard recover on later operations.
Replacing a nonextractable RSA key under the same selector invalidates bound
signatures while an unrelated identity remains usable. Owned-pool checks prove
module lifetime survives the external Arc and ends after the final pool is dropped.

The CI workflow now checks production feature configurations and runs the TLS suite
in both existing software-token lanes. These are local results; no remote CI run or
publication is claimed. Test storage is disposable and cleaned by the runner.

## Remaining acceptance limits

Ring cannot verify P-521 in this configuration; its credential is rejected before
TLS use. P-521 encoding tests do not establish positive P-521 TLS interoperability.
Hardware, hot-unplug and positive protected-path behavior remain separate acceptance
work. Raw/prehashed always-authenticate operations retain the documented cryptoki
single-part limitation. Software-token results are not hardware assurance.

The adapter implements authentication signing and credential selection, not a full
CryptoProvider or chain-validation policy. No Git commit or publication was created.
