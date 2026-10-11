# Stage 5: application client

Date: 2026-09-26. Workspace: `/var/home/xan/Documentos/Proxectos/pkcs11-stack`.

## Implementation

`pkcs11-client` now provides a synchronous application API over a runtime-owned
pool: full token URI selection, unique private/public key and certificate lookup,
public metadata, explicit attributes, capabilities, planning and signing.
Authentication is borrowed per call. The client retains no PINs, object handles or
cached execution plans. The application owns the module, pool capacity and policy.

`Certificate` parses exact DER X.509 with supported RSA or named EC public keys.
`bind_identity` proves an explicitly selected key/certificate association through
one token signature and independent public-key verification. `sign_identity`
verifies every result against the retained certificate, detecting object
replacement under an unchanged selector. Verification failure discards the lease.
Neither matching labels/IDs nor certificate parsing establishes trust.

The small runtime addition, `Module::resolve_token_uri`, enforces module, slot and
token constraints together and rejects ignored object/credential/vendor criteria.
Its location matching is shared with object resolution. Lifecycle, token signing,
authentication, pool accounting and session recovery stay in runtime.

The [API guide](../crates/pkcs11-client/README.md) contains a compiled usage example,
policy/authentication behavior and ownership constraints. [ADR 0008](adr/0008-client-identity.md)
records the association decision and verification dependencies. The shared isolated
SoftHSM runner now provisions application fixtures after the runtime tests finish.
CI installs OpenSC for that fixture provisioner in both provider lanes.

## Verification

Builds ran in a disposable Fedora 44 Podman container because the host lacks a C
linker. The workspace was mounted directly; target output, test token stores and
provider builds stayed in the disposable environment. Stable is Rust 1.97.1;
minimum Rust is 1.85.0. Rust 1.85 used a separate toolchain/target directory.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --locked` | Passed on stable and 1.85.0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed on stable |
| `cargo test --workspace --locked` | Passed on stable and 1.85.0: 39 ordinary tests and 10 doctests; 3 token suites ignored by default |
| `./tools/test-softhsm.sh`, Fedora packaged SoftHSM 2.7 | All 3 suites passed on stable and 1.85.0 |
| Pinned upstream SoftHSM, strict multipart requirement | All 3 suites passed on stable; 3 combined ECDSA context-authentication mechanisms verified |
| CI YAML, shell syntax and local documentation links | Passed |
| Cargo dependency boundaries | Passed |

Pure client tests verify independently generated OpenSSL signatures across RSA
PKCS#1 v1.5, explicit-salt RSA-PSS and P-256/P-384/P-521, with SHA-256/384/512 in
both message and prehash forms. They reject altered messages/signatures, wrong
PSS salt lengths, malformed/trailing certificate DER, invalid EC points,
unsupported keys and unsupported verification requests. P-521/SHA-256 is covered
explicitly. Policy tests cover digest and key restrictions and always-authenticate
limitations. Five workspace compile-fail doctests check ownership, including the
client/module lifetime.

Application SoftHSM acceptance checks:

- Unique, missing and ambiguous object/token selectors, plus full URI constraints.
- Public certificate access, private-key visibility, wrong PIN recovery and
  nonextractable/sensitive RSA and EC token key attributes.
- Correct bindings and rejection of unrelated RSA certificates of the same size.
- Bound message/prehash signing for every supported algorithm/digest combination;
  independent OpenSSL verification of a generic client-produced RSA signature.
- Context authentication for always-authenticate keys, pool exhaustion, explicit
  discard/reopen, concurrent calls and early unsupported-verification rejection.
- Replacement of an RSA key under the same selector while retaining its old
  certificate; bound signing rejects the replacement and another identity still works.

The upstream check built unmodified SoftHSM commit
`884cb38f3d2012a0447bd5f50dbd29c429987c41` in the disposable container and ran
`./tools/test-softhsm.sh` with its module/util paths and
`PKCS11_TEST_REQUIRE_EC_MULTIPART=1`. This validates both CI provider paths locally;
GitHub CI itself was not run. CLI help also passed.

The existing two runtime acceptance suites also passed. They retain the packaged
provider's exact known multipart ECDSA limitation check, without treating arbitrary
backend failures as success. Provider-specific evidence from the earlier review
is retained in [the implemented-stage report](implemented-stage-review.md).

## Dependency and scope boundaries

New compatible release lines are x509-cert 0.2.5 and RustCrypto rsa 0.9.10,
p256 0.13.2, p384 0.13.1 and p521 0.13.3, for certificate parsing and software
public-key verification. Existing locked package versions did not change.
Resolved metadata at Stage 5 confirmed that runtime was the only direct cryptoki
consumer, locator was independent of it, client and CLI did not depend on one
another, and rustls was confined to the adapter. All workspace licensing stays
MIT OR Apache-2.0; dependency/fixture provenance is recorded in ADR 0006.

The subsequent architecture revision, [ADR 0009](adr/0009-cli-library-reuse.md),
allows CLI to consume client in Stage 6 while retaining direct runtime access.
The graph verified above is historical; client must still never depend on CLI.

Certificate issuer/chain validation, dates, key usage, revocation and hostnames
remain application responsibilities. Bound PSS requires matching message/MGF1
digests; generic signing retains runtime's independent MGF1 support. RSA-PSS
restricted SPKI, other curves/algorithms, certificate-chain construction, TLS,
administration and key import/generation remain outside Stage 5. Raw/prehashed
always-authenticate remains an upstream cryptoki API limitation. Hardware and
positive protected-path behavior are not established by software-token tests.

No Git repository is present, so no commits or publication were performed.
The pre-stage backup is `/tmp/pkcs11-stack-before-stage5.tar.gz`.
Local validation logs are `/tmp/pkcs11-stage5-tests.log`,
`/tmp/pkcs11-stage5-msrv.log`, `/tmp/pkcs11-stage5-integration.log`,
`/tmp/pkcs11-stage5-msrv-integration.log` and
`/tmp/pkcs11-stage5-upstream-integration.log`. These are local evidence, not
portable repository artifacts. The disposable container was removed after checks.
Next stage: `pkcs11ctl`; the rustls adapter remains a later milestone.
