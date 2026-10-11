# Stage 6: pkcs11ctl

Date: 2026-09-26. Workspace: `/var/home/xan/Documentos/Proxectos/pkcs11-stack`.

## Delivered behavior

The CLI implements twenty command families for discovery, inspection, signing,
binding, diagnostics and token/PIN/object administration. The
[CLI guide](../crates/pkcs11ctl/README.md) documents invocation, authentication,
output contracts and limits; the [specification](stage-6-spec.md) records scope.
The rustls adapter remains the Stage 7 milestone and has not been implemented.

Client is reused for selected-key workflows, capabilities, signing plans,
certificate parsing, binding and signature verification. Runtime handles raw
inspection, module/session ownership, authentication and all token operations.
CLI owns arguments, input files, PIN acquisition, command sequencing, JSON/text
presentation and exit codes. It adds no cryptoki dependency or independent pool.

New runtime administration APIs provide exclusive module-level initialization,
USER PIN initialization/reset, USER/SO PIN changes, explicit-template creation and
attribute updates, object destruction and sensitive/nonextractable RSA or named
EC signing-key generation. Mutation failures invalidate the session, including
unwinds; pure RW-mode rejection leaves a healthy session usable. There is no
operation retry or rollback. Attribute updates can have partial provider effects.

Client now exposes `CertificateDocument`, sharing the existing exact DER parser
while allowing public metadata extraction for unsupported signing algorithms.
Certificate import uses real subject/issuer/serial DER attributes, including for
Ed25519 certificates. `Certificate` still validates only supported signing keys.
Its public request preflight lets CLI reject unsupported bound parameters before
the binding signature. Raw certificate export remains independent of parsing.
Runtime's pure token-URI validation is shared with CLI preflight.

PINs come from explicit files/file-descriptor paths or protected paths, never a
plaintext command-line PIN. Parser failures do not quote raw arguments. Mutations
require `--confirm`; selection remains unique and explicit. New binary output
files are reserved before module loading and never overwrite existing files.
Binary stdout contains no status text, and structured errors go to stderr.
An I/O/cleanup error after an operation cannot undo the token action.

## Validation

Checks ran in a disposable Fedora 44 Podman container because the host lacks a C
linker. It used stable Rust 1.97.1 and a separate Rust 1.85.0 toolchain/target tree,
packaged SoftHSM 2.7.0, OpenSC and OpenSSL 3.5.8. Test tokens and provider builds
stayed in disposable storage. No hardware token or operator token store was used.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --locked` | Passed on stable and 1.85.0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed on stable |
| `cargo test --workspace --locked` | Passed on stable and 1.85.0: 44 ordinary tests, 11 doctests, 4 token suites ignored by default |
| `python3 tools/check-dependencies.py` | Passed; also added to CI |
| `./tools/test-softhsm.sh`, packaged provider | All 4 suites passed on stable and 1.85.0 |
| Same runner, pinned upstream provider with strict multipart requirement | All 4 suites passed on stable; all 3 combined ECDSA context-authentication mechanisms verified |
| CLI help/version, shell syntax, CI YAML and local Markdown links | Passed |

The upstream provider was built without source changes from commit
`884cb38f3d2012a0447bd5f50dbd29c429987c41`. Its runner used the explicit module and
utility paths plus `PKCS11_TEST_REQUIRE_EC_MULTIPART=1`. These runs exercise both
CI provider configurations locally; GitHub CI itself was not run.

Pure CLI tests check every command's help, early input validation, URI/PIN
redaction, missing mutation authorization, typed JSON errors, existing-output
preservation and failed-output cleanup. Client tests cover generic certificate
metadata independently of key support, alongside existing OpenSSL vectors.
A new compile-fail doctest rejects initialization with a live borrowed session.

CLI acceptance executes the real binary for every command family. It checks:

- Token initialization and USER PIN setup; USER/SO PIN changes and subsequent login.
- RSA/P-256/P-384/P-521 generation and sensitive/nonextractable private attributes.
- Discovery, URI round trips, missing/ambiguous selection, wrong PIN errors,
  negative protected-path capability and pool exhaustion/reuse diagnostics.
- Data import/export/relabel/delete and exact Ed25519 DER export, with imported
  subject/issuer/serial attributes and rejection by the signing-specific parser.
- Private-key export refusal and failed binary-file cleanup.
- Explicit binding and mismatch rejection, generic and bound signing, software
  hashing plans, message/prehash distinction, context authentication and binary stdout.
- Independent OpenSSL verification of CLI RSA PKCS#1 and explicit-salt PSS output;
  P-521/SHA-256 bound signing with the expected raw signature width.
- Runtime mutation failure invalidation and healthy RO-session rejection.

SoftHSM rejects some independent message/MGF1 PSS combinations even when the
mechanism is advertised. Positive PSS acceptance uses matching digests; generic
CLI signing still forwards explicit independent parameters and propagates provider
errors without fallback. Bound mismatched digests fail client preflight.

## Dependencies and limits

CLI now directly consumes client, runtime, locator, clap, secrecy, zeroize and
serde_json. The locked serde_json 1.0.151 addition declares Rust 1.71 and
MIT OR Apache-2.0. Existing locked package versions did not change. Runtime remains
the only direct cryptoki consumer, locator remains hardware-independent, client
never depends on CLI, and rustls stays confined to the adapter. The graph checker
verifies direct sibling edges and transitive forbidden dependencies.

Raw ECDSA output is fixed-width `r || s`; DER/PEM output transforms are not included.
Arbitrary CLI JSON templates, private/secret-key import/export, wrapping, encryption,
decryption, derivation and vendor-specific administration remain outside the
recorded command scope. Generic runtime templates remain available to library
callers. Certificate trust/chain/validity checks and hardware acceptance remain
application or later validation responsibilities. Protected-path positive behavior
is not established by these software-token tests. Raw/prehashed always-authenticate
remains constrained by the upstream safe API.

No Git repository is present, so no commits or publication were performed.
The pre-stage backup is `/tmp/pkcs11-stack-before-stage6.tar.gz`.
Local logs are `/tmp/pkcs11-stage6-quality.log`, `/tmp/pkcs11-stage6-msrv.log`,
`/tmp/pkcs11-stage6-integration.log`, `/tmp/pkcs11-stage6-msrv-integration.log` and
`/tmp/pkcs11-stage6-upstream-integration.log`; they are local evidence rather than
portable repository artifacts. The disposable container was removed after validation.
