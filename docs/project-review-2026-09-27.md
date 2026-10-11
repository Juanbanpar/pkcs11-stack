# Project review — 2026-09-27

Reviewed the implemented locator, runtime, client, CLI and rustls adapter after
Stages 1–7 and the client-only CLI refactor. The review covered URI identity,
module/session ownership, authentication and failure recovery, signing and binding,
CLI input/output contracts, TLS selection and dependency boundaries. Each issue
below was reproduced with a failing regression before applying the fix.

## Findings and changes

1. **Malformed prehashes reached provider loading.** A 31-byte SHA-256 digest with
   a missing module returned backend exit 5 before reporting the input error.
   `pkcs11ctl` now checks digest length during input preparation and returns exit 2
   before module loading, login or output reservation. A regression checks the
   JSON error, empty stdout and absence of a new output file.
2. **Typed selectors were validated too late.** Private-key and certificate
   commands accepted generic object references during preflight. Wrong or absent
   `type` criteria could therefore trigger module loading before rejection.
   Preflight now requires `type=private` or `type=cert` as appropriate. Executable
   regressions cover key inspection, certificate inspection and binding.
3. **Listed URIs dropped empty labels and IDs.** An available empty value became
   an absent criterion, broadening the selector. URI construction now uses the
   original attribute bytes, removing the JSON/hex round trip and preserving
   `object=` and `id=`. SoftHSM acceptance lists an empty-label/ID certificate,
   exports and deletes it through that URI, and verifies that another certificate
   remains accessible.
4. **Mixed-version offers could select an incompatible TLS credential.** With
   rustls 0.23.43, a TLS 1.2-only server retaining TLS 1.3 provider suites could
   select RSA before ECDSA for a dual-version client whose TLS 1.2 suites require
   ECDSA. The handshake then failed with `NoCipherSuitesInCommon`. The new
   `server_config_builder` filters a cloned application provider to the enabled
   protocol versions before rustls resolves certificates. The same handshake now
   passes through normal peer verification. Tests also cover invalid version/suite
   combinations and preservation of the caller's provider.

The TLS change is an additive configuration API. Applications must use
`server_config_builder`, as shown in the updated adapter guide, or apply the same
suite/version restriction when building rustls configurations directly. Existing
direct builder calls are not changed automatically. Provider choice, suite order,
trust policy and credential ordering remain application decisions.

Updated the CLI/adapter guides, Stage 6/7 specifications, ADR 0004 and test inventory.
No dependency versions or lockfile entries changed. The CLI still has no direct
runtime dependency; runtime remains the sole direct cryptoki consumer, and the
adapter's production graph selects no software TLS provider. No vendored source
override was restored.

## Validation

All commands completed successfully in a disposable Fedora 44 container:

| Check | Result |
| --- | --- |
| Rust 1.97.1: formatting, locked workspace/all-target check, Clippy with warnings denied | Passed |
| Stable and Rust 1.85.0: locked workspace tests | 52 ordinary tests and 14 doctests each, including 7 compile-fail checks |
| Rust 1.85.0: locked workspace/all-target check | Passed |
| Stable: production adapter check without default features, with and without `tls12` | Passed |
| Locked dependency architecture check | Passed |
| Packaged SoftHSM `2.7.0-0.1.rc1.fc44.1`, stable and Rust 1.85.0 | All 6 integration tests in 5 suites passed on each toolchain |
| Upstream SoftHSM `884cb38f3d2012a0447bd5f50dbd29c429987c41`, stable | All 6 integration tests passed; strict multipart ECDSA verified all 3 SHA-2 mechanisms |

The integration runner used isolated disposable token stores and retained the
existing runtime, client, CLI and TLS acceptance matrix. New cases extend the
existing suites. The packaged SoftHSM lane retains its documented multipart ECDSA
limitation; the upstream lane requires successful signing and independent
verification instead of accepting that limitation.

## Remaining limits

Hardware interoperability, hot unplug and positive protected-path authentication
remain unvalidated. Ring does not provide P-521 verification, so positive P-521
TLS is not covered. Raw/prehashed always-authenticate signing remains constrained
by cryptoki's single-part API. These are existing boundaries, not newly completed
features. This review is not a formal security audit or a current dependency
advisory scan. Software-token results establish behavior only for the tested
providers and configurations.
