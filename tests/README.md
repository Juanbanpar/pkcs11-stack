# Testing

Normal `cargo test --workspace --locked` needs no token. It runs 61 ordinary tests
and fourteen doctests across the workspace. Coverage includes RFC 7512
parsing/matching/redaction, binary IDs, capability and policy planning, stable
references and seven compile-fail ownership checks. Client tests also verify
independent OpenSSL signatures, certificate parsing and binding policy. CLI executable tests cover validation, redaction and output handling;
adapter tests cover TLS scheme/provider/policy intersection, canonical ECDSA DER,
credential redaction and server protocol configuration.

Six ignored tests in five SoftHSM suites run through `./tools/test-softhsm.sh`. The script discovers
common Debian, Fedora and local library paths, creates disposable token storage,
and cleans it on exit. `PKCS11_TEST_MODULE` and `SOFTHSM2_UTIL` override trusted tool
locations. A C linker, SoftHSM, OpenSSL and OpenSC executables are needed; on Fedora these
are provided by `gcc`, `softhsm`, `openssl` and `opensc`. Production crates have no OpenSSL dependency. Client fixtures are provisioned only after runtime tests
finish, so their token-count assumptions remain intact. Provisioning uses public
disposable PINs and nonextractable RSA/P-256/P-384/P-521 keys in the new store.

Acceptance covers discovery, token-wide authentication, ambiguity, pooling,
concurrent leases, exhaustion, session discard/recreation, invalidation after failures,
nonextractable RSA/EC keys, allowed-mechanisms restrictions and signing. Empty,
single and multiple mechanism lists exercise the released cryptoki 0.12.1 decoder.
The [local source override was retired](../vendor/README.md); no vendored-only test
command remains. OpenSSL independently verifies signatures and rejects changed
messages, including explicit PSS parameters and test-only raw-to-DER ECDSA conversion.

Combined ECDSA context authentication is exercised when advertised. SoftHSM 2.7
returns CKR_OPERATION_NOT_INITIALIZED from SignUpdate for these mechanisms; the test
accepts only that exact known backend limitation and verifies session invalidation
and replacement. Other errors fail the suite. Providers without the advertisement
have no positive coverage for this path. Use a provider with multipart ECDSA and
set `PKCS11_TEST_REQUIRE_EC_MULTIPART=1` to require all three SHA-2 combinations to
sign and verify. `RUST_TEST_NOCAPTURE=1` prints the successful mechanism count.
The [September 25 review](../docs/implemented-stage-review.md) records the providers
and revisions actually tested. CI has packaged and pinned upstream SoftHSM lanes;
the upstream lane sets the strict multipart requirement.

Hardware interoperability, hot unplug and positive protected-path authentication
are separate acceptance work. Software-token results do not establish hardware
behavior. Raw/prehashed always-authenticate operations remain blocked by cryptoki's
single-part API; combined RSA and ECDSA use explicit init/login/update/final.

Client acceptance adds public/private visibility, wrong PIN recovery, missing and
ambiguous selectors, exact module/slot constraints, explicit key/certificate
binding, mismatched public keys, message/prehash signing, context authentication,
pool exhaustion and concurrent calls. It replaces an RSA key under the same URI
and checks that bound signing rejects the new signature while other identities
still work. OpenSSL verifies a generic client-produced RSA signature; independent
public fixtures cover each verification algorithm and digest combination.

Stage 6 CLI acceptance follows the [CLI specification](../docs/stage-6-spec.md):
test command behavior against shared client workflows and exercise client
inspection/administration directly. Dependency checks require CLI-to-client, reject direct CLI-to-runtime and reject
client-to-CLI dependencies, including transitive ones. CLI must have no
direct cryptoki/rustls dependency; runtime retains the cryptoki boundary.

CLI acceptance exercises all twenty command families, including generated RSA/EC
keys, USER/SO PIN changes, certificate/data import/export, relabel/delete, binding,
raw Ed25519 export, binary/stdout/JSON contracts and independent OpenSSL RSA/PSS
verification. Malformed prehash lengths and typed selectors fail before module
loading; available empty IDs/labels survive listing and subsequent export/delete.
Runtime mutation failures invalidate sessions; RO mutation attempts
are rejected without invalidating an otherwise healthy session.

Stage 7 provisions a separate disposable TLS token after the CLI suite. All eight
RSA/EC private keys are checked as sensitive and nonextractable. An external test
CA signs exported public keys; token private keys are never exported. Adapter
acceptance uses explicit ring providers and normal rustls trust verification for
TLS 1.2/1.3 server and mutual authentication. It exchanges application data in both
directions through in-memory TLS records. The matrix includes RSA/P-256/P-384
servers, RSA/EC clients, and a context-authenticated RSA server. Additional cases
cover PKCS#1-only TLS 1.2 success/TLS 1.3 failure, absent and unknown SNI, issuer hints,
wrong trust roots, missing client certificates, binding mismatch, callback/PIN
failure, concurrent handshakes, exhaustion/discard recovery, selector replacement
and owned-module shutdown. A dual-version client offering ECDSA-only TLS 1.2 suites
also connects to a TLS 1.2-only server with RSA before ECDSA in its resolver, using
the adapter's protocol-aware server builder. Ring's P-521 verification limitation is tested as a
rejected credential, not a successful TLS path. See the
[Stage 7 report](../docs/stage-7-report.md).

No testkit crate has been added. Small ordered fixture scripts share the existing
isolated runner. Deterministic tests supplement software-token acceptance; hardware
acceptance remains separate.

The [CLI client refactor](../docs/cli-client-refactor-report.md) adds direct client
management acceptance: metadata, diagnostics, wrong-PIN recovery, RO mutation
rejection, data and unsupported-algorithm certificate import/export, attribute
status/redaction, nonextractable generation, shared-owner signing, relabel/delete
and ambiguity without mutation. Runtime mutation guard coverage moved from CLI
tests to client integration, where runtime remains an allowed dependency.

The [September 27 project review](../docs/project-review-2026-09-27.md) records the
current fixes and validation on stable Rust, Rust 1.85 and both SoftHSM builds.

Stage 8 adds four [application examples](../docs/examples.md). The isolated runner
executes them before client/TLS tests replace fixture keys. OpenSSL verifies generic
and bound signatures; mismatched binding emits no signature. Separate TLS server
and client processes exercise loopback server/mutual authentication and reject
wrong trust roots and absent required client credentials. Server timeouts are not
accepted as successful negative tests. These executable checks supplement the six
ignored integration tests rather than adding Rust test functions.

CI also checks and tests each crate in a separate job, without feature unification
from unrelated workspace members. Examples are compiled by all-target checks and
executed in both SoftHSM lanes. A pure client regression classifies omitted provider
attribute status as a runtime failure. See [ADR 0011](../docs/adr/0011-application-api-contracts.md)
for the public API contracts exercised by the examples.

## Generated regression coverage

Eight property tests run as part of ordinary workspace testing (256 cases each by
default). Locator properties cover arbitrary binary IDs, exact Unicode/empty label
matching, secret query redaction, canonical serialization and conservative unknown
criteria. Adapter properties check ECDSA DER using an independent decoder, invalid
raw widths/zero scalars, and unchanged RSA representation. ECDSA formatting lives
in a private module also compiled by its fuzz harness; the production API is unchanged.

Proptest shrinks failures and persists regression seeds. Commit useful regression
files with the fix; they are not ignored. Reproduce or expand a run with:

```sh
PROPTEST_RNG_SEED=20260927 PROPTEST_CASES=4096 cargo test -p pkcs11-locator --test properties --locked
PROPTEST_RNG_SEED=20260927 PROPTEST_CASES=4096 cargo test -p pkcs11-rustls-adapter --lib encoding::properties --locked
```

CI uses fixed seeds 20260927 and 20260928 (MSRV); ordinary local runs choose random seeds. A fixed seed alone
is not comprehensive input coverage. Keep minimized failures as explicit tests
and vary seeds when investigating a failure or expanding coverage.

Three [fuzz targets](../fuzz/README.md) supplement the property tests with bounded
AddressSanitizer runs on Linux. The separate fuzz workspace has its own lockfile,
pinned tooling, synthetic seed corpora and crash/corpus artifacts. Existing per-crate
jobs remain; new Windows/macOS jobs check pure portability as described in the
[platform policy](../docs/platforms.md). Local results and exact limits are recorded
in the [regression coverage report](../docs/regression-coverage-report.md).
