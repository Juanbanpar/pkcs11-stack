# Fuzzing

This separate, unpublished workspace uses cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13
and nightly-2026-09-25. Its lockfile is committed. Fuzz tooling does not enter any
production crate's dependency graph or change the Rust 1.85 workspace requirement.
The runner validates the lockfile with `cargo fetch --locked`, then builds offline.

```sh
rustup toolchain install nightly-2026-09-25 --profile minimal --component rust-src
cargo +nightly-2026-09-25 install cargo-fuzz --version 0.13.2 --locked
bash tools/test-fuzz.sh
```

Run from the repository root. Each target runs for 30 seconds with AddressSanitizer,
debug assertions, seed 20260927, a 4096-byte input limit, five-second per-input
timeout and 1024 MiB RSS limit. Compilation time is additional. A crash, assertion
failure, timeout or resource-limit failure fails the job. The complete CI job has
a twenty-minute deadline. The smoke budget is regression coverage, not evidence
that the input space has been exhausted.

| Target | Invariants |
| --- | --- |
| `uri_parser` | Accepted UTF-8 input reparses from its explicit secret serialization without losing path criteria or changing canonical/redacted output |
| `binary_selectors` | Every input byte survives ID construction/parsing; absent or different IDs fail exact matching; PIN canaries remain redacted |
| `ecdsa_encoding` | Wrong widths and zero scalars fail; accepted fixed-width scalars become canonical positive DER integers with unchanged values |

The ECDSA harness compiles the actual private `src/encoding.rs` from the adapter.
It adds no public feature or API to production. RustCrypto's DER decoder is the
independent encoding oracle. This checks representation, not whether arbitrary
scalars form a valid signature or lie inside the curve's group order. Full signature
verification remains covered by the existing client and TLS acceptance tests.
No target loads a PKCS#11 module, signs with a token, or disables verification.

`seeds/` contains original synthetic inputs: URI grammar/escape boundaries, all ID
octets and ECDSA width/zero/sign-padding cases. ECDSA input starts with a curve byte
(`byte % 3` selects P-256/P-384/P-521), followed by raw `r || s`. Seeds include both
short and long DER sequence lengths. The runner copies seeds into ignored mutable
`corpus/` directories. It retains discoveries between local runs and writes crash
inputs to `artifacts/`; CI uploads both directories even on failure. Never put real
PINs, private material or production data in corpora or regression files.

To explore one target longer:

```sh
FUZZ_SECONDS=300 FUZZ_SEED=42 bash tools/test-fuzz.sh ecdsa_encoding
```

To replay a saved artifact, use its exact file path:

```sh
cargo +nightly-2026-09-25 fuzz run ecdsa_encoding fuzz/artifacts/ecdsa_encoding/crash-HASH -- -runs=1
```

Minimize reproducible failures with `cargo fuzz tmin`, fix the implementation, then
add an ordinary regression and an appropriate nonsecret seed. Preserve useful
property-test regression files too. Fixed RNG seeds aid reproduction, but elapsed
time budgets and growing corpora do not promise identical fuzz run counts.

The [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html) documents
the underlying runner and corpus commands. Platform scope and native CI status are
recorded in the [platform policy](../docs/platforms.md).
