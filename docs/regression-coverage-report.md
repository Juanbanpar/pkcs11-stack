# Automated regression coverage — 2026-09-28

Completed the regression-coverage work following Stage 8: generated properties,
bounded fuzzing, reproducible failures and a documented platform validation policy.

## Changes

- Added five locator property tests covering binary IDs, exact Unicode and empty
  labels, secret redaction, canonical serialization and unknown path constraints.
- Added three adapter properties covering canonical ECDSA DER, invalid raw widths
  and zero scalars, and unchanged RSA representation. DER output is decoded and
  re-encoded by an independent RustCrypto decoder and compared by integer value.
- Moved the existing encoder into a private module without changing its function
  body. The fuzz harness compiles that production source directly; no public
  testing API or production feature was introduced.
- Added three cargo-fuzz targets, original synthetic seed corpora, a separate
  lockfile, pinned tooling and a bounded runner using AddressSanitizer. CI preserves
  crashes and generated corpora. Property-test failures retain shrinkable regression
  seeds; ordinary CI test jobs upload them on failure.
- Retained independent crate checks and added Windows/macOS pure build/test jobs.
  Removed Unix-only absolute-path assumptions from two tests. The
  [platform policy](platforms.md) separates pure portability from provider acceptance.
- Extended the dependency checker to reject property/fuzz tooling in production
  dependency graphs. Proptest is dev-only; existing locked package versions remain
  unchanged. The fuzz workspace has its own tool dependencies and lockfile.

## Local validation

All completed commands below exited successfully in a disposable Fedora 44 Linux
x86_64 container. Stable was Rust 1.97.1; the minimum toolchain was Rust 1.85.0.

| Check | Result |
| --- | --- |
| Formatting for both workspaces; main all-target check; Clippy with warnings denied | Passed |
| Stable and Rust 1.85 workspace tests | 61 ordinary tests and 14 doctests each, including 7 compile-fail checks |
| Rust 1.85 all-target workspace check | Passed |
| Eight properties with 4,096 cases each, RNG seed 1337 | 32,768 generated cases passed |
| Dependency boundaries and production adapter feature configurations | Passed |
| Packaged SoftHSM integration and all application examples | All 6 integration tests and example acceptance passed |
| Fuzz runner argument bounds, shell syntax, CI YAML and platform matrix | Passed |

Stable workspace validation used property seed 20260927; MSRV used 20260928.
The expanded property run supplements those ordinary 256-case runs.

The final fuzz-runner invocation used cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13 and
nightly-2026-09-25. Each target had a 30-second budget, a 4,096-byte maximum input,
five-second per-input timeout and 1,024 MiB RSS limit, with AddressSanitizer and
debug assertions enabled. It reused the synthetic corpus expanded during the
initial smoke run. The complete final runner exited successfully:

| Target | Executed inputs | Peak RSS |
| --- | ---: | ---: |
| URI parser | 1,109,927 | 514 MiB |
| Binary selectors/redaction | 186,351 | 454 MiB |
| ECDSA encoding | 6,469,344 | 489 MiB |

No assertion or sanitizer failure was found in those bounded runs. Counts depend on
machine speed and the starting corpus; they are observations, not coverage guarantees.
The [fuzz guide](../fuzz/README.md) documents replay, longer runs and preservation of
minimized failures. The [testing guide](../tests/README.md) gives property-test commands.

## Validation limits

Windows/macOS jobs are configured but were not run in this Linux environment.
Their native CI results remain required before claiming those platforms validated.
The pinned upstream SoftHSM lane remains configured with the existing strict
multipart requirement; this coverage-only pass reran the packaged provider locally.
Hardware and provider-specific acceptance remain separate. Production APIs,
cryptographic policies and publishing status are unchanged.
