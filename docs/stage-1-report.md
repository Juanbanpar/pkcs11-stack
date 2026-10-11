# Stage 0 and Stage 1 completion record

Date: 2026-09-05. Workspace: `/home/jbanga/Personal/pkcs11-stack`.
The directory was empty and had no Git repository, existing code or ADRs.
This historical Stage 0/1 snapshot records architectural scaffolding.
For current locator functionality, see [Stage 2](stage-2-report.md). No Git commit, publication or
name reservation was performed. Stage 2 has not started.

## Resulting source tree

Build output under ignored `target/` is excluded.

```text
pkcs11-stack/
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   ├── pkcs11-client/
│   │   ├── src/
│   │   │   └── lib.rs
│   │   ├── Cargo.toml
│   │   └── README.md
│   ├── pkcs11-locator/
│   │   ├── src/
│   │   │   └── lib.rs
│   │   ├── Cargo.toml
│   │   └── README.md
│   ├── pkcs11-runtime/
│   │   ├── src/
│   │   │   └── lib.rs
│   │   ├── Cargo.toml
│   │   └── README.md
│   ├── pkcs11-rustls-adapter/
│   │   ├── src/
│   │   │   └── lib.rs
│   │   ├── Cargo.toml
│   │   └── README.md
│   └── pkcs11ctl/
│       ├── src/
│       │   └── main.rs
│       ├── Cargo.toml
│       └── README.md
├── docs/
│   ├── adr/
│   │   ├── 0001-workspace-architecture.md
│   │   ├── 0002-object-identity.md
│   │   ├── 0003-session-ownership.md
│   │   ├── 0004-rustls-boundary.md
│   │   ├── 0005-client-cli-separation.md
│   │   ├── 0006-licensing.md
│   │   └── preflight-2026-09-05.json
│   ├── preflight.md
│   └── stage-1-report.md
├── tests/
│   └── README.md
├── .gitignore
├── LICENSE-APACHE
├── LICENSE-MIT
├── Cargo.lock
├── Cargo.toml
├── README.md
├── clippy.toml
└── rustfmt.toml
```

## Actual direct dependency graph

Arrows mean depends on. Derived from `cargo metadata --locked`.

```text
pkcs11-client -> pkcs11-runtime
pkcs11-locator -> secrecy, thiserror, zeroize
pkcs11-runtime -> cryptoki, pkcs11-locator, secrecy, thiserror
pkcs11-rustls-adapter -> pkcs11-runtime, rustls, rustls-pki-types
pkcs11ctl -> clap, pkcs11-runtime
```

Metadata traversal verified both direct and transitive boundaries at Stage 1.
The former CLI-to-client prohibition was later superseded by
[ADR 0009](adr/0009-cli-library-reuse.md); this list records the original validation:

- pkcs11-client does not depend on pkcs11ctl.
- pkcs11ctl does not depend on pkcs11-client.
- pkcs11-runtime does not depend on rustls.
- pkcs11-locator does not depend on cryptoki or pkcs11-runtime.
- pkcs11-rustls-adapter is the only workspace crate depending on rustls.
- Rustls resolved features are exactly `std`; no software provider is selected.

## Names and selected dependencies

[ADR 0001](adr/0001-workspace-architecture.md) and its [raw response summary](adr/preflight-2026-09-05.json)
record every exact check. All six original names returned crates.io HTTP 404.
GitHub returned no exact basename matches except `pkcs11-client`, matching
`mlecar/pkcs11-client` and `JoeyGii/pkcs11-client`. The requested name
`pkcs11-client` is retained; GitHub matches do not change that decision.
No testkit crate was created.

| Direct dependency | Selected version | Declared MSRV | License |
| --- | --- | --- | --- |
| cryptoki | 0.12.0 | 1.77 | Apache-2.0 |
| rustls | 0.23.43 | 1.71 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | 1.60 | MIT OR Apache-2.0 |
| secrecy | 0.10.3 | 1.60 | Apache-2.0 OR MIT |
| zeroize | 1.9.0 | 1.85 | Apache-2.0 OR MIT |
| thiserror | 2.0.20 | 1.71 | MIT OR Apache-2.0 |
| clap | 4.6.6 | 1.85 | MIT OR Apache-2.0 |

MSRV is deliberately Rust 1.85, for edition 2024/resolver 3 and the highest
selected direct minimum. Metadata reports no locked dependency declaring a
higher minimum. All five workspace crates inherit MIT OR Apache-2.0, edition 2024,
Rust 1.85 and publish=false. All five original Rust files have SPDX headers and
forbid unsafe code. LICENSE-MIT and LICENSE-APACHE provide the two license options
for original code and documentation. The former GPL COPYING file is removed.
[ADR 0006](adr/0006-licensing.md) records dependency and third-party policies;
upstream licenses and required notices still apply, including Apache-2.0 for cryptoki.

## Validation

Local stable toolchain: rustc 1.97.0, cargo 1.97.0, x86_64-unknown-linux-gnu.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed, zero tests in skeleton harnesses |
| `cargo run -p pkcs11ctl -- --help` | Passed, help/version only |

Additional local MSRV checks both passed with rustc 1.85.0:

- `cargo +1.85.0 check --workspace --all-targets --locked`
- `cargo +1.85.0 test --workspace --locked` (zero skeleton tests)

The first rustup download hit DNS failure. Retrying with its curl backend installed
1.85.0 successfully; rustup then failed its unrelated self-update due to a missing
`rustup-init` path. The installed compiler and Cargo were verified by the passing
commands above. CI toolchain installation disables rustup self-update explicitly.

CI includes stable format/check/clippy/tests and a separate locked Rust 1.85.0
check/test job. CI configuration has not been executed on a remote runner.
No test result claims module loading, cryptography, TLS or hardware acceptance.

## Architectural findings

- cryptoki's safe loading API allows workspace unsafe prohibition. Cloneable
  contexts still need runtime-owned initialization/finalization coordination.
- Sessions are Send but not Sync. Normal login state is shared across sessions;
  per-operation authentication needs deliberate sequencing. One-shot signing
  cannot insert context-specific login after initialization; raw mechanisms need
  further upstream investigation before support can be promised.
- RFC 7512 requires binary IDs, attribute-aware matching and explicit secret
  redaction. Unknown constraints must not silently widen selection.
- rustls accepts unhashed messages and supports external signers plus both
  server and client credential resolvers. The normal provider remains the
  application's choice. Scheme/encoding conversion belongs in the adapter.
- Current reference documentation is not automatically authoritative: the
  inspected OxiCrypto adapter README's claim that rustls lacks Ed25519 schemes
  contradicts the released rustls enum. Its ECDSA first-byte heuristic must not
  be adopted.
- Original code and documentation are MIT OR Apache-2.0. Dependencies retain
  their own licenses; specifications and reference code are not copied implicitly.

[Preflight sources and details](preflight.md) explain these findings. All requested
crate names are retained, as recorded explicitly in ADR 0001.

Next milestone: **Stage 2, implement pkcs11-locator**. Stop here.
