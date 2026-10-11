# pkcs11-stack

A Rust-native PKCS#11 workspace built above cryptoki, licensed MIT OR Apache-2.0.

**Status: Stages 1–8 implemented.**
The locator handles RFC 7512 URIs and matching. Runtime owns module/session
lifecycle, token/object discovery, authentication, bounded concurrent leases,
stable key references and RSA PKCS#1 v1.5, RSA-PSS and ECDSA signing. The client adds
application lookup, signing and verified key/certificate association. `pkcs11ctl` adds
inspection, signing, diagnostics and token/PIN/object administration. The rustls
adapter adds token-backed server and mutual TLS authentication.
Stage 8 adds [application API contracts](docs/adr/0011-application-api-contracts.md)
and [runnable signing/TLS examples](docs/examples.md).

## Architecture

Arrows point from a dependency to its consumer:

```text
pkcs11-locator -> pkcs11-runtime -> pkcs11-client -> pkcs11ctl
cryptoki      -> pkcs11-runtime
                pkcs11-runtime -> pkcs11-rustls-adapter
rustls                         -> pkcs11-rustls-adapter
```

All requested crate names are retained. Exact GitHub repository matches for
`pkcs11-client` are recorded in [ADR 0001](docs/adr/0001-workspace-architecture.md);
they do not change the selected name. No crate names were published or reserved.

| Crate | Intended responsibility | Actual sibling dependencies |
| --- | --- | --- |
| [pkcs11-locator](crates/pkcs11-locator/README.md) | RFC 7512 parsing, construction, selectors, binary IDs, matching, redaction | None |
| [pkcs11-runtime](crates/pkcs11-runtime/README.md) | Shared lifecycle, authentication, sessions, objects, capabilities and operations | locator |
| [pkcs11-client](crates/pkcs11-client/README.md) | Application and management workflows | runtime, locator |
| [pkcs11ctl](crates/pkcs11ctl/README.md) | Administration, inspection and diagnostics | client, locator |
| [pkcs11-rustls-adapter](crates/pkcs11-rustls-adapter/README.md) | TLS authentication signing and credentials | runtime |

The CLI uses client workflows for signing, inspection, diagnostics and
administration, with no direct runtime dependency. Client must never depend on the CLI. The table records current
manifests. Runtime is the
only direct cryptoki consumer and must not depend on rustls. Locator is independent
of cryptoki, runtime and hardware. The adapter is the only rustls consumer; the
application owns software CryptoProvider selection. Persistent identity uses
selectors, never durable object handles or preferred slot IDs. Session and
module lifecycle, recovery and capability planning stay in runtime.

This is an independent implementation, not a libp11 binding, an OpenSC port,
an API-compatible recreation, an OpenSSL library or a complete rustls provider.
The architecture is shallow; no speculative public types or testkit are included.

## Development

Rust 1.85 or newer, edition 2024 and Cargo resolver 3. A system C linker is
required by the Rust toolchain (for example, install `gcc` on Fedora). The committed lockfile
records the dependency set. Rustls 0.23.43 has default features disabled and only
`std` enabled in production by default; the adapter selects no software crypto
provider. Its optional `tls12` feature enables TLS 1.2, and tests explicitly use ring.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
python3 tools/check-dependencies.py
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p pkcs11ctl -- --help
```

CI runs these quality checks with locked dependency resolution and separately
checks/tests Rust 1.85.0. The [testing strategy](tests/README.md) distinguishes
pure tests, software-token tests and hardware acceptance. A separate CI job runs
`./tools/test-softhsm.sh` against isolated disposable token storage.
All original workspace Rust sources forbid unsafe code. Cryptoki 0.12.1 includes
the upstream allowed-mechanisms decoding fix; the temporary vendored override has
been [retired](vendor/README.md). Locator errors are typed and secret-free; URI Debug and Display redact PINs.
All consumers preserve these practices.

## Decisions and research

- [0001: architecture, name preflight, dependency graph and MSRV](docs/adr/0001-workspace-architecture.md)
- [0002: object identity](docs/adr/0002-object-identity.md)
- [0003: module and session ownership](docs/adr/0003-session-ownership.md)
- [0004: rustls boundary](docs/adr/0004-rustls-boundary.md)
- [0005: original application API / CLI separation, superseded](docs/adr/0005-client-cli-separation.md)
- [0006: licensing and dependency review](docs/adr/0006-licensing.md)
- [0007: signing and pooling](docs/adr/0007-signing-and-pooling.md)
- [0008: client identity association](docs/adr/0008-client-identity.md)
- [0009: original CLI reuse of client and runtime, superseded](docs/adr/0009-cli-library-reuse.md)
- [0010: CLI consumes the client library](docs/adr/0010-cli-client-boundary.md)
- [0011: application API contracts](docs/adr/0011-application-api-contracts.md)
- [Upstream preflight findings](docs/preflight.md)
- [Stage 0/1 completion record](docs/stage-1-report.md)
- [Stage 2 implementation and validation](docs/stage-2-report.md)
- [Stage 3 implementation and validation](docs/stage-3-report.md)

- [Stage 4 implementation and validation](docs/stage-4-report.md)

The [implemented-stage review](docs/implemented-stage-review.md) records the
September 25 dependency cleanup, session-health fixes and combined ECDSA support.

The [Stage 5 report](docs/stage-5-report.md) records client behavior and validation.
The [Stage 6 specification](docs/stage-6-spec.md), [CLI guide](crates/pkcs11ctl/README.md)
and [completion report](docs/stage-6-report.md) describe the command scope and validation.
The [Stage 7 specification](docs/stage-7-spec.md),
[adapter guide](crates/pkcs11-rustls-adapter/README.md) and
[completion report](docs/stage-7-report.md) describe TLS integration and acceptance.
The [CLI client refactor report](docs/cli-client-refactor-report.md) records the
completed removal of direct CLI runtime access.
The [September 27 project review](docs/project-review-2026-09-27.md) records CLI
input/selector fixes, TLS server configuration and regression coverage.
The [Stage 8 specification](docs/stage-8-spec.md) and
[completion report](docs/stage-8-report.md) cover API review and application examples.
The [regression coverage report](docs/regression-coverage-report.md) records generated
tests, bounded fuzzing and the [platform validation policy](docs/platforms.md).

## License

All original project code and documentation are available under either the
[MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your
option. Every workspace crate inherits `MIT OR Apache-2.0`, and original Rust
files carry that SPDX expression. Third-party dependencies retain their own
licenses and notices; see [ADR 0006](docs/adr/0006-licensing.md).
Crates.io publication remains disabled.
