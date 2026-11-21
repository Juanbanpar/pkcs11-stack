# Development and release checks

## Workspace

| Path | Responsibility |
| --- | --- |
| `crates/pkcs11-locator` and `crates/pkcs11-runtime` | RFC 7512 selectors and the typed module/session layer |
| `crates/pkcs11-client` and `crates/pkcs11-rustls-adapter` | Application workflows and token-backed TLS authentication |
| `crates/pkcs11ctl` and `crates/pkcs11-desktop` | CLI and desktop interfaces |
| `tests/`, `tools/`, and `fuzz/` | Test guidance, disposable provider runners, and fuzz targets |

## Validate changes

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

- The default tests include doctests and need no token. See the
  [test guide](../tests/README.md) for native dependencies and provider setup.
- Use `./tools/test.sh --providers` for disposable provider-backed integration
  tests. Re-run changed examples using the documented commands.
- When changing public APIs, mechanisms, authentication, security behavior,
  or CLI flags, update the corresponding rustdoc, examples, and user guides.
  Review generated crate landing pages as well as Markdown links.

For bug reports, include the version or commit, OS, provider and version,
mechanism, expected result, and a minimal reproduction on a disposable token if
possible. Redact credentials, key material, and production token identifiers.
Use [GitHub issues](https://github.com/Juanbanpar/pkcs11-stack/issues) for ordinary
bugs and the [security policy](../SECURITY.md) for vulnerability reports.

## Code review

- The locator parses and matches selectors independently of the runtime. The
  runtime owns direct `cryptoki` access. The client builds application workflows
  on the runtime and is shared by the CLI and desktop. The rustls adapter uses
  runtime signing and leaves selection of the software TLS provider to the caller.
- Keep software public-key verification in the client. Keep TLS dependencies in
  the adapter, CLI and desktop framework dependencies in their applications, and
  testing dependencies in development or fuzz targets.
- Keep the desktop's Wayland backend and Iced thread-pool executor. Review the
  enabled widget and icon-font features when changing desktop dependencies.
- Keep `mod.rs` files limited to module declarations and re-exports, with optional
  documentation and attributes. Put implementations in named sibling files.
- Preserve public API compatibility when moving code. Review public paths,
  re-exports and documented contracts alongside any implementation change.

Reviewers enforce these conventions. When a dependency changes, inspect the
manifest and its production dependency tree with
`cargo tree -p <crate> --locked -e normal,build,features`. Check the affected crate
in isolation when siblings could supply a feature it needs. The adapter's
standalone production builds are also checked in CI:

```sh
cargo check -p pkcs11-rustls-adapter --lib --no-default-features --locked
cargo check -p pkcs11-rustls-adapter --lib --features tls12 --locked
```

## Release validation

Run the [workspace and provider tests](../tests/README.md) in full and audit
the workspace, fuzz and pinned provider lockfiles. See the
[advisory policy](../SECURITY.md#dependency-advisories) for reviewing exclusions.

From a clean checkout, list and verify the locator archive independently and
package the publishable workspace members together so Cargo can stage their
registry dependencies locally:

```sh
cargo package --list -p pkcs11-locator --locked
cargo package -p pkcs11-locator --locked
cargo package --list --workspace --exclude pkcs11-desktop --locked
cargo package --workspace --exclude pkcs11-desktop --locked
```

Use `cargo metadata --no-deps --locked --format-version 1` and review the manifests
for release metadata, registry dependency versions and publication restrictions.
The locator, runtime, client, rustls adapter and CLI are publishable. The desktop
is excluded. Review each archive's file list for source, README, both licenses,
and crate-local public fixtures. Check that the licenses match the repository
copies, shared public fixtures in the CLI and adapter match the client's copies,
and the archives exclude secrets, generated provider binaries, token databases,
and build or fuzz artifacts. These comparisons and package-content rules require
manual review.

## Initial 0.1.0 release summary

- Crates planned for crates.io are `pkcs11-locator`, `pkcs11-runtime`,
  `pkcs11-client`, `pkcs11-rustls-adapter`, and `pkcs11ctl`. The desktop
  application builds from source.
- The stack provides RFC 7512 selectors, token discovery and object management,
  typed cryptography, certificate binding, and rustls server and client
  authentication with token-held keys.
- Rust 1.88 is the minimum. Token operations require a trusted module and
  compatible token. The locator and offline verification can run without one.
- Integration tests use SoftHSM and Kryoptic. Mechanism support depends on the
  provider and key. See the [compatibility matrix](oasis-compatibility.md) for
  tested profiles and upstream limits.
