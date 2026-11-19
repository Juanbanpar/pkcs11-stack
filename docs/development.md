# Development and release checks

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
