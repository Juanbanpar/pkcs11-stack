# pkcs11-stack

Use PKCS#11 tokens and hardware security modules from Rust, the terminal, or a
desktop app. Inspect and provision keys and certificates, run cryptographic
operations on a token, and use token-held keys for TLS authentication.

## Crates

| If you want to | Use |
| --- | --- |
| Add token discovery, certificate binding, cryptography, and public import/export to a Rust app | [pkcs11-client](crates/pkcs11-client/README.md) |
| Inspect and administer a token by hand in a graphical interface | [pkcs11-desktop](crates/pkcs11-desktop/README.md) |
| Use a token from the terminal or automate workflows in scripts | [pkcs11ctl](crates/pkcs11ctl/README.md) |
| Authenticate a rustls server or mutual TLS client with a token-held key | [pkcs11-rustls-adapter](crates/pkcs11-rustls-adapter/README.md) |
| Own modules, sessions, and pools, discover resources, and execute PKCS#11 operations directly | [pkcs11-runtime](crates/pkcs11-runtime/README.md) |
| Parse, build, or match RFC 7512 PKCS#11 URIs, with binary IDs and query-value redaction | [pkcs11-locator](crates/pkcs11-locator/README.md) |

## Build and run

| Component | Minimum Rust | Requirements |
| --- | --- | --- |
| Libraries and CLI | 1.88 | Trusted PKCS#11 module for token operations |
| Desktop and full workspace | 1.88 | Wayland to run the app on Linux and [native build dependencies](crates/pkcs11-desktop/README.md#build-and-run) |

```sh
cargo build --release -p pkcs11ctl --locked
./target/release/pkcs11ctl --module /path/to/pkcs11.so tokens
./target/release/pkcs11ctl --help
```

After installing the desktop prerequisites, start the GUI.

```sh
cargo run --release -p pkcs11-desktop --locked
```

- Load a trusted module explicitly. Module files contain executable code.
- Use a PKCS#11 URI with a stable token serial and binary object ID. Operations
  that require one result reject ambiguous matches.

## Workspace crates and key dependencies

```mermaid
flowchart TD
    cli[pkcs11ctl] --> client[pkcs11-client]
    cli --> locator[pkcs11-locator]
    client -->|token operations| runtime[pkcs11-runtime]
    client --> locator
    runtime --> locator
    runtime --> cryptoki
    adapter[pkcs11-rustls-adapter] -->|token-backed signing| runtime
    adapter --> rustls
    desktop[pkcs11-desktop] --> client
```

- The runtime owns the PKCS#11 lifecycle and executes token operations. Its
  modules follow operation families such as signing, encryption, key establishment,
  and derivation. The client builds workflows on those operations. Library callers
  use crate-root exports.
- Rustls applications choose the software provider used for record protection,
  key exchange, and peer verification.

## Supported operations

Availability depends on the token and provider.

- [Runnable signing and TLS examples](docs/examples.md)
- [Mechanism support by crate](docs/oasis-compatibility.md#application-surfaces)
- [Security model](docs/security-model.md)

## Testing

Run from the repository root.

| Suite | Command | Setup |
| --- | --- | --- |
| Workspace tests and doctests | `cargo test --workspace --locked` or `./tools/test.sh --unit` | Native desktop build dependencies |
| Provider integration | `./tools/test.sh --providers` | [Disposable SoftHSM and Kryoptic setup](tests/README.md#full-provider-suite) |
| Both suites | `./tools/test.sh --all` | Same provider setup |
| Fuzzing | See the [fuzzing guide](fuzz/README.md) | Sanitizer runs, corpora, and artifact replay |

See the [test guide](tests/README.md) for coverage and provider prerequisites.

## Documentation and checks

The library READMEs also serve as rustdoc landing pages.

```sh
cargo doc --workspace --all-features --no-deps --locked
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option.

[Report a vulnerability](SECURITY.md)
