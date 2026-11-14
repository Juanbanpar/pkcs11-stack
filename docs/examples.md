# Application examples

Runnable examples use trusted module paths and existing RSA token keys. All take
positional arguments; `--help` needs no module.

| Example | Purpose |
| --- | --- |
| `sign` | Sign a message through `Provider::client` |
| `bound_sign` | Prove key/certificate association and verify the returned signature |
| `tls_server` | Accept one loopback TLS connection, optionally requiring client authentication |
| `tls_client` | Verify a server, optionally authenticating with a token key |

PIN files are UTF-8, limited to 65536 bytes and read into zeroizing buffers. One
optional final LF/CRLF is removed; PINs are never command-line values. Protect
source files with operating-system access controls.

```sh
cargo build -p pkcs11-client --examples --locked
cargo build -p pkcs11-rustls-adapter --examples --locked
```

## Signing

Both programs use RSA PKCS#1 v1.5 with SHA-256 and require combined token hashing.
They write raw signatures to stdout: shell redirection controls permissions and
overwriting. `pkcs11ctl` creates outputs exclusively and provides structured errors.

```sh
cargo run --quiet -p pkcs11-client --example sign -- \
  /path/to/trusted-pkcs11.so \
  'pkcs11:serial=123;id=%01;type=private' \
  /secure/user.pin message.bin > signature.bin

cargo run --quiet -p pkcs11-client --example bound_sign -- \
  /path/to/trusted-pkcs11.so \
  'pkcs11:serial=123;id=%01;type=private' \
  'pkcs11:serial=123;id=%01;type=cert' \
  /secure/user.pin message.bin > bound-signature.bin
```

[sign.rs](../crates/pkcs11-client/examples/sign.rs) uses `Provider::client` and
`Client::sign`. [bound_sign.rs](../crates/pkcs11-client/examples/bound_sign.rs)
additionally proves the association and verifies the returned signature. Binding
does not validate certificate trust. `token_uri` derives the token selector from the key.

## TLS and mutual TLS

These programs explicitly choose ring, TLS 1.3 and token hashing. Certificates are
DER: each configured chain contains a leaf followed by its issuer. Supply a root
that trusts that chain; the server leaf must cover the supplied DNS name. The
examples do not construct chains or modify trust validation.

Start [tls_server.rs](../crates/pkcs11-rustls-adapter/examples/tls_server.rs) in one
terminal. It binds an ephemeral port on `127.0.0.1`, writes its address to a new file,
accepts one connection and exits after a `ping`/`pong` exchange. It waits for a
connection; established socket operations have a ten-second timeout. The address
file must not exist. Use an application-owned directory and remove the file before
another run.

```sh
cargo run --quiet -p pkcs11-rustls-adapter --example tls_server -- \
  /path/to/trusted-pkcs11.so 'pkcs11:serial=123' \
  'pkcs11:serial=123;id=%01;type=private' \
  server.der issuer.der /secure/user.pin localhost /path/to/new-address.txt
```

Once the address file has been written, run
[tls_client.rs](../crates/pkcs11-rustls-adapter/examples/tls_client.rs) in another
terminal. This form verifies the server and loads no PKCS#11 module:

```sh
cargo run --quiet -p pkcs11-rustls-adapter --example tls_client -- \
  "$(cat /path/to/new-address.txt)" localhost server-root.der
```

For mutual TLS, append `client-root.der` to the server invocation. Start a new
server for each exchange, and supply a client identity as six additional arguments:

```sh
cargo run --quiet -p pkcs11-rustls-adapter --example tls_client -- \
  "$(cat /path/to/new-address.txt)" localhost server-root.der \
  /path/to/trusted-pkcs11.so 'pkcs11:serial=456' \
  'pkcs11:serial=456;id=%02;type=private' \
  client.der client-issuer.der /secure/client.pin
```

The server then requires a client certificate trusted by its supplied root. Both
programs print success only after exchanging the expected data and, where a module
is used, dropping consumers and explicitly finalizing it. The application-owned
credential callback rereads its PIN file for binding and signing. Authentication
still follows token-wide login semantics. Early errors use best-effort Drop
cleanup and propagate the primary error. These are single-connection demonstrations,
not a concurrent server framework.

## Testing

`./tools/test-softhsm.sh` provisions disposable token keys and executes these
examples. It verifies signatures with OpenSSL and tests TLS authentication and
trust failures. See the [test guide](../tests/README.md) for setup.
