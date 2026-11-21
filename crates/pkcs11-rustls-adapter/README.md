# pkcs11-rustls-adapter

Authenticate a rustls 0.23 server or mutual TLS client with a private key held
on a PKCS#11 token or HSM. The token produces the handshake authentication
signatures. The application's rustls `CryptoProvider` handles key exchange,
record protection, randomness, and peer verification.

| Integration | API |
| --- | --- |
| Turn a token key and certificate chain into a rustls identity | `Credential` provides a rustls `SigningKey` and `Signer` through [pkcs11-runtime](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md) |
| Route server certificates by DNS name and signature scheme | `ServerResolver` |
| Present a client certificate for mutual TLS | `ClientResolver` |

## Installation

The server example uses Rust 1.88 or newer, rustls 0.23 with ring, and a trusted
PKCS#11 module. Use these dependencies after version `0.1.0` is published.

```toml
[dependencies]
pkcs11-rustls-adapter = "0.1.0"
pkcs11-runtime = "0.1.0"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

For a sibling checkout, substitute these two dependencies and keep the
rustls dependency above.

```toml
[dependencies]
pkcs11-rustls-adapter = { path = "../pkcs11-stack/crates/pkcs11-rustls-adapter" }
pkcs11-runtime = { path = "../pkcs11-stack/crates/pkcs11-runtime" }
```

Pass `Arc::new(rustls::crypto::ring::default_provider())` as the example's
`provider` argument to use ring.
See the [API reference](https://docs.rs/pkcs11-rustls-adapter) after publication or
generate it with the command under [Examples and tests](#examples-and-tests).

## Server configuration

- Supply the same `CryptoProvider` for credentials and TLS configuration.
  Applications choose the provider explicitly. The adapter installs no global provider.
- TLS 1.3 is available by default. Enable `tls12` for TLS 1.2.
- Pass an owned read-only session pool, a leaf-first DER chain, and a
  `CredentialSource`. A thread-safe closure returning `Result<Credentials, Error>`
  can serve as the source.

```no_run
use std::{num::NonZeroUsize, sync::Arc};
use pkcs11_runtime::{Module, PrivateKeyRef, SessionMode, SessionPool, SigningPolicy};
use pkcs11_rustls_adapter::{Credential, CredentialSource, ServerResolver, server_config_builder};
use rustls::{ServerConfig, crypto::CryptoProvider, pki_types::CertificateDer};

fn server_config(
    provider: Arc<CryptoProvider>,
    chain: Vec<CertificateDer<'static>>,
    source: Arc<dyn CredentialSource>,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let module = Arc::new(Module::load("/absolute/path/to/trusted-pkcs11.so")?);
    let pool = Arc::new(SessionPool::new_owned(
        module,
        &"pkcs11:token=production;serial=123".parse()?,
        SessionMode::ReadOnly,
        NonZeroUsize::new(4).unwrap(),
    )?);
    let key = PrivateKeyRef::new(
        "pkcs11:serial=123;object=server-key;type=private".parse()?,
    )?;
    let credential = Arc::new(Credential::load(
        pool, key, chain, SigningPolicy::default(), source, provider.clone(),
    )?);
    let resolver = ServerResolver::new(
        vec![("example.org".into(), credential)], None,
    )?;
    let config = server_config_builder(provider, &[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Ok(Arc::new(config))
}
```

Use `server_config_builder` for version-specific cipher suite filtering.
It preserves provider order and leaves the source provider unchanged. Apply
the same filter with direct rustls builders. TLS 1.3 suites can affect
credential selection on a TLS 1.2-only server with mixed key algorithms.

## Mutual TLS

1. Pass `ClientResolver::new(vec![credential])` to
   `ClientConfig::with_client_cert_resolver`. An empty resolver sends no certificate.
2. Configure trust roots on both sides and client-certificate verification on the server.

## Binding, authentication and ownership

| Concern | Contract |
| --- | --- |
| Binding | `Credential::load` requires a leaf-first DER chain and explicit key selector. Signs a probe and verifies with the leaf/provider |
| Key replacement | Every later signature is checked against the retained leaf. Shared labels/IDs alone never prove binding |
| Trust | Loading does not check chain trust, time, EKU or revocation. Configure normal rustls peer verification |
| Credentials | Source called once per binding/signature. Returns optional USER/context PINs in `SecretText` or `PinInput::ProtectedPath` |
| Authentication | `None` leaves login unchanged. Matching pooled USER role does not revalidate a PIN. Always-authenticate needs separate context credentials |
| Concurrency | Synchronous signing acquires one exclusive nonblocking lease. Exhaustion fails immediately |
| Cleanup | Runtime discards uncertain sessions. Encoding/binding failures also discard the lease. Failed closure blocks checkout until the pool is replaced |

- **Credential callbacks**. The source handles storage and prompting. Returned
  PINs stay scoped to the operation. Return `CredentialsUnavailable` without
  leaking source diagnostics. Scheme selection and resolvers avoid token I/O and
  credential callbacks.
- **Operation ownership**. Calls are synchronous and use the supplied pool.
  Applications handle logout, token removal, and slot rediscovery. Failed
  signing calls are issued once.
- **Checked shutdown**. Retain an application-owned `Arc<Module>`. Stop
  connections and drop configs, credentials, signers, and pools. When
  `Arc::try_unwrap` succeeds, call `Module::finalize`. A failed unwrap means
  a consumer still owns the module. The example uses best-effort Drop cleanup.

## Schemes and routing

| Subject key | TLS signature schemes |
| --- | --- |
| rsaEncryption | RSA-PSS SHA-256/384/512. RSA PKCS#1 v1.5 SHA-256/384/512 for TLS 1.2 |
| EC P-256 | ECDSA P-256/SHA-256 |
| EC P-384 | ECDSA P-384/SHA-384 |
| EC P-521 | ECDSA P-521/SHA-512, when the application provider supports verification |
| Ed25519 | Ed25519, when the application provider supports verification |
| ML-DSA-44/65/87 | Matching ML-DSA parameter set. TLS 1.3 only |

- Offered schemes intersect token capabilities, runtime policy, and provider
  verification support. Each call resolves the key and plans again.
- RSA-PSS uses the message digest for MGF1 and a digest-length salt. The runtime
  receives unhashed TLS messages. Token hashing is the default, with explicit
  options to allow or require software SHA-2.
- ECDSA converts fixed-width `r || s` to canonical DER using the curve width.
  Ed25519 uses pure signing and a key without per-operation authentication.
- Unsupported profiles include restricted RSA-PSS SPKI, Ed448, and SHA-1.

| Resolver | Selection |
| --- | --- |
| `ServerResolver` | Checks registered names against leaf SANs and matches exact DNS names case-insensitively. Uses the first compatible credential in registration order. Wildcard certificates can cover an explicit registration. The optional default applies only when SNI is missing, and unknown SNI fails |
| `ClientResolver` | Uses the first compatible credential in application order with matching exact DER issuer-name hints from the configured chain. Empty hints allow any compatible identity. Callers supply the chain in order |

## ML-DSA for TLS 1.3

| Area | Contract |
| --- | --- |
| Credential | Use `Credential::load_ml_dsa` with `MlDsaSigningPolicy`. Reuse pools, sources, leaf-first chains, and resolvers. Each leaf advertises its matching ML-DSA-44/65/87 scheme in TLS 1.3 |
| Provider | AWS-LC supports ML-DSA verification. Ring does not. Certificate, policy, and provider checks run before credential acquisition |
| Binding | Loading verifies one probe against the leaf. Later signatures are checked against the same leaf to detect key replacement |
| Signing | Pure ML-DSA signs the complete CertificateVerify message supplied by rustls with an empty FIPS 204 context. The adapter requires hedging. Always-authenticate keys use a separate context PIN. [ML-DSA TLS draft, handshake signatures](https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-06#section-3.2) |

### Hybrid key exchange

- `hybrid_tls13_provider` clones the application's provider and retains only
  X25519MLKEM768 and TLS 1.3 suites. It returns an error if either is missing.
- Use the returned provider on both peers. The provider runs key exchange and
  the TLS key schedule. This works independently of the certificate signature
  algorithm and the runtime's application hybrid combiner.

```no_run
# fn configure(application_provider: &rustls::crypto::CryptoProvider) -> Result<(), Box<dyn std::error::Error>> {
let provider = pkcs11_rustls_adapter::hybrid_tls13_provider(application_provider)?;
let client = rustls::ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])?;
let server = pkcs11_rustls_adapter::server_config_builder(
    provider, &[&rustls::version::TLS13],
)?;
# let _ = (client, server);
# Ok(())
# }
```

Both peers must support the hybrid group. Configure trust, resolvers, and
authentication as in the server and mutual TLS examples.

## Examples and tests

The [server and mutual TLS examples](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/examples.md#tls-and-mutual-tls)
use loopback connections and an explicit ring provider.

```sh
cargo test -p pkcs11-rustls-adapter --locked
cargo doc -p pkcs11-rustls-adapter --all-features --no-deps --locked
cargo check -p pkcs11-rustls-adapter --lib --no-default-features --locked
cargo check -p pkcs11-rustls-adapter --lib --features tls12 --locked
```

| Suite | Coverage |
| --- | --- |
| Unit | Scheme selection, ML-DSA certificate parameters, encoding, and redaction |
| SoftHSM | TLS 1.2/1.3, trust failures, concurrency, exhaustion, and replacement keys. Ring cannot verify P-521 |
| ML-DSA provider | All parameter sets, server and mutual TLS 1.3, ML-DSA issuer, and X25519MLKEM768. Exercises authentication, policy, trust, and replacement failures |

AWS-LC is a development dependency for ML-DSA tests. Applications supply
the production provider. See the
[provider setup](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md#pqc-provider-compatibility).
