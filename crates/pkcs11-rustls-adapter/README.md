# pkcs11-rustls-adapter

Token-backed TLS authentication for rustls 0.23. The adapter supplies `SigningKey`,
`Signer`, server certificate resolution and client certificate resolution over
[pkcs11-runtime](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md). Private keys stay in the token.

The application supplies its software `CryptoProvider` for record encryption,
key exchange, peer verification and randomness. Production dependencies select no
provider, and the adapter never installs a global one. TLS 1.3 is available by
default; enable `tls12` for TLS 1.2. Use the same provider for credentials and configs.

## Server configuration

This example accepts a leaf-first DER chain and an application credential source.
The source implements `CredentialSource`, or is a thread-safe closure returning
`Result<Credentials, Error>`. The trusted module path and selectors are explicit.

```no_run
use std::{num::NonZeroUsize, sync::Arc};
use pkcs11_runtime::{Module, PrivateKeyRef, SessionMode, SessionPool, SigningPolicy};
use pkcs11_rustls_adapter::{Credential, CredentialSource, ServerResolver, server_config_builder};
use rustls::{ServerConfig, crypto::CryptoProvider};
use rustls_pki_types::CertificateDer;

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

`server_config_builder` filters the provider's suites to the enabled protocol
versions without changing the source provider, preference order or global state.
This matters for TLS 1.2-only servers with mixed key algorithms: retaining TLS 1.3
suites can affect credential selection. Direct rustls builders need the same filter.

For mutual TLS, pass `ClientResolver::new(vec![credential])` to
`ClientConfig::with_client_cert_resolver`; configure server client-certificate
verification and trust roots separately. Empty client credentials send no certificate.

## Binding, authentication and ownership

| Concern | Contract |
| --- | --- |
| Binding | `Credential::load` requires a leaf-first DER chain and explicit key selector; signs a probe and verifies with the leaf/provider |
| Key replacement | Every later signature is checked against the retained leaf; shared labels/IDs alone never prove binding |
| Trust | Loading does not check chain trust, time, EKU or revocation; configure normal rustls peer verification |
| Credentials | Source called once per binding/signature; returns optional USER/context PINs in `SecretString` or `PinInput::ProtectedPath` |
| Authentication | `None` leaves login unchanged; matching pooled USER role does not revalidate a PIN; always-authenticate needs separate context credentials |
| Concurrency | Synchronous signing acquires one exclusive nonblocking lease; exhaustion fails immediately |
| Cleanup | Runtime discards uncertain sessions; encoding/binding failures also discard the lease; failed closure blocks checkout until the pool is replaced |

The adapter retains the credential source, never its returned PINs. Callbacks own
storage/prompting policy and should report `CredentialsUnavailable` without leaking
source diagnostics. Scheme selection and resolver filtering neither contact the
token nor invoke the source. There are no hidden workers, signing retries, logouts
or secondary pools. Token removal and slot rediscovery remain explicit.

Owned pools retain `Arc<Module>` through session closure. For explicit shutdown,
stop connections, drop configs/credentials/signers/pools, unwrap an application-
retained module Arc with `Arc::try_unwrap`, then call `Module::finalize`. A failed
unwrap means a consumer still owns it. The example transfers ownership to the
config and uses best-effort Drop cleanup; borrowed runtime APIs remain available.

## Schemes and routing

| Subject key | TLS signature schemes |
| --- | --- |
| rsaEncryption | RSA-PSS SHA-256/384/512; RSA PKCS#1 v1.5 SHA-256/384/512 for TLS 1.2 |
| EC P-256 | ECDSA P-256/SHA-256 |
| EC P-384 | ECDSA P-384/SHA-384 |
| EC P-521 | ECDSA P-521/SHA-512, when the application provider supports verification |
| Ed25519 | Ed25519, when the application provider supports verification |
| ML-DSA-44/65/87 | Matching ML-DSA parameter set; TLS 1.3 only |

Offers intersect runtime capabilities/policy and provider verification algorithms.
RSA-PSS uses matching MGF1 hash and digest-sized salt. The adapter passes unhashed
TLS messages to runtime, which re-resolves the key and replans each operation.
Runtime policy defaults to token hashing; applications may explicitly allow or
require software SHA-2. ECDSA `r || s` is converted to canonical DER using the known
curve width. Restricted RSA-PSS SPKI, Ed448 and SHA-1 are unsupported.
Ed25519 uses `Credential::load` with pure original-message signing;
context-authenticated EdDSA is rejected.

`ServerResolver` checks registered names against leaf SANs and routes exact DNS
names case-insensitively. Multiple credentials for one name retain application
order; the first compatible key wins. Wildcard certificates may cover a registered
name, but no wildcard route is inferred. An explicit default applies only when SNI
is absent; unknown SNI fails. `ClientResolver` uses application order, compatible
schemes and exact DER issuer-name hints from the configured chain. Empty hints
allow any compatible identity. Callers remain responsible for chain ordering.

## ML-DSA for TLS 1.3

Use `Credential::load_ml_dsa` with `MlDsaSigningPolicy` instead of the classical
`Credential::load`/`SigningPolicy` pair. Pools, credential sources, leaf-first
chains and resolvers are shared. ML-DSA-44, ML-DSA-65 and ML-DSA-87 each advertise
only their corresponding TLS signature scheme. TLS 1.2 is not supported for these
identities.

The application provider must supply verification for the leaf's parameter set;
AWS-LC supports it, while ring does not. Certificate, policy and provider checks
precede credential acquisition. Loading performs one binding signature and verifies
it; each subsequent signature is checked against the retained leaf. A reused
selector with a replacement key therefore fails verification.

Signing uses pure ML-DSA with required hedging and an empty FIPS 204 context, as
specified by the [ML-DSA TLS draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-06).
Rustls supplies the complete CertificateVerify message, including its TLS context;
the adapter does not prehash it. Required hedging has no deterministic fallback.
Always-authenticate keys use the credential source's separate context PIN.

ML-DSA authentication and hybrid key exchange are separate choices.
`hybrid_tls13_provider(&provider)` clones the application's provider, retaining
only X25519MLKEM768 and TLS 1.3 cipher suites. It fails when either is unavailable.
Use the returned provider in both client and server builders with TLS 1.3:

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

Continue configuring trust, resolvers and authentication as usual. Peers offering
only classical groups cannot negotiate. The source provider is unchanged and no
global provider is installed. TLS key exchange and its key schedule execute in
the supplied provider, not on the token. This policy is independent of the
runtime/client application combiner.

## Examples and tests

[Runnable TLS server/client examples](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/examples.md) use loopback,
optional mutual authentication and an explicit ring provider.

```sh
cargo test -p pkcs11-rustls-adapter --locked
cargo doc -p pkcs11-rustls-adapter --all-features --no-deps --locked
cargo check -p pkcs11-rustls-adapter --lib --no-default-features --locked
cargo check -p pkcs11-rustls-adapter --lib --features tls12 --locked
```

| Suite | Coverage |
| --- | --- |
| Unit | Scheme selection, ML-DSA certificate parameters, encoding and redaction |
| SoftHSM | TLS 1.2/1.3, trust failures, concurrency, exhaustion and key replacement; ring does not verify P-521 |
| ML-DSA provider | All parameter sets, server/mutual TLS 1.3, ML-DSA issuer and X25519MLKEM768; authentication, policy, trust and replacement failures |

AWS-LC is a development dependency for ML-DSA tests; production selects no provider.
See the [provider setup](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md#pqc-provider-compatibility).
Token delegation covers authentication signatures; record protection, key exchange
and the TLS key schedule remain in the application's rustls provider, independently
of the runtime/client hybrid combiner.
