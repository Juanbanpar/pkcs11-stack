# pkcs11-rustls-adapter

Token-backed TLS authentication for rustls 0.23. The adapter supplies `SigningKey`,
`Signer`, server certificate resolution and client certificate resolution over
[pkcs11-runtime](../pkcs11-runtime/README.md). Private keys stay in the token.

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

`server_config_builder` restricts the supplied provider's suites to the enabled
protocol versions before starting rustls configuration. Use it especially for
TLS 1.2-only servers with multiple key algorithms. Retaining TLS 1.3 suites can affect credential selection when a dual-version
client offers only ECDSA suites for TLS 1.2. The builder keeps
provider algorithms and suite preference order, changes no global state and leaves
the caller's provider unchanged. Callers using rustls builders directly must apply
the same suite/version restriction. Normal trust and authentication choices follow
on the returned rustls builder.

For mutual TLS, construct `ClientResolver::new(vec![credential])` and pass it to
`ClientConfig`'s `with_client_cert_resolver`. Configure the server's normal client
certificate verifier and trust roots separately. Empty client credentials send no
certificate. No verification is bypassed by these resolvers.

## Binding, authentication and ownership

`Credential::load` requires a nonempty leaf-first DER chain and explicit private-key
selector. It parses the chain, checks the leaf's subject key type/curve, signs a
binding probe and verifies it using the leaf and supplied provider. Matching labels
or IDs alone never establish binding. Every later signature is verified against
that retained leaf, rejecting key replacement behind an unchanged selector.
Loading does not validate chain trust, time, EKU or revocation; the application
configures rustls's normal peer verification for those decisions.

A credential source is called once per binding or signature operation. It returns
short-lived `Credentials` with optional USER and context PINs in `SecretString`, or
`PinInput::ProtectedPath`. `None` leaves authentication unchanged. A runtime pool
ensures the requested USER role; an already logged-in role does not revalidate the
PIN. Always-authenticate keys require explicit context credentials. The adapter
retains the callback, never the returned PINs; application callbacks own their own
secret-storage and prompting policy. Use `Error::CredentialsUnavailable` to report
source failure without leaking source diagnostics.

Scheme selection and resolver filtering do not invoke the source or contact the
token. Signing is synchronous and acquires one exclusive, nonblocking runtime
lease; exhaustion fails immediately. There are no hidden workers, signing retries,
logout calls or secondary pools. Failed/uncertain sessions are discarded by runtime;
encoding or binding failures also discard the lease. Later independent operations
may acquire a fresh session after successful cleanup. If a discarded session fails
to close, runtime blocks further checkouts; replace the pool explicitly. Token
removal and slot rediscovery remain explicit.

An owned runtime pool holds `Arc<Module>` through session closure, satisfying rustls's
`'static` signing traits without leaking the owner. For explicit shutdown, stop
connections, drop configs/credentials/signers and pools, then
`Arc::try_unwrap(module)` on an application-retained module Arc. If unwrapping
succeeds, call `Module::finalize`; otherwise a consumer still retains the owner.
The example transfers ownership to the config and uses best-effort Drop cleanup.
Borrowed runtime APIs remain available to other callers.

## Schemes and routing

| Subject key | TLS signature schemes |
| --- | --- |
| rsaEncryption | RSA-PSS SHA-256/384/512; RSA PKCS#1 v1.5 SHA-256/384/512 for TLS 1.2 |
| EC P-256 | ECDSA P-256/SHA-256 |
| EC P-384 | ECDSA P-384/SHA-384 |
| EC P-521 | ECDSA P-521/SHA-512, when the application provider supports verification |
| ML-DSA-44/65/87 | Matching ML-DSA parameter set; TLS 1.3 only |

Offers intersect runtime capabilities/policy and provider verification algorithms.
RSA-PSS uses matching MGF1 hash and digest-sized salt. The adapter passes unhashed
TLS messages to runtime, which re-resolves the key and replans each operation.
Runtime policy defaults to token hashing; applications may explicitly allow or
require software SHA-2. ECDSA `r || s` is converted to canonical DER using the known
curve width. Restricted RSA-PSS SPKI, EdDSA and SHA-1 are outside this implementation.

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

ML-DSA authentication and hybrid key exchange are separate choices. Configure
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

Runnable [TLS server and client examples](../../docs/examples.md) use loopback
connections, optional mutual authentication and an explicit ring provider.

```sh
cargo test -p pkcs11-rustls-adapter --locked
cargo check -p pkcs11-rustls-adapter --lib --no-default-features --locked
cargo check -p pkcs11-rustls-adapter --lib --features tls12 --locked
./tools/test-softhsm.sh
```

Unit tests cover scheme selection, ML-DSA certificate parameters, encoding and
redaction. AWS-LC is enabled only as a development dependency for ML-DSA tests;
production still selects no provider. Classical SoftHSM tests perform TLS 1.2/1.3
handshakes, including trust failures, concurrent connections, pool exhaustion and
key replacement. Those tests use ring, which does not verify P-521; P-521
credentials require a provider that does.

The required PQC lane tests all ML-DSA parameter sets with token-backed server and
mutual TLS 1.3 authentication, an ML-DSA certificate issuer and X25519MLKEM768
key exchange. It also covers always-authenticate keys, missing provider support,
policy rejection before credentials, classical-only peer rejection in both
directions, trust failure, TLS 1.2 rejection, pool
exhaustion and key replacement. Run it with the provider configuration in the
[workspace test instructions](../../tests/README.md#pqc-provider-compatibility).
