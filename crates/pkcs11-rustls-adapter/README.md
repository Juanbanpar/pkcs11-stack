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
TLS 1.2-only servers with multiple key algorithms. In rustls 0.23.43, retaining
TLS 1.3 suites in that server's provider can allow RSA credential selection even
when a dual-version client offers only ECDSA suites for TLS 1.2. The builder keeps
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
may acquire a fresh session. Token removal and slot rediscovery remain explicit.

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

## Validation and boundaries

Runnable [TLS server and client examples](../../docs/examples.md) exchange data over
loopback, with optional mutual authentication and explicit module shutdown. They
select ring as applications; no production provider dependency is added.

`cargo test -p pkcs11-rustls-adapter --locked` covers schemes, policy/provider
intersection, signature encoding and secret redaction. `./tools/test-softhsm.sh`
adds full TLS 1.2/1.3 server and mutual-authentication handshakes with nonextractable
RSA/P-256/P-384 keys, wrong-trust and selection failures, context authentication,
concurrency, pool exhaustion/recovery, key replacement and module lifetime.
Tests explicitly choose ring; ring does not verify P-521, so that credential is
rejected in this test configuration. Encoding coverage is not positive P-521 TLS
or hardware acceptance. See the [Stage 7 report](../../docs/stage-7-report.md).

Runtime remains the sole direct cryptoki consumer. The adapter depends on runtime,
rustls, rustls-pki-types, rustls-webpki, x509-cert, secrecy and thiserror; locator is
a test dependency. It does not depend on client or CLI and implements no complete
CryptoProvider. Original code and documentation are [MIT](../../LICENSE-MIT) OR
[Apache-2.0](../../LICENSE-APACHE).
