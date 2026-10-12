# pkcs11-client

Synchronous application workflows over [pkcs11-runtime](../pkcs11-runtime/README.md):
unique token/key/certificate lookup, public metadata, policy-controlled signing,
explicit key/certificate association, discovery and scoped administration. Part of [pkcs11-stack](../../README.md).

## Signing with a certificate

The application loads a trusted module and supplies authentication for each call.
Use stable token serials and binary object IDs where available. Labels are accepted
but ambiguous matches return errors.

```no_run
use pkcs11_client::{
    Authentication, DigestAlgorithm, Provider, Pin, SignInput,
    SignRequest, SignatureAlgorithm, SigningPolicy,
};
use secrecy::SecretString;
use std::num::NonZeroUsize;

let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let client = provider.client(
    &"pkcs11:token=production;serial=123".parse()?,
    NonZeroUsize::new(4).unwrap(),
    SigningPolicy::default(),
)?;
// Example only: obtain this from the application's secret source.
let pin = SecretString::from("example-only");
let auth = || Authentication::User(Pin::Value(&pin));
let key = client.private_key(
    "pkcs11:serial=123;id=%01;type=private".parse()?, auth(),
)?;
let certificate = client.certificate(
    "pkcs11:serial=123;id=%01;type=cert".parse()?, auth(),
)?;
// Performs one signature to prove the selected key matches the certificate.
let identity = client.bind_identity(key, certificate, auth(), None)?;
let request = SignRequest {
    algorithm: SignatureAlgorithm::RsaPkcs1,
    digest: DigestAlgorithm::Sha256,
    input: SignInput::Message(b"application message"),
    pss: None,
};
let signature = client.sign_identity(&identity, &request, auth(), None)?;
assert!(!signature.is_empty());
drop(client);
provider.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example requires an RSA key and token support for combined SHA-2 signing.
Callers using `Pin::Value` also depend on `secrecy` 0.10. `Pin::ProtectedPath` is
available when supported by the token. Always-authenticate keys need a separate
`Some(Pin::Value(&pin))` or protected-path input to each binding/signing call.

## Ownership and policy

Prefer `Provider::load` and `Provider::client` for application construction. The
re-exported runtime types support applications that need direct control of pools
and sessions; their ownership rules still apply.

`Client::new` accepts an existing runtime pool; `Client::connect` creates one in
read-only session mode. The full token URI is checked against the explicitly
loaded module, slot and token. Object criteria, credentials and unsupported URI
constraints are rejected. A URI never causes module loading.

The client owns its pool and borrows the module. It cannot outlive or finalize its
module; drop the client before explicit finalization:

```compile_fail,E0505
use pkcs11_client::{Client, Module, SigningPolicy};
use std::num::NonZeroUsize;
fn invalid_shutdown(module: Module) {
    let client = Client::connect(&module, &"pkcs11:token=test".parse().unwrap(),
        NonZeroUsize::new(1).unwrap(), SigningPolicy::default()).unwrap();
    module.finalize().unwrap();
    drop(client);
}
```

Share one client per token and authentication role. Runtime leases provide bounded
concurrency; exhaustion returns `Error::Runtime(PoolExhausted)` immediately.
Authentication ensures a role, so an already logged-in token may not recheck the
supplied PIN. `Authentication::None` leaves token-wide login state unchanged.
External logout affects all sessions. PINs are borrowed and never retained.

`SigningPolicy::default()` requires token hashing and RSA keys of at least 2048
bits. Applications can explicitly select `HashingPolicy::AllowSoftware` or
`SoftwareOnly`. AllowSoftware selects a supported plan before signing; it does
not retry an operation if an advertised mechanism fails. `plan` is advisory;
execution resolves the selector and rediscovers capabilities. A failed signature
or authentication attempt is never retried by the client.

`private_key`, `public_key`, `certificate`, `public_metadata`, `attributes` and
`capabilities` expose common lookup/inspection workflows. Raw requested attributes
can include extractable secret data; their Debug container is redacted. `sign`
returns the runtime's modulus-width RSA or fixed-width ECDSA `r || s` signature.
It does not require a certificate. `SignInput::Digest` always means an already
computed digest, distinct from a message that still needs hashing.

## Identity association and verification

`Client::signing_options` offers common SHA-2 message-signing choices under current
key capabilities and the client's policy, including the planned mechanism and
hashing boundary. PSS choices use a matching MGF1 digest and digest-length salt.
Choices are advisory: signing rediscovers capabilities. `SignatureParameters`
creates a typed request from borrowed message or digest bytes without retaining them.

`Certificate::verification_options` supplies matching SHA-2 parameter choices.
`verify_signature` independently verifies raw RSA or fixed-width ECDSA `r || s`
signatures in software, returning `SignatureMismatch` for invalid signatures.
It does not authenticate the certificate, establish trust, or associate it with
a token key. Parameter validation remains separate from token signing policy.

`CertificateDocument::from_der` parses exact X.509 DER independently of signing
support. It provides original DER, SPKI, subject/issuer Names and serial-number DER
for application inspection and certificate import. It accepts algorithms such as
Ed25519 without claiming their keys are valid or supported for signing. `Certificate`
uses the same parser, then validates a supported public key; `document()` exposes
its metadata. Neither parser makes a certificate trust decision.

`Certificate::from_der` accepts one exact DER X.509 certificate with an
rsaEncryption RSA key (up to 16384 bits) or a named P-256, P-384 or P-521 key.
Malformed keys, unknown curves, RSA-PSS-restricted public keys and trailing bytes
are rejected. `der` retains the certificate; `spki_der` exposes its public key.

`bind_identity` signs `pkcs11-client identity binding v1` followed by a NUL byte,
then verifies the result with the selected certificate. It does not infer a
binding from matching labels or IDs. This also works when a token does not expose
its EC private key's public point. Binding uses the client's policy, tries plans
in RSA-PSS / PKCS#1 order (ECDSA for EC), then SHA-256 / SHA-384 / SHA-512, with PSS
salt length equal to digest length. Exactly one selected token operation executes.
No permitted probe produces `NoBindingMechanism`.

An `Identity` retains the selector and certificate snapshot, with no object handle
or cached credentials. `sign_identity` verifies every signature before returning
it, detecting a different key under the same selector. Verification mismatch
discards the lease. A token signing failure keeps its runtime error. Taking
`identity.key()` and calling generic `sign` opts out of this association check.

Bound RSA-PSS signing requires the message and MGF1 digests to match because the
software verifier supports that subset. Unsupported requests fail before session
checkout. `Certificate::validate_signing_request` validates verifier parameters
so callers can check requests before performing a binding probe; capability and
policy planning remain separate. Generic `sign` retains the runtime's independent MGF1 support.

Parsing and association do **not** validate issuer signatures, trust chains,
validity dates, key usage, revocation or hostnames. The application owns those
checks. There is no certificate-chain construction, TLS integration or private-key
import. Administration uses the separate management API described below.

## Discovery and administration

`Provider` owns one explicitly loaded runtime module. It returns slot/token/mechanism
snapshots, creates signing clients with `client`, and opens a `ManagementSession`
with explicit token URI, mode and authentication. Sessions expose typed inspection,
raw certificate/data export, certificate/data import, nonextractable signing-key
generation, relabel/delete and USER/SO PIN administration. They do not expose raw
runtime sessions or object handles. Existing `Module`/`Client::connect` APIs remain
compatible for applications already using them.

```no_run
use pkcs11_client::{Authentication, AttributeType, Provider, SessionMode, object_reference};
let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let token = "pkcs11:token=production;serial=123".parse()?;
let mut session = provider.management(&token, SessionMode::ReadOnly, Authentication::None)?;
let reference = object_reference("pkcs11:serial=123;object=certificate;type=cert".parse()?)?;
let attributes = session.inspect(&reference, &[AttributeType::Label, AttributeType::Subject])?;
// AttributeRead Debug redacts values; explicit value access can expose secrets.
let der = session.export_value(&reference)?;
session.close()?;
provider.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Provider::generation_options` returns common RSA sizes and P-256/P-384/P-521
choices within the provider's advertised key-pair generation bounds. Choices are
advisory: a vendor can still reject the requested curve or template. The existing
generation API keeps its full RSA range and requires a nonempty ID.

`export_public` exports public certificate/data values and supported public keys.
It rejects CKA_PRIVATE objects and private/secret key classes before reading values.
RSA and named EC public attributes are validated and encoded as SubjectPublicKeyInfo
DER; incomplete or invalid attributes fail. `export_value` retains its explicit
raw certificate/data export behavior.

`objects` reads only caller-requested attributes of persistent objects visible to
the session. `inspect` reports available, unavailable, sensitive or unsupported
attributes. `export_value` accepts raw certificate/data values without parsing their
signing algorithms, and rejects key classes before reading their value. Imports
create persistent public objects; certificate metadata comes from
`CertificateDocument`, including for algorithms outside signing support. Data IDs
use CKA_OBJECT_ID. Selectors still follow the runtime's CKA_ID semantics, so use
unique labels to select data objects. IDs/labels do not imply uniqueness.

`object_locator(&token, &attributes)` builds an object URI from available class,
label and CKA_ID reads. Empty label/ID bytes remain exact constraints; token and
module-path constraints are preserved. It returns `None` for missing identity,
unsupported classes or labels that cannot be represented as URI text, and rejects
credential-bearing token URIs. Resolve the resulting selector again before use;
multiple objects can share the same metadata.

`Provider::diagnose` exercises a fresh bounded runtime pool: simultaneous leases,
exhaustion and reuse. It accepts an authentication factory called once per initial
lease and once for reuse; the factory returns borrowed credentials. This is an
explicit diagnostic, not automatic recovery or a signing retry. CLI limits capacity
to 1–64; the library accepts any nonzero capacity. Runtime keeps token-wide login
semantics, so an established role does not validate the PIN again.

`management_owned` returns a session that retains the provider's initialization
owner without borrowing the provider. Use it to keep authentication active between
application requests. `state` reads actual session state; `authenticate` applies
one USER/SO login attempt; `logout` logs out the application's sessions on that
token. SO requires read-write mode. These methods retain no PIN and never retry.
Close owned sessions before `initialize_token` or `finalize`; live owned consumers
return `Error::ProviderInUse`. A consumed or dropped provider does not finalize the
module while an owned session remains alive.

Management uses one explicitly authenticated session, not an additional pool.
Mutations require RW mode and appropriate provider authorization. Failed operations
retain runtime invalidation semantics and are never retried or rolled back. Drop
never explicitly logs out; closing the last session may reset token login state.
`Provider::initialize_token` can erase a selected slot and requires exclusive owner
access. Drop all sessions/clients before finalizing or initializing a token:

```compile_fail,E0505
use pkcs11_client::{Authentication, Provider, SessionMode};
fn invalid_shutdown(provider: Provider) {
    let session = provider.management(&"pkcs11:token=test".parse().unwrap(),
        SessionMode::ReadOnly, Authentication::None).unwrap();
    provider.finalize().unwrap();
    session.close().unwrap();
}
```

`object_reference`, `validate_token_uri` and `token_uri` support provider-independent
input validation and projection without loading a library. `Error::kind` provides
semantic error categories so consumers can present errors without matching runtime
variants. It defines no terminal format or exit codes. Existing detailed errors and
sources remain available. A missing provider attribute status is a runtime failure,
not invalid user input. Diagnostic strings are not a parsing contract; categories
do not authorize retries.

Runnable [signing examples](../../docs/examples.md) demonstrate `Provider::client`,
generic signing, binding and explicit shutdown with PIN files and raw stdout output.

## Random bytes

`ManagementSession::generate_random` accepts a `RandomRequest` with a length from
1 byte to one MiB. `RandomRequest::new` rejects other lengths before allocation
or token calls. The session requests the token's RNG once, with no automatic login,
software fallback or retry; the provider may require an authenticated session.

Returned `RandomBytes` use `secrecy::SecretBox<Vec<u8>>`: Debug is redacted and
storage is zeroized on drop, including partial output discarded after failures.
Access bytes explicitly through `secrecy::ExposeSecret` when writing an intended
output. Close the session separately to report lifecycle failures.

## Testing

```sh
cargo test -p pkcs11-client --locked
./tools/test-softhsm.sh
```

Unit tests use independent OpenSSL-generated certificates and signatures. SoftHSM
tests exercise management, signing, association checks and key replacement.
