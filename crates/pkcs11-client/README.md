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

## Streaming RSA and ECDSA

[`ManagementSession::start_signing`] and [`ManagementSession::start_verification`]
return exclusive message-operation guards. [`ManagementSession::sign_reader`] and
[`ManagementSession::verify_token_reader`] use zeroizing 64 KiB input buffers.
[`SignatureParameters`] describes the algorithm, digest and explicit PSS parameters;
[`SigningPolicy`] selects token or incremental software hashing before initialization.
Streaming accepts messages only; existing single-part APIs also accept caller digests.

Callers enforce their input budget and close sessions before publishing output when
cleanup errors must be checked. Incomplete streams, read failures and native errors
discard sessions. Completed verification mismatches permit reuse; consuming guard
cancellation permits reuse only after confirmed native termination. Signing output
is limited to 1024 bytes (RSA through 8192 bits, or P-256/P-384/P-521 r || s).
These management APIs do not perform certificate binding or establish trust.

Streaming capability queries are advisory. A combined mechanism and its entry points
do not guarantee provider multipart support. Packaged SoftHSM 2.7.0 rc1 rejects
combined ECDSA updates; choose software hashing explicitly or use a provider with
multipart support. No failed native operation triggers a software retry.

## ML-DSA

The client exposes pure ML-DSA-44/65/87 with a separate `MlDsaRequest` and explicit
`MlDsaSigningPolicy`. The classical digest-based `SigningPolicy` does not govern
these calls. Requests select the expected parameter set, original message, context
(0 through 255 bytes), and required/preferred/deterministic hedging. Required hedging
fails if the token cannot supply randomness; there is no software fallback.

`ManagementSession::start_ml_dsa_signing` returns an exclusive signing guard;
`sign_ml_dsa_reader` reads original messages through a zeroizing 64 KiB buffer.
`MlDsaParameters` separates the parameter set, context and hedging requirement
from streamed message input. Context/PIN borrows end after initialization; input
has no total limit, so callers enforce their budget. Incomplete streams and
read/native failures discard sessions. Explicit cancellation permits reuse only
after confirmed native termination. Check session closure before publishing output.
The management reader does not perform certificate binding.

Both single-part and streaming ML-DSA signing allocate exactly the selected
signature length, without native size queries or retries. ML-DSA verification
through `C_Verify` is single-part under PKCS#11 3.2 section 6.67.5; streaming
verification needs the signature-first API and remains planned. Pure EdDSA
multipart support also remains gated on an implementing provider; the pinned
SoftHSM build supports its single-part profile.

Use `Provider::ml_dsa_generation_options` for advisory generation choices and
`ManagementSession::generate_ml_dsa_key_pair` to create persistent nonextractable
keys in an RW session. Both pooled clients and management sessions expose
`ml_dsa_capabilities`, `sign_ml_dsa`, `verify_ml_dsa` and `export_ml_dsa_public_key`.
Public export returns RFC 9881 SPKI DER with absent algorithm parameters.

```no_run
use pkcs11_client::{
    Authentication, MlDsaHedging, MlDsaParameterSet, MlDsaRequest,
    MlDsaSigningPolicy, Pin, Provider, SigningPolicy,
};
use secrecy::SecretString;
use std::num::NonZeroUsize;

let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let client = provider.client(&"pkcs11:serial=123".parse()?,
    NonZeroUsize::new(1).unwrap(), SigningPolicy::default())?;
// Obtain this from the application's secret source.
let pin = SecretString::from("example-only");
let key = client.private_key("pkcs11:serial=123;id=%01;type=private".parse()?,
    Authentication::User(Pin::Value(&pin)))?;
let certificate = client.ml_dsa_certificate(
    "pkcs11:serial=123;id=%02;type=cert".parse()?,
    Authentication::User(Pin::Value(&pin)))?;
let policy = MlDsaSigningPolicy::default();
let identity = client.bind_ml_dsa_identity(key, certificate, &policy,
    Authentication::User(Pin::Value(&pin)), None)?;
let request = MlDsaRequest {
    parameter_set: MlDsaParameterSet::MlDsa65,
    message: b"application message",
    context: b"application-v1",
    hedging: MlDsaHedging::Required,
};
let outcome = client.sign_ml_dsa_identity(&identity, &request, &policy,
    Authentication::User(Pin::Value(&pin)), None);
let closed = client.close();
let finalized = provider.finalize();
closed?;
finalized?;
let signature = outcome?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example requires an existing ML-DSA-65 key and matching certificate, without
always-authenticate. Their selectors can use different IDs and labels.
For always-authenticate keys, supply a separate context PIN to each signing call.
Policy/context validation precedes pool checkout; capabilities and handles are
rediscovered for execution. `verify_ml_dsa` runs on the token and maps a mismatch to
`Error::SignatureMismatch`.

`MlDsaVerifyingKey` verifies in software from raw public bytes or exact RFC 9881
SPKI DER, without a module or login. `MlDsaCertificate` retains exact X.509 DER and
a verifier; it requires absent public-key algorithm parameters and byte-aligned,
correctly sized public keys. Both verify the original message and context, reject
noncanonical signatures, and report `SignatureMismatch` for malformed or incorrect
signatures. Verification does not interpret the request's hedging choice.

`bind_ml_dsa_identity` signs a fixed domain-separated probe with required hedging
and verifies it in software before constructing an `MlDsaIdentity`.
`sign_ml_dsa_identity` verifies every subsequent signature against that retained
certificate before returning bytes, detecting replacement keys even under the
same selector and parameter set. Verification failures discard the lease, with
no operation retry. Use explicit client/session closure before releasing output
when cleanup errors must be reported.

Certificate parsing, binding and message verification do not check issuer
signatures, chains, validity, usage, revocation or hostnames. Applications own
those trust decisions. The existing `Certificate` and `Identity` types support
RSA/EC; ML-DSA uses its own certificate, identity and request types.

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

SHA-224 and SHA3-224/256/384/512 RSA PKCS#1 v1.5, RSA-PSS and ECDSA
require adding the corresponding `DigestAlgorithm` to `SigningPolicy::digests`.
The default policy stays SHA-256/384/512. Certificate verification accepts
messages and exact-length prehashes; software PSS verification requires matching
message/MGF digests. Binding probes try SHA-224 and then SHA-3 after the existing
SHA-2 choices when policy permits them. OAEP, HKDF, SP800-108 and ECDH KDF profiles
remain SHA-256/384/512.

`Client::signing_options` offers common SHA-2/SHA-3 message-signing choices under current
key capabilities and the client's policy, including the planned mechanism and
hashing boundary. PSS choices use a matching MGF1 digest and digest-length salt.
Choices are advisory: signing rediscovers capabilities. `SignatureParameters`
creates a typed request from borrowed message or digest bytes without retaining them.

`Certificate::verification_options` supplies matching SHA-2/SHA-3 parameter choices.
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
in RSA-PSS / PKCS#1 order (ECDSA for EC), then SHA-256 / SHA-384 / SHA-512 / SHA-224 followed by SHA3-224/256/384/512,
with PSS salt length equal to digest length. Exactly one selected token operation executes.
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
The observed key type selects RSA, named EC, ML-DSA or ML-KEM SubjectPublicKeyInfo
DER encoding. ML-DSA and ML-KEM use their typed export helpers and require valid
parameter sets and public-key bytes. Unknown types and incomplete or invalid
attributes fail without trying another encoder. Export does not authenticate a
peer or establish certificate trust. `export_classical_public_key` restricts
export to RSA and named EC keys; the typed PQC helpers retain their family checks.
`export_value` retains its explicit raw certificate/data export behavior.

`objects` reads only caller-requested attributes of persistent objects visible to
the session. `inspect` reports available, unavailable, sensitive or unsupported
attributes. `export_value` accepts raw certificate/data values without parsing their
signing algorithms, and rejects key classes before reading their value. Imports
create persistent public objects; certificate metadata comes from
`CertificateDocument`, including for algorithms outside signing support. Data IDs
use CKA_OBJECT_ID. Selectors still follow the runtime's CKA_ID semantics, so use
unique labels to select data objects. IDs/labels do not imply uniqueness.

Unknown object classes and numeric key/certificate/profile/validation types remain
readable in requested attributes without suppressing other objects in a listing.
They do not enable typed key import, export or cryptographic operations. Raw public
certificate/data export retains its existing behavior. Classes outside RFC 7512's
object types have no object locator; they remain visible through `objects`.

`public_metadata` reads a bounded public inspection profile for one object;
`public_object_metadata` also includes profile and validation objects without
inventing RFC 7512 selectors. Both query optional attributes regardless of the
selected interface version. The profile includes unique IDs, public-key-info,
profile IDs, validation metadata and numeric object validation flags, with a
65,536-byte limit per attribute. Empty values remain available; sensitive,
unsupported and unavailable statuses remain distinct. Identity reads during
resolution use the same limit. `inspect_bounded` applies a caller-supplied limit
to identity and explicitly requested attributes; ordinary `inspect` remains
available for callers choosing its existing allocation behavior. Nonempty
public-key-info must parse as SPKI DER, including for unknown algorithms; malformed
DER returns `InvalidPublicKey` without changing session health. Native length/scalar errors
invalidate the session. No secret values or nested templates are requested, and
URI metadata is never fetched. Unique IDs do not replace CKA_ID association or
existing selector rules. `PUBLIC_METADATA_FIELDS` lists the profile's names.
`public_object_summaries` reads only class/label/ID for ordinary objects and adds
metadata snapshots for profiles/validations without selectors. Browsers can defer
ordinary key metadata to selection without losing those unaddressable objects.

`ManagementSession::session_validation_flags` queries the provider's last-operation
flags before closing that session. `None` is unavailable and `Some(0)` is reported
zero; unknown bits survive. Query immediately after the operation of interest.
Validation objects and flags are provider reports, not independent trust decisions.

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

For confirmation flows, capture `TokenSnapshot::initialization_target` and pass
it to `Provider::initialize_token_checked` after closing all consumers. It rejects
changed slot/token metadata, initialized state or PIN bounds before initialization.
The snapshot contains no live resources or credentials. Identical devices and
changes between the check and native call cannot be distinguished; callers must
arrange exclusive physical access. `accepts_new_pin` checks a nonempty host PIN
against available advertised byte bounds; provider constraints remain authoritative.

Management uses one explicitly authenticated session, not an additional pool.
Mutations require RW mode and appropriate provider authorization. Failed operations
retain runtime invalidation semantics and are never retried or rolled back. Drop
never explicitly logs out; closing the last session may reset token login state.

`Client::close` checks closure of idle pooled sessions and reports earlier
closure failures from discarded leases. Release leases before calling it, then
finalize the provider before releasing operation output when cleanup must be
verified. Drop remains best effort. Management session constructors also attempt
checked closure after authentication fails; a closure error takes precedence.

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

## ECDH and AES key generation

`Provider::generation_capabilities` collects classical signing, ECDH, AES, ML-DSA
and ML-KEM generation choices for frontends. Missing mechanisms produce empty
lists; metadata errors propagate. Choices describe generation only and are not an
atomic snapshot or a guarantee of subsequent operation support. Generation
rechecks the selected token before calling the provider.

`generate_ecdh_key_pair` creates a public EC key and a sensitive, nonextractable
private key permitting only derivation, on P-256/P-384/P-521. Export the public
key with `export_public` for peer exchange; authenticate that exchange separately.
`generate_aes_key` creates a private, sensitive, nonextractable AES-128/192/256
key. Choose `Encryption` for encryption/decryption, `Wrapping` for
wrapping/unwrapping, or `Authentication` for AES-CMAC generation/verification.
Authentication keys allow CKM_AES_CMAC only. Other operation permissions are disabled.

```no_run
use pkcs11_client::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication,
    EcdhKeyPairRequest, NamedCurve, Pin, Provider, SessionMode,
};
use secrecy::SecretString;

let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let token = "pkcs11:serial=123".parse()?;
let choices = provider.generation_capabilities(&token)?;
assert!(choices.ecdh.contains(&NamedCurve::P256));
assert!(choices.aes.contains(&AesKeySize::Bits256));
// Obtain this from the application's secret source.
let pin = SecretString::from("example-only");
let mut session = provider.management(&token, SessionMode::ReadWrite,
    Authentication::User(Pin::Value(&pin)))?;
let generated = (|| {
    session.generate_ecdh_key_pair(&EcdhKeyPairRequest {
        curve: NamedCurve::P256, id: b"ecdh-1", label: b"agreement key",
    })?;
    session.generate_aes_key(&AesKeyRequest {
        size: AesKeySize::Bits256, purpose: AesKeyPurpose::Wrapping,
        id: b"wrap-1", label: b"wrapping key",
    })
})();
let closed = session.close();
let finalized = provider.finalize();
closed?;
finalized?;
generated?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Both requests require nonempty ID/label fields of at most 128 bytes. Existing
public/private IDs are rejected for ECDH pairs, and secret IDs for AES. These
checks do not ensure uniqueness against concurrent writers. There is no retry,
rollback or software fallback; failures may leave persistent objects. A wrapping
key does not make nonextractable targets exportable. Existing signing-generation
APIs retain their signing-only behavior.

## AES-GCM encryption

`ManagementSession::aes_gcm_capabilities` checks an AES secret key's current size,
permissions, allowed mechanisms and native provider support. `encrypt_aes_gcm`
and `decrypt_aes_gcm` accept typed requests with a 12-byte nonce, AAD and borrowed
input. The tag is always 16 bytes and follows the ciphertext. The methods work in
RO sessions with the required login state; execution rechecks capabilities.
Encryption keys created by `generate_aes_key` or HKDF can be used directly.
Wrapping-only keys and raw shared secrets are rejected.

```no_run
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, Authentication, Error,
    ObjectRef, Pkcs11Uri, Plaintext, Provider, SessionMode,
};

// The caller supplies a nonce not previously used with this key, including after restart.
fn round_trip(provider: &Provider, token: &Pkcs11Uri, key: &ObjectRef,
    request: &AesGcmEncryptRequest<'_>, auth: Authentication<'_>) -> Result<Plaintext, Error> {
    let mut session = provider.management(token, SessionMode::ReadOnly, auth)?;
    let outcome = (|| {
        let ciphertext = session.encrypt_aes_gcm(key, request)?;
        session.decrypt_aes_gcm(key, &AesGcmDecryptRequest {
            nonce: request.nonce, aad: request.aad, ciphertext: &ciphertext,
        })
    })();
    let closed = session.close();
    closed?;
    outcome
}
```

Plaintext is limited to 16 MiB and AAD to 1 MiB. Empty input/AAD are supported;
decryption requires at least the full tag. Successful plaintext zeroizes on drop
and its Debug is redacted. Authentication failures return no plaintext and make
the session unusable; native error context is retained. Preflight rejection does
not itself invalidate the session. Native decryption output buffers zeroize on
failure and on drop.

Callers manage nonce uniqueness per key across writers, restarts and copies of key
material. No nonce generation/tracking, retry, software fallback, streaming or file
format is provided. Keep the nonce, AAD and protocol context with the ciphertext;
an error does not authorize nonce reuse. The CLI and desktop expose the same raw
ciphertext/tag profile with an explicit nonce and optional AAD file.

`GenerationCapabilities::rsa_encryption` reports common advertised RSA pair sizes.
`ManagementSession::generate_rsa_encryption_key_pair` accepts
`RsaEncryptionKeyPairRequest` for encryption/decryption-only, nonextractable pairs,
including an optional always-authenticate requirement. Existing signing-generation
APIs retain their signing-only permissions. Identity and modulus bounds are
validated before generation; duplicate public/private IDs are rejected.

## RSA-OAEP encryption

`ManagementSession::oaep_options` checks a selected key's class, permissions,
allowed mechanisms and RSA bounds before offering SHA-256/SHA-384/SHA-512 choices.
Each choice uses matching OAEP/MGF1 digests and an empty label. Providers may still
reject a digest parameter; advertisement is advisory and no probe operation occurs.

`encrypt_oaep` and `decrypt_oaep` accept `RsaOaepParameters` for independent
SHA-256/384/512 OAEP and MGF1 digests and a binary label up to 4096 bytes.
`RsaOaepParameters::new(digest)` selects matching digests and an empty label.
The OAEP hash determines the plaintext bound; MGF1 and label length do not change it.
Decryption requires the exact parameters used for encryption. Ciphertext contains
no parameter metadata. Unsupported parameters fail without probing or retrying.

`encrypt` accepts a `PublicKeyRef` and `EncryptRequest`; `decrypt` accepts a
`PrivateKeyRef` and `DecryptRequest`. Both resolve the selector afresh and execute
once on the token, with no fallback or padding downgrade. RSA keys must have
2048–16384 bits. Input is one block: at 2048 bits, SHA-256 OAEP permits 190 plaintext
bytes and ciphertext is exactly 256 bytes. This is not a bulk-file format or sender
authentication. Decryption requires a key with CKA_DECRYPT; always-authenticate
keys require a separate context credential.

Requests redact input in Debug. `Plaintext` and failed decryption buffers use
zeroizing storage; no bytes are returned after failure.

`ManagementSession::decrypt_with_context` supplies a separate per-operation
credential for always-authenticate RSA-OAEP keys. `oaep_options` reports that
requirement. Decryption buffers zeroize on failure and on drop.

## Derivation and key transfer

`ManagementSession::key_operation_options` checks the selected base/wrapping
key's class, permissions, allowed mechanisms and advertised provider bounds.
It returns an advisory `KeyOperationProfile` without performing crypto.
Each request rechecks these constraints and resolves all selectors afresh.

`derive` accepts a `DeriveRequest` with an `EcdhPeer` parsed from SPKI DER and a
`SecretKeyIdentity`. The parser validates named-curve points on P-256/P-384/P-521
and normalizes them to uncompressed SEC1 form. The base must be a private EC key
with CKA_DERIVE on that curve, without per-operation authentication. The explicit
null KDF creates raw ECDH material as a persistent private, sensitive,
nonextractable generic secret with derivation permission only. Raw shared secrets
never leave the provider. Peer authentication and a subsequent KDF are the
caller's responsibility. Apply `derive_hkdf` separately with a supported base/hash
length.

```no_run
use pkcs11_client::{DeriveRequest, EcdhPeer, ManagementSession, ObjectRef, SecretKeyIdentity};
fn derive(session: &mut ManagementSession<'_>, base: &ObjectRef, peer_der: &[u8])
    -> Result<(), pkcs11_client::Error>
{
    let peer = EcdhPeer::from_spki_der(peer_der)?;
    session.derive(base, &DeriveRequest {
        peer: &peer,
        identity: SecretKeyIdentity { id: b"agreement-1", label: b"ECDH material" },
    })
}
```

`derive_ecdh` accepts an `EcdhRequest` with the same validated peer, an explicit
`EcdhKdf`, public shared info and `EcdhOutput`. ANSI X9.63 and NIST SP 800-56A
support SHA-256/384/512. Hashed output can be AES-128/192/256 for encryption and
decryption, or a 1–4096-byte generic secret for further derivation. All outputs
remain persistent, private, sensitive and nonextractable. The null KDF preserves
the full raw secret and cannot create an AES key or accept shared info.
P-521 raw output is still 66 bytes; select a hashed 64-byte generic output
explicitly when a later HKDF-SHA512 stage is needed. Provider rejection never
changes the KDF or triggers software derivation.

```no_run
use pkcs11_client::{DigestAlgorithm, EcdhKdf, EcdhOutput, EcdhPeer, EcdhRequest,
    ManagementSession, ObjectRef, SecretKeyIdentity};
fn derive(session: &mut ManagementSession<'_>, base: &ObjectRef, peer_der: &[u8])
    -> Result<(), pkcs11_client::Error>
{
    let peer = EcdhPeer::from_spki_der(peer_der)?;
    session.derive_ecdh(base, &EcdhRequest {
        peer: &peer,
        kdf: EcdhKdf::X963(DigestAlgorithm::Sha512),
        shared_info: b"protocol v1 peer identities and transcript",
        output: EcdhOutput::DerivationSecret { length: 64 },
        identity: SecretKeyIdentity { id: b"agreement-2", label: b"ECDH KDF material" },
    })
}
```

`wrap` accepts a `WrapRequest` naming an extractable AES-128/192/256 target.
The wrapping key must be AES with CKA_WRAP; CKA_WRAP_WITH_TRUSTED requires a
trusted wrapping key. The operation never reads CKA_VALUE or changes permissions.
`unwrap` accepts an `UnwrapRequest` with a 24/32/40-byte RFC 3394 blob and an
explicit identity. The AES unwrapping key must have CKA_UNWRAP. The created key
is persistent, private, sensitive and nonextractable, with encryption/decryption
permission only. Both use the default RFC 3394 IV; blobs contain no metadata.
Provider wrapping/unwrapping templates remain authoritative.

`aes_key_wrap_options` checks KW and KWP independently for Wrap or Unwrap.
`wrap_with_algorithm` and `unwrap_with_algorithm` use the same request types
with an explicit `AesKeyWrapAlgorithm::Kw` (RFC 3394) or `Kwp` (RFC 5649).
KWP uses its own standard mechanism, not deprecated `AES_KEY_WRAP_PAD`.
Default IVs only; AES-128/192/256 targets and outputs have 24/32/40-byte blobs.
The blob carries no algorithm identifier, so callers must convey and match it.
Existing `wrap`/`unwrap` calls retain KW behavior. All permission, trust and
extractability checks remain in force; there is no algorithm substitution.

New identities require nonempty ID/label fields of at most 128 bytes and reject
existing token secret-key IDs. The check is not atomic against another process.
Derivation and unwrapping require RW mode and provider authorization. Creation
has no retry or rollback: a failure may still have persistent effects. Requests
and peer keys redact their payloads in Debug. No software fallback is used.

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

## ML-KEM

The client exposes ML-KEM-512/768/1024 through scoped management sessions.
`Provider::ml_kem_generation_options` reports advertised choices;
`ManagementSession::generate_ml_kem_key_pair` creates a persistent pair, and
`ml_kem_capabilities` checks the selected direction without performing crypto.
Private decapsulation keys remain sensitive and nonextractable.

`MlKemPublicKey::from_spki_der` accepts RFC 9935 public keys for all three
parameter sets. It requires absent algorithm parameters, a byte-aligned raw
public-key BIT STRING, the exact key length and canonical FIPS 203 coefficients.
`to_spki_der` returns the same standard encoding. The management session's
`export_ml_kem_public_key` reads only public, non-private objects;
`import_ml_kem_public_key` creates a persistent public encapsulation key with an
explicit ID/label in RW mode. It does not overwrite existing objects or establish
peer trust. Duplicate key IDs make subsequent selection ambiguous.

`encapsulate_ml_kem` returns public ciphertext and creates a persistent token-held
raw shared secret under the `MlKemRequest` ID/label. `decapsulate_ml_kem` retains
the corresponding secret under a different explicit identity. Both require RW
mode, rediscover capabilities, check the expected parameter set and reject an
existing secret ID. The 32-byte private generic secrets permit only derivation;
public export helpers reject them. No runtime session or object handle is exposed.

```no_run
use pkcs11_client::{Authentication, Error, MlKemParameterSet, MlKemRequest,
    Pin, Pkcs11Uri, Provider, PublicKeyRef, SessionMode};
use secrecy::SecretString;

fn encapsulate(
    provider: &Provider, token: &Pkcs11Uri, key: &PublicKeyRef, pin: &SecretString,
) -> Result<Vec<u8>, Error> {
    let mut session = provider.management(
        token, SessionMode::ReadWrite, Authentication::User(Pin::Value(pin)),
    )?;
    let outcome = session.encapsulate_ml_kem(key, &MlKemRequest {
        parameter_set: MlKemParameterSet::MlKem768,
        id: b"exchange-1", label: b"raw ML-KEM secret",
    });
    session.close()?;
    outcome
}
```

The caller must authenticate the peer and apply a protocol KDF. Same-length
ciphertext corruption can succeed with a different secret through ML-KEM implicit
rejection. Invalid lengths fail before crypto. Always-authenticate decapsulation
is not implemented. No operation or authentication is retried;
close the session before releasing ciphertext when cleanup must be checked.

## HMAC

`ManagementSession::hmac_capabilities(key, operation)` reports permitted
SHA-224/256/384/512, SHA-512/224, SHA-512/256 and SHA3-224/256/384/512
profiles for generation or verification. `HmacAlgorithm::ALL` enumerates these
choices; the default remains `Sha256`.
`mac_hmac` generates a full tag and `verify_hmac` verifies it on the token.
Generic and matching hash-specific HMAC secrets are supported, with 16–4096-byte
keys, sensitivity, nonextractability and direction-specific permissions required.
Messages may be empty and are limited to 16 MiB. A wrong-length or nonmatching tag
returns `Error::MacMismatch` and leaves the session reusable. Other native failures
invalidate it. RO sessions are supported; check closure before releasing results.

```no_run
use pkcs11_client::{Error, HmacAlgorithm, ManagementSession, ObjectRef};
fn authenticate(session: &mut ManagementSession<'_>, key: &ObjectRef) -> Result<(), Error> {
    let tag = session.mac_hmac(key, HmacAlgorithm::Sha384, b"protocol message")?;
    session.verify_hmac(key, HmacAlgorithm::Sha384, b"protocol message", &tag)
}
```

`generation_capabilities().hmac` reports generic-secret generation choices.
`generate_hmac_key(HmacKeyRequest)` creates a persistent, private, sensitive,
nonextractable hash-length generic secret permitting only the chosen HMAC and
signing/verification. RW access and a new 1–128-byte ID/label are required. Failed
generation may leave effects; no rollback or retry occurs. Provider-specific key
limits may reject a profile; no software MAC, truncation or downgrade is attempted.
Existing derivation-only secrets do not gain MAC permissions.

`hmac_options` reports full and general mechanisms independently;
`hmac_general_capabilities` inspects general profiles only. The explicit
`mac_hmac_with_profile` / `verify_hmac_with_profile` methods accept
`HmacTagProfile::General { tag_length }`. Native general HMAC accepts this
application's half-hash through full-hash lengths (14–28, 16–32, 24–48 or 32–64
bytes). Full-length general tags still require the general mechanism and its
permission. No software truncation or fallback occurs. Agree on one algorithm
and length per key before communicating.

`generation_capabilities().hmac_general` and `generate_hmac_general_key` expose
hash-length secrets restricted to the chosen general mechanism. They retain the
same key attributes and generation checks. Tag length is a protocol contract,
not a token attribute. Existing generation and MAC methods retain full-tag behavior.

## AES-CMAC

`ManagementSession::aes_cmac_capabilities(key, MacOperation::Generate|Verify)`
checks current key permissions and native full-tag CMAC support.
`mac_aes_cmac(key, message)` returns a 16-byte tag; `verify_aes_cmac(key, message,
tag)` verifies on the token and returns `Error::MacMismatch` for incorrect length
or contents. It requires verification permission independently of generation.

The AES secret must be sensitive and nonextractable. Messages may be empty and
are limited to 16 MiB. RO sessions are supported. A completed verification mismatch
leaves the session reusable; other native failures invalidate it. No key values,
software MAC or retry are exposed. Check session closure before releasing the
result. Generate a dedicated key using `AesKeyPurpose::Authentication`.

Use `aes_cmac_options(key, operation)` to inspect full/general profiles. The
explicit `_with_profile` capability, generation and verification methods accept
`AesCmacProfile::General { tag_length }` for native 8–16-byte tags. The original
methods remain full-tag calls. Tags are generated and verified natively, with no
software truncation or profile fallback. Invalid length parameters precede I/O;
wrong tag length/content is a reusable mismatch. Native failures invalidate the
session. Fix the agreed tag length for the key's lifetime and check closure.

Generate a separate `AesKeyPurpose::AuthenticationGeneral` key for this profile;
it permits only CKM_AES_CMAC_GENERAL and MAC operations. The shared generation
capability query reports compatible sizes in `aes_cmac_general`. Existing
`Authentication` keys remain restricted to full-tag CKM_AES_CMAC.

## HKDF

`ManagementSession::hkdf_options` discovers permitted SHA-2 profiles for a selected
generic/HKDF secret without deriving or reading key values. The hash-length base
requirement permits at most one digest. Unsupported profiles are omitted;
selection and provider failures propagate. `hkdf_capabilities` checks an explicit
digest, which is useful when the protocol already specifies one.
`derive_hkdf` takes `HkdfRequest` and performs token-side extract-and-expand with
SHA-256/384/512. The base must be sensitive, nonextractable, permit derivation
and match the hash length. Use SHA-256 with a 32-byte ML-KEM shared secret.

```no_run
use pkcs11_client::{Authentication, DigestAlgorithm, Error, HkdfOutput,
    HkdfRequest, ObjectRef, Pin, Pkcs11Uri, Provider, SessionMode};
use secrecy::SecretString;

fn derive_encryption_key(
    provider: &Provider, token: &Pkcs11Uri, base: &ObjectRef, pin: &SecretString,
    public_salt: &[u8], protocol_context: &[u8],
) -> Result<(), Error> {
    let mut session = provider.management(
        token, SessionMode::ReadWrite, Authentication::User(Pin::Value(pin)),
    )?;
    let outcome = session.derive_hkdf(base, &HkdfRequest {
        digest: DigestAlgorithm::Sha256,
        salt: public_salt, info: protocol_context,
        output: HkdfOutput::Aes256,
        id: b"encryption-key-1", label: b"protocol encryption key",
    });
    session.close()?;
    outcome
}
```

For separate stages, call `derive_hkdf_with_mode(base, request, mode)` with
`HkdfMode::ExtractOnly` or `HkdfMode::ExpandOnly`. Extract-only requires empty
`info` and `HkdfOutput::DerivationSecret { length: digest.output_len() }`. Its
output is a token-held PRK, usable as the base of an expand-only request with
empty `salt`. The caller must establish that an expansion base is a PRK;
matching key metadata cannot prove its origin. Parameters for a disabled stage
are rejected. The original `derive_hkdf` keeps extract-and-expand behavior.

For a token-held salt, call
`derive_hkdf_with_salt_key(base, salt_key, request, mode)` with empty byte `salt`.
Extraction must be enabled. Both locators resolve in the same session. Salt keys
must be sensitive, nonextractable generic/HKDF secrets of 1–4096 bytes with
derivation permission and permitted HKDF use. They need not be hash-length.
The salt stays on the token; its metadata is rechecked at execution. Conflicting
salts and expand-only mode are rejected before native derivation.

New keys are persistent private, sensitive and nonextractable. AES outputs permit
only encryption/decryption; `HkdfOutput::DerivationSecret` permits only further
derivation. IDs and labels are nonempty and at most 128 bytes. Salt/context are
public and at most 4096 bytes each. Empty salt means zero salt; empty context is
permitted. Output length must be 1..=255 times the hash length. Existing secret IDs
are rejected before derivation, without guaranteeing uniqueness against concurrent
writers. No base/output values leave the token, no base is automatically deleted,
and no retry, rollback or software fallback occurs.

Peer authentication and protocol context selection remain application concerns.
An altered ML-KEM ciphertext can produce a different derived key without an error.
`derive_hkdf` accepts one input; the hybrid combiner below accepts two.

## SP 800-108 KDF

`ManagementSession::kbkdf_capabilities` inspects native counter-mode support for a
selected generic or matching SHA-256/384/512 HMAC secret. Bases must be sensitive,
nonextractable, 16–4096 bytes and permit derivation and the selected mechanism.
Generic bases permit all three PRF choices; typed HMAC bases permit their matching
hash. Parameter/template support remains advisory until the native call.

```no_run
use pkcs11_client::{Authentication, DigestAlgorithm, Error, KbkdfOutput,
    KbkdfRequest, ObjectRef, Pin, Pkcs11Uri, Provider, SessionMode};
use secrecy::SecretString;

fn derive_counter_key(
    provider: &Provider, token: &Pkcs11Uri, base: &ObjectRef, pin: &SecretString,
    protocol_label: &[u8], protocol_context: &[u8],
) -> Result<(), Error> {
    let mut session = provider.management(
        token, SessionMode::ReadWrite, Authentication::User(Pin::Value(pin)),
    )?;
    let outcome = session.derive_kbkdf(base, &KbkdfRequest {
        digest: DigestAlgorithm::Sha256,
        kdf_label: protocol_label, context: protocol_context,
        output: KbkdfOutput::Aes256,
        id: b"counter-key-1", label: b"protocol encryption key",
    });
    session.close()?;
    outcome
}
```

The PRF input is `[i]_32 || kdf_label || 0x00 || context || [L]_32`, with
big-endian integers and L in bits. Label/context may be empty or binary, each
bounded to 4096 bytes. Callers agree on an unambiguous encoding and authenticate
peers. This profile creates one persistent private, sensitive, nonextractable
AES-128/192/256 encryption/decryption key, or a 1–4096-byte generic derivation
secret. New IDs/labels are 1–128 bytes; duplicate secret IDs are rejected.
No key values leave the token and native rejection never triggers a retry or
software fallback. Failed calls may leave persistent effects; check closure.

For feedback mode, call `derive_kbkdf_with_mode(base, request,
KbkdfMode::Feedback, iv)`. The PRF input prepends K(i-1) before the existing
counter/label/separator/context/length fields; K(0) is the supplied public IV.
The IV must be empty or match the hash output length (32/48/64 bytes). An empty
IV supplies no initial bytes. `KbkdfMode::Counter` rejects a nonempty IV and
keeps the original `derive_kbkdf` behavior.

`kbkdf_capabilities_with_mode` inspects one mode; `kbkdf_options` returns the
permitted counter/feedback profiles. Only unsupported profiles are omitted.
Selection/provider failures propagate, and execution checks the selected mode
again without substitution or software fallback. Both modes retain the same
output types, permissions, bounds and checked session lifecycle.

## Application hybrid derivation

`ManagementSession::derive_hybrid_hkdf(classical, post_quantum, request)` combines
P-256 ECDH and ML-KEM-768 token secrets in that order, then runs HKDF-SHA512.
Use the same management-session lifecycle as the HKDF example above, with two
distinct 32-byte sensitive, nonextractable generic secrets permitting derivation.
Set `request.digest` to SHA-512, supply public salt of at most 128 bytes and a
nonempty protocol context of at most 4096 bytes. Output permissions remain the same.

The caller establishes the origin and independence of both components,
authenticates peers and binds context to the protocol exchange. Key metadata cannot
prove provenance. The temporary concatenation is destroyed before return; close the
session on success and failure, and account for possible persistent output when
cleanup fails. Inputs are not deleted and values never leave the token.

This is an application combiner, not a complete hybrid KEM wire protocol, X-Wing
or the TLS key schedule. See the [runtime contract](../pkcs11-runtime/README.md#application-hybrid-derivation)
for construction and failure semantics.

`Client::verify_token` and `ManagementSession::verify_token` verify RSA/ECDSA
signatures with a selected token public key and `VerifyRequest`. Shared
`verification_options` queries report choices from verification permissions and
the caller's signature policy. Certificate verification remains a separate
software workflow; neither operation validates certificate trust.

## RSA and EC public-key import

`ClassicalPublicKey::from_spki_der` validates one canonical SPKI DER document
up to 4096 bytes: rsaEncryption keys of 2048–16384 bits, or named
P-256/P-384/P-521 keys. Restricted RSA-PSS keys and other algorithms/curves are
rejected. The existing RSA/EC libraries validate the components and curve points.
Absent RSA NULL parameters normalize to NULL; compressed EC points normalize to
uncompressed SEC1 form. `spki_der()` returns this normalized encoding.

`import_classical_public_key` takes a `PublicKeyImportRequest` with an explicit
verification or RSA-encryption purpose and nonempty ID/label of at most 128 bytes.
It creates a public persistent object through the runtime's component-attribute
creation API. Wrapping, verification recovery and derivation are disabled.
An existing public-key ID is rejected; private keys/certificates sharing the ID
are neither changed nor bound to the imported key. Import does not establish
identity, provenance or private-key possession.

```no_run
use pkcs11_client::{ClassicalPublicKey, ClassicalPublicKeyPurpose, ManagementSession,
    PublicKeyImportRequest};
fn import(session: &mut ManagementSession<'_>, spki: &[u8]) -> Result<(), pkcs11_client::Error> {
    let key = ClassicalPublicKey::from_spki_der(spki)?;
    session.import_classical_public_key(&PublicKeyImportRequest {
        key: &key,
        purpose: ClassicalPublicKeyPurpose::Verification,
        id: b"peer-key",
        label: b"Peer verification key",
    })
}
```

Requires RW access; providers may impose authentication or component limits.
Duplicate checks do not lock concurrent writers. Provider failures may leave an
object and invalidate the session; no retry or rollback occurs. Check closure.
Private/secret components are not accepted by this API.

## Token file digests

`ManagementSession::digest_algorithms(DigestMode)` discovers advertised fixed-output
hash algorithms with the required native entry points. `digest_reader` streams a
`Read` input in 64 KiB chunks on the token. Its input buffer zeroizes on return;
the whole input is never retained. It supports empty input and interrupted reads.
A read or provider failure leaves the session unusable; close it before replacing
it. No software hash fallback, key digest or algorithm substitution occurs.

```no_run
use pkcs11_client::{HashAlgorithm, ManagementSession};
fn hash_file(session: &mut ManagementSession<'_>, file: &mut std::fs::File)
    -> Result<Vec<u8>, pkcs11_client::Error>
{
    session.digest_reader(HashAlgorithm::Sha3_256, file)
}
```

Supported hash choices are SHA-224/256/384/512, SHA-512/224, SHA-512/256 and the
four fixed-output SHA-3 hashes. Signature and MGF choices remain separate.
Check session closure before publishing the digest.

## Pure Ed25519 and Ed448

`EdDsaRequest { curve, message }` accepts original messages, including empty input.
`Client::sign_eddsa` and `verify_eddsa` execute the explicit pure profile without
external hashing, prehash/context variants or fallback. These APIs do not use
`SigningPolicy::digests`; choosing an `EdDsaCurve` explicitly enables that curve.
Management sessions expose the same operations and bounded persistent generation.
`GenerationCapabilities::eddsa` supplies advisory frontend choices.

`EdDsaVerifyingKey::from_spki_der` validates one canonical
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) document with absent
algorithm parameters and raw 32/57-byte public keys. Decoding rejects identity,
non-prime-subgroup and noncanonical points. `verify_signature` checks pure
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) signatures in software.
`import_eddsa_public_key` creates verification-only public objects with explicit
1–128-byte ID/label in RW mode; duplicate public IDs are rejected.
`export_eddsa_public_key` and `ManagementSession::export_public` validate public
material before emitting SPKI DER. Private keys and seeds are never imported or
exported by these APIs.

`EdDsaCertificate` retains exact certificate bytes and a software verifier.
`bind_eddsa_identity` proves possession using one domain-separated message;
`sign_eddsa_identity` checks every signature against that retained certificate,
including after a key is replaced under the same selector. Verification failures
discard the lease. Parsing and binding do not establish certificate trust.

## Explicit digest cancellation

`ManagementSession::start_digest` returns an exclusively borrowed
`DigestOperation` with `update`, `finish` and consuming `cancel` methods. Use it
when the application controls chunking and may explicitly abandon input. No
chunks or credentials are retained by the guard. Only confirmed native
cancellation restores reuse; failed updates and unsuccessful cancellation require
closing the session. Drop never calls cancellation implicitly.

`ManagementSession::cancel_operations` exposes the runtime's typed `CancelFlags`
for currently supported synchronous operation classes. It checks the selected
function table and never falls back to legacy cancellation or global teardown.
`Provider::supports_function(Function::SessionCancel)` reports pointer presence;
a provider may still reject the actual call. A 2.40 selection cannot cancel,
even when the module reports a newer library/table version.

The existing `digest_reader` contract is unchanged: interrupted reads continue,
while read/native failures discard the operation and session. No reader failure
causes an automatic cancellation or second attempt.
