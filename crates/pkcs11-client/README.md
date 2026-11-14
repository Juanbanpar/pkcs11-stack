# pkcs11-client

Synchronous application workflows over [pkcs11-runtime](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md):
resource discovery, signing, certificate binding, encryption, key derivation and
scoped administration. Part of [pkcs11-stack](https://github.com/Juanbanpar/pkcs11-stack/blob/main/README.md).

## Signing with a certificate

Load a trusted module and supply authentication per call. Prefer token serials and
binary object IDs; zero or multiple matches return errors. Binding proves key
possession with a signature, independently of matching labels or IDs.

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
client.close()?;
provider.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

This requires an RSA key with combined SHA-2 signing support. `Pin::Value` uses
`secrecy` 0.10; `Pin::ProtectedPath` requires token support. Always-authenticate
keys need a separate context PIN for each binding/signing call.

## Ownership, authentication and failure handling

| API | Contract |
| --- | --- |
| `Provider::load` | Own one explicitly trusted module; a URI never loads code |
| `Provider::client` / `Client::connect` | Create a read-only pool; `Client::new` accepts an existing pool |
| `Provider::management` | Open one borrowed session with explicit mode and authentication |
| `Provider::management_owned` | Retain the module owner across requests without borrowing the provider or retaining a PIN |
| `Client::close` / session `close` | Report cleanup failures; Drop is best effort |
| `Provider::finalize` | Requires closed consumers; live owned sessions return `ProviderInUse` |

The complete token URI is checked against the loaded module, slot and token.
Object criteria, credentials and unsupported token constraints are rejected.
`object_reference`, `validate_token_uri` and `token_uri` validate/project selectors
without loading a library. Clients cannot outlive their borrowed module:

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

Share a client per token and authentication role. Pool exhaustion fails immediately
with `Error::Runtime(PoolExhausted)`. Authentication ensures a role; an already
logged-in role may not recheck the supplied PIN. `Authentication::None` leaves
login state unchanged. Login/logout affect all sessions on the token. Drop never
explicitly logs out, though closing the last session may reset authentication.
PINs are borrowed and never retained; SO requires RW mode.

Operations re-resolve selectors and recheck capabilities. Advisory choices and
plans do not guarantee provider acceptance. Authentication and failed operations
are never retried; failed sessions follow runtime invalidation rules. Mutations
have no rollback and may leave persistent objects or partial attribute updates.
Duplicate-ID checks do not prevent races with concurrent writers.

When cleanup must be verified, capture the operation result, close the client or
session, finalize the provider, then release output. Cleanup errors take precedence;
failed management authentication also attempts checked closure. `Error::kind`
provides semantic categories; diagnostic strings are not a parsing or retry contract.

## Classical signing and certificate binding

| API or option | Behavior |
| --- | --- |
| `SigningPolicy::default()` | Token hashing, RSA minimum 2048 bits, SHA-256/384/512 |
| `HashingPolicy::AllowSoftware` / `SoftwareOnly` | Explicit software hashing selection before signing; no retry after a token failure |
| `SignInput::Digest` | Already computed digest of the exact selected length; never hashed again |
| `signing_options` / `plan` | Advisory mechanism and hashing-location selection |
| `SignatureParameters` | Build requests from borrowed message/digest bytes |
| `sign` | Raw modulus-width RSA or fixed-width ECDSA `r \|\| s`; no certificate required |
| `Certificate::verification_options` / `verify_signature` | Software signature verification; mismatch returns `SignatureMismatch` |
| `bind_identity` / `sign_identity` | Prove association, then verify every signature against the retained certificate |

SHA-1 and SHA-224 require explicit additions to `policy.digests`; software
certificate verification also requires the SHA-1 opt-in. PSS choices use matching
MGF1/message digests and digest-length salt. Generic token signing permits
independent MGF1 parameters; bound signing requires matching digests and rejects
unsupported requests before checkout.

`CertificateDocument::from_der` parses exact X.509 DER for inspection/import,
including algorithms outside classical signing support. It retains DER, SPKI,
subject/issuer Names and serial-number DER. `Certificate::from_der` additionally
requires rsaEncryption RSA (up to 16384 bits) or named P-256/P-384/P-521 keys;
malformed keys, restricted RSA-PSS SPKI and trailing bytes fail. `document()`
exposes the parsed metadata.

`bind_identity` signs `pkcs11-client identity binding v1` followed by NUL, then
verifies with the certificate. It chooses RSA-PSS, then PKCS#1 (ECDSA for EC),
and SHA-256/384/512 under policy, executing exactly one probe. No allowed probe
returns `NoBindingMechanism`. `Certificate::validate_signing_request` checks
verifier parameters independently of token capability/policy planning.

An `Identity` retains a selector and certificate snapshot, without handles or PINs.
`sign_identity` detects replacement keys by verifying each signature; mismatch
discards the lease. Calling generic `sign(identity.key(), ...)` omits that check.
Parsing, binding and verification do not validate issuer signatures, chains,
validity, usage, revocation or hostnames. Applications own certificate trust.

## Discovery and administration

`Provider` returns slot, token, mechanism and generation snapshots. Management
sessions expose inspection, import/export, key generation, relabel/delete and PIN
administration without raw runtime sessions or object handles.

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

| Workflow | Contract |
| --- | --- |
| `objects` / `inspect` | Read caller-requested persistent-object attributes; distinguish unavailable, sensitive and unsupported values |
| `attributes` / `public_metadata` / `capabilities` | Typed lookup and inspection; raw requested attributes can expose extractable secrets |
| `export_value` | Raw certificate/data values; rejects key classes before reading values |
| `export_public` | Public certificate/data values or validated RSA/EC/ML-DSA/ML-KEM/SLH-DSA SPKI; rejects private objects and private/secret key classes |
| Typed public-key helpers | EdDSA/Montgomery and family-specific PQC import/export; `export_classical_public_key` restricts to RSA/EC |
| Certificate/data import | Create persistent public objects; certificate metadata is parsed without a trust decision |
| `import_public_key` | Validate RSA/named-EC SPKI with explicit verification or RSA-encryption purpose |
| `object_locator` | Build a selector from available class/label/CKA_ID; preserve empty criteria and module-path constraints |
| `diagnose` | Explicit bounded-pool capacity, exhaustion and reuse check; not automatic recovery |

Attribute containers redact Debug output; explicit value access can reveal secrets.
Data IDs use CKA_OBJECT_ID, while selectors use CKA_ID: select data by unique label.
Locators return `None` for unrepresentable identities and can remain ambiguous.
Resolve them again before use. Public export validates encoding, not peer identity.

For destructive confirmation flows, capture `TokenSnapshot::initialization_target`
and call `Provider::initialize_token_checked` after closing all consumers. It
rechecks slot/token metadata, initialized state and PIN bounds. `accepts_new_pin`
checks nonempty host PINs against advertised byte bounds; the provider remains
authoritative. Identical replacement devices and swaps after the check cannot be
detected; arrange exclusive physical access. Direct `initialize_token` can erase
an explicit slot and also requires exclusive ownership:

```compile_fail,E0505
use pkcs11_client::{Authentication, Provider, SessionMode};
fn invalid_shutdown(provider: Provider) {
    let session = provider.management(&"pkcs11:token=test".parse().unwrap(),
        SessionMode::ReadOnly, Authentication::None).unwrap();
    provider.finalize().unwrap();
    session.close().unwrap();
}
```

## Key generation

`Provider::generation_capabilities` collects advisory choices for frontends;
missing mechanisms yield empty lists and metadata errors propagate. Generation
rechecks the selected token. `generation_options` offers common RSA sizes and
P-256/P-384/P-521; the signing API retains its full RSA range and nonempty-ID rule.

| Request | Generated key permissions |
| --- | --- |
| Signing key pair | Sensitive, nonextractable private key for signing |
| `EcdhKeyPairRequest` | P-256/P-384/P-521 public key plus derivation-only sensitive, nonextractable private key |
| `AesKeyRequest` | Private, sensitive, nonextractable AES-128/192/256; `Encryption` or `Wrapping` purpose |
| `generate_mac_key` | Persistent HMAC or AES-CMAC key |

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

ECDH/AES IDs and labels require 1–128 bytes. Existing public/private IDs are
rejected for ECDH, secret IDs for AES; concurrent uniqueness is not guaranteed.
Wrapping keys do not make nonextractable targets exportable.

## Encryption

| API | Profile and constraints |
| --- | --- |
| `aes_gcm_capabilities`, `encrypt_aes_gcm`, `decrypt_aes_gcm` | AES secret key with direction permission; 12-byte nonce, separate AAD, ciphertext followed by full 16-byte tag |
| `oaep_options`, `encrypt`, `decrypt` | RSA 2048–16384 bits, SHA-256/384/512 with matching MGF1 and empty label; one block |
| `aes_capabilities`, `encrypt_aes`, `decrypt_aes` | ECB/CBC/CBC-PAD; see request rustdoc for IV, padding and input bounds |

AES-GCM permits RO sessions and empty plaintext/AAD; plaintext is limited to
16 MiB, AAD to 1 MiB. Generated encryption keys and HKDF AES outputs qualify;
wrapping-only keys and raw shared secrets do not. Callers ensure nonce uniqueness
per key across writers, restarts and key copies. An encryption error does not
permit nonce reuse. No nonce tracking or file envelope is supplied.

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

Decryption returns zeroizing, redacted `Plaintext` only after provider success.
GCM authentication failure returns no plaintext and invalidates the session;
preflight rejection alone does not. cryptoki's temporary failed-call buffers
cannot be guaranteed zeroized.

OAEP uses `PublicKeyRef`/`EncryptRequest` and `PrivateKeyRef`/`DecryptRequest`.
At 2048 bits, SHA-256 allows 190 plaintext bytes and produces 256 ciphertext bytes.
It provides neither bulk encryption nor sender authentication. Per-operation-
authenticated decryption keys are rejected before init because the binding cannot
interleave context login and single-part decryption. No padding downgrade occurs.

## Derivation and key transfer

`key_operation_options` returns advisory permissions/mechanisms/bounds without
crypto. Execution checks every selector again.

| API | Input and result |
| --- | --- |
| `derive` / `DeriveRequest` | Validated P-256/P-384/P-521 `EcdhPeer` SPKI; null KDF; persistent derivation-only generic secret |
| `wrap` / `WrapRequest` | AES CKA_WRAP key plus extractable AES-128/192/256 target; honor CKA_WRAP_WITH_TRUSTED |
| `unwrap` / `UnwrapRequest` | AES CKA_UNWRAP key plus 24/32/40-byte RFC 3394 blob; persistent AES encryption/decryption key |

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

ECDH requires matching curves and rejects per-operation-authenticated base keys.
Authenticate peers and apply a subsequent KDF. RFC 3394 uses the default IV and
carries no metadata. Derivation/unwrapping require RW mode and new 1–128-byte
IDs/labels, rejecting existing secret IDs. Resulting keys are private, sensitive
and nonextractable; provider templates remain authoritative.

## ML-DSA

Pure ML-DSA-44/65/87 uses `MlDsaRequest` and `MlDsaSigningPolicy`, independently of
classical `SigningPolicy`. Requests carry the original message, 0–255-byte context
and required/preferred/deterministic hedging. Required hedging fails without token
randomness. Generation is advisory through `Provider::ml_dsa_generation_options`
and persistent through `ManagementSession::generate_ml_dsa_key_pair`.

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

The example needs an existing ML-DSA-65 key and matching certificate, without
always-authenticate. Their IDs/labels can differ. Supply a separate context PIN
for always-authenticate signing. Validation precedes checkout; execution
rediscovers capabilities. `verify_ml_dsa` runs on the token and reports
`SignatureMismatch` for a mismatch.

`MlDsaVerifyingKey` verifies messages/context in software from raw public bytes or
RFC 9881 SPKI without a module. `MlDsaCertificate` retains exact X.509 DER with
absent algorithm parameters and a correctly sized, byte-aligned public key.
Malformed/noncanonical signatures return `SignatureMismatch`; verification does
not interpret hedging.

`bind_ml_dsa_identity` proves association with a domain-separated probe and required
hedging. `sign_ml_dsa_identity` checks every signature against the retained leaf,
detecting replacement under an unchanged selector/parameter set. Mismatch discards
the lease. These types make no certificate trust decision. Typed public export
produces RFC 9881 SPKI DER.

## ML-KEM

Management sessions support ML-KEM-512/768/1024 generation, capability inspection,
public import/export, encapsulation and decapsulation. Private keys are sensitive
and nonextractable. `MlKemPublicKey::from_spki_der` validates RFC 9935 encoding,
absent parameters, byte alignment, length and canonical FIPS 203 coefficients;
`to_spki_der` returns that encoding. Import needs RW mode and explicit ID/label;
it preserves existing objects but duplicate IDs can make selection ambiguous.

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

`encapsulate_ml_kem` returns public ciphertext; `decapsulate_ml_kem` accepts it.
Both need RW mode, an expected parameter set and a new secret ID/label. They create
persistent private 32-byte generic secrets, sensitive/nonextractable and permitting
only derivation. Always-authenticate decapsulation is unsupported.

Authenticate the peer and apply a protocol KDF. ML-KEM implicit rejection can
produce a different secret for altered same-length ciphertext without an error.
Invalid lengths fail before crypto; success does not prove peer identity or agreement.

## HKDF

`hkdf_options` returns the base's permitted hash profile without deriving or reading
values; unsupported profiles are omitted and selection/provider errors propagate.
`hkdf_capabilities` checks an explicit digest. `derive_hkdf` performs token-side
extract-and-expand on a sensitive, nonextractable generic/HKDF base with CKA_DERIVE.
The base must match the hash length: 20/28/32/48/64 bytes for SHA-1/224/256/384/512.
Use SHA-256 for a 32-byte ML-KEM secret.

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

| Parameter | Contract |
| --- | --- |
| Salt/context | Public; at most 4096 bytes each; empty salt means zero salt and empty context is permitted |
| Output | AES-128/192/256 for encryption/decryption, or `DerivationSecret` for further derivation |
| Length | 1 through 255 times the hash length |
| Identity | New nonempty ID/label, at most 128 bytes each; existing secret IDs rejected |
| Ownership | Persistent private, sensitive, nonextractable output; bases remain until explicitly deleted |

Peer authentication and context selection belong to the protocol. Single-input
HKDF does not authenticate ciphertexts or combine classical/PQC inputs.

## Application hybrid derivation

`derive_hybrid_hkdf(classical, post_quantum, request)` combines P-256 ECDH then
ML-KEM-768 token secrets and applies HKDF-SHA512. Use two distinct 32-byte sensitive,
nonextractable generic secrets permitting derivation and concatenation. Set SHA-512,
salt of at most 128 bytes and nonempty protocol context of at most 4096 bytes.
Output permissions follow HKDF.

The caller establishes component provenance/independence, authenticates peers and
binds identities, roles, algorithms and transcript in the protocol context.
The temporary concatenation is destroyed before return; cleanup failure can leave
a persistent output. Inputs remain on the token. See the
[runtime contract](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md#application-hybrid-derivation).
This is not a wire protocol, X-Wing or the TLS key schedule.

## Additional mechanisms

| Family | Application API |
| --- | --- |
| Capabilities | `Provider::mechanism_capabilities`, `function_availability` |
| Digest/MAC | `digest`, `digest_chunks`, `mac`, `verify_mac`; management also supports multipart MAC |
| Token verification | `verify`, `verify_signature` and family-specific verification for EdDSA/ML-DSA/SLH-DSA/hash-PQC |
| SP 800-108 | Management `kbkdf_options`, `kbkdf_capabilities`, `derive_kbkdf` |
| SLH-DSA/hash-PQC | Generation, signing, verification and public parameter inspection; HashSLH-DSA uses a separate HashSLH-only pair |
| EdDSA | Pure Ed25519/Ed448 generation, sign/verify, public import/export, `EdDsaVerifyingKey`, `EdDsaCertificate`, `EdDsaIdentity` |
| Montgomery | X25519/X448 generation, validated RFC 8410 public import/export and `derive_montgomery` |

All reuse runtime permission, mechanism and session-health checks; unsupported
families return typed errors. EdDSA context authentication is rejected because
`cryptoki` lacks single-part signing after explicit initialization. Software
certificate verification supports Ed25519/Ed448; the TLS adapter enables Ed25519.
See the [mechanism matrix](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/oasis-compatibility.md) for application
coverage and upstream limits; API rustdoc defines individual request contracts.

## Random bytes and examples

`generate_random(RandomRequest)` requests 1–1048576 bytes from the token once.
Invalid lengths fail before allocation. Authentication is explicit and subject to
token policy. `RandomBytes` uses zeroizing, redacted `SecretBox<Vec<u8>>`; access
output through `ExposeSecret` and check session closure before releasing it.

[Runnable examples](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/examples.md) cover generic signing, certificate
binding and shutdown with PIN files.

```sh
cargo test -p pkcs11-client --locked
cargo doc -p pkcs11-client --no-deps --locked
```

See the [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md) for disposable provider suites.
