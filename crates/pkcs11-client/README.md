# pkcs11-client

A synchronous Rust API for applications that use PKCS#11 tokens and HSMs. Find
keys and certificates by URI, run cryptography with token-held keys, and manage
persistent objects through typed requests over [pkcs11-runtime](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md).

| What you can do | API |
| --- | --- |
| Load a trusted module and discover slots, tokens, mechanisms, and key generation options | `Provider` |
| Sign and verify with a bounded session pool. Bind a key to a certificate and check each resulting signature against it | `Client` |
| Inspect, generate, import, export, relabel, and delete objects, and initialize or change PINs | `ManagementSession` |
| Encrypt and decrypt, establish or derive keys, wrap and unwrap AES keys, compute digests and MACs, and generate random bytes | `ManagementSession` |

## Installation

Requires Rust 1.88 or newer. Use this dependency after version `0.1.0` is
published on crates.io.

```toml
[dependencies]
pkcs11-client = "0.1.0"
```

For development against a sibling checkout, use the workspace path.

```toml
[dependencies]
pkcs11-client = { path = "../pkcs11-stack/crates/pkcs11-client" }
```

## Signing with a certificate

For a first signature without a certificate, follow the
[disposable SoftHSM quickstart](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/quickstart.md#sign-from-rust-with-the-same-key).
Token operations use a trusted PKCS#11 module and a compatible token.
See the [API reference](https://docs.rs/pkcs11-client) after publication or
generate it with the command in [Tests](#tests).

Use `Client::sign` for a private-key selector, or bind the key to a certificate
when the application needs to verify each signature against that certificate.
Binding proves key possession with a signature. Certificate trust remains the
application's responsibility.

This example uses an existing RSA key and matching certificate on a token
that supports combined RSA PKCS#1 v1.5 signing with SHA-256.

```no_run
use pkcs11_client::{
    Authentication, DigestAlgorithm, Pin, Provider, SecretText, SignInput, SignRequest,
    SignatureAlgorithm, SigningPolicy,
};
use std::num::NonZeroUsize;

let token = "pkcs11:serial=123".parse()?;
let key_uri = "pkcs11:serial=123;id=%01;type=private".parse()?;
let certificate_uri = "pkcs11:serial=123;id=%01;type=cert".parse()?;
let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let client = provider.client(&token, NonZeroUsize::new(4).unwrap(), SigningPolicy::default())?;
// Example only: obtain this from the application's secret source.
let pin = SecretText::from("example-only");
let auth = || Authentication::User(Pin::Value(&pin));
let outcome = (|| {
    let key = client.private_key(key_uri, auth())?;
    let certificate = client.certificate(certificate_uri, auth())?;
    let identity = client.bind_identity(key, certificate, auth(), None)?;
    let request = SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input: SignInput::Message(b"application message"),
        pss: None,
    };
    client.sign_identity(&identity, &request, auth(), None)
})();
let closed = client.close();
let finalized = provider.finalize();
closed?;
finalized?;
let signature = outcome?;
assert!(!signature.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Classical signing and certificate binding

| API or option | Behavior |
| --- | --- |
| `SigningPolicy::default()` | Token hashing, RSA minimum 2048 bits, SHA-256/384/512 |
| `HashingPolicy::AllowSoftware` / `SoftwareOnly` | Explicit software hashing selection before signing. No retry after a token failure |
| `SignInput::Digest` | Already computed digest of the exact selected length. Never hashed again |
| `signing_options` / `plan` | Advisory mechanism and hashing-location selection |
| `SignatureParameters` | Build requests from borrowed message/digest bytes |
| `sign` | Raw modulus-width RSA or fixed-width ECDSA `r \|\| s`. No certificate required |
| `Certificate::verification_options` / `verify_signature` | Software signature verification. Mismatch returns `SignatureMismatch` |
| `bind_identity` / `sign_identity` | Prove association, then verify every signature against the retained certificate |

| Profile or API | Details |
| --- | --- |
| SHA-1 and SHA-224 | Add to `policy.digests` explicitly. Software certificate verification also requires the SHA-1 opt-in |
| PSS | Offered choices use matching message and MGF1 digests and digest-length salt. Generic token signing permits independent MGF1 parameters. Bound signing requires matching digests |
| `CertificateDocument::from_der` | Exact X.509 DER for inspection and import, including keys outside classical signing support. Retains DER, SPKI, subject/issuer Names, and serial-number DER |
| `Certificate::from_der` | Requires rsaEncryption RSA up to 16384 bits or named P-256/P-384/P-521. Rejects malformed keys, restricted RSA-PSS SPKI, and trailing bytes. `document()` exposes the parsed metadata |
| `Certificate::validate_signing_request` | Checks verifier parameters independently of token capability or policy planning |
| `bind_identity` | Signs one probe (`pkcs11-client identity binding v1` followed by NUL). Prefers RSA-PSS, then PKCS#1, or ECDSA for EC, using SHA-256/384/512 under policy. Returns `NoBindingMechanism` if no probe qualifies |
| `sign_identity` | The identity holds a selector and certificate without handles or PINs. A signature mismatch discards the lease. Use this API for replacement-key detection |
| Certificate trust | Applications validate issuer signatures, chains, validity, usage, revocation, and hostnames |

## Discovery and administration

Use a scoped management session to inspect a visible certificate and export its
DER. Use stable token serials and object IDs so each selector has one match.

```no_run
use pkcs11_client::{Authentication, AttributeType, Provider, SessionMode, object_reference};
let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let token = "pkcs11:token=production;serial=123".parse()?;
let mut session = provider.management(&token, SessionMode::ReadOnly, Authentication::None)?;
let reference = object_reference("pkcs11:serial=123;object=certificate;type=cert".parse()?)?;
let outcome = (|| {
    session.inspect(&reference, &[AttributeType::Label, AttributeType::Subject])?;
    session.export_value(&reference)
})();
let closed = session.close();
let finalized = provider.finalize();
closed?;
finalized?;
let _der = outcome?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Workflow | Contract |
| --- | --- |
| `objects` / `inspect` | Read caller-requested persistent-object attributes. Distinguish unavailable, sensitive and unsupported values |
| `attributes` / `public_metadata` / `capabilities` | Typed lookup and inspection. Raw requested attributes can expose extractable secrets |
| `export_value` | Raw certificate/data values. Rejects key classes before reading values |
| `export_public` | Public certificate/data values or validated RSA/EC/ML-DSA/ML-KEM/SLH-DSA SPKI. Rejects private objects and private/secret key classes |
| Typed public-key helpers | EdDSA/Montgomery and family-specific PQC import/export. `export_classical_public_key` restricts to RSA/EC |
| Certificate/data import | Create persistent public objects. Certificate metadata is parsed without a trust decision |
| `import_public_key` | Validate RSA/named-EC SPKI with explicit verification or RSA-encryption purpose |
| `object_locator` | Build a selector from available class/label/CKA_ID. Preserve empty criteria and module-path constraints |
| `diagnose` | Explicit bounded-pool capacity, exhaustion and reuse check. Not automatic recovery |

- Attribute containers redact Debug output. Explicit value access can reveal secrets.
- Select data objects by unique label. Their IDs use CKA_OBJECT_ID, while URI IDs
  match CKA_ID. `object_locator` returns `None` for unrepresentable identities.
  Resolve a locator before use because it can still be ambiguous.
- For a destructive confirmation flow, capture `TokenSnapshot::initialization_target`,
  close all consumers, and call `Provider::initialize_token_checked`. It rechecks
  slot and token metadata, initialized state, and PIN bounds. `accepts_new_pin`
  checks nonempty host PINs against advertised byte bounds.
- Keep exclusive physical access for token initialization. The checked operation
  can miss identical replacements and swaps after the check. Direct
  `initialize_token` erases an explicit slot and also requires exclusive ownership.

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

- `Provider::generation_capabilities` returns advisory choices. Missing
  mechanisms yield empty lists. Metadata errors propagate.
- `generation_options` offers common RSA sizes and P-256/P-384/P-521. The
  signing API supports its full RSA range and requires a nonempty ID.
- Generation rechecks the selected token before submitting the request.

| Request | Generated key permissions |
| --- | --- |
| Signing key pair | Sensitive, nonextractable private key for signing |
| `EcdhKeyPairRequest` | P-256/P-384/P-521 public key plus derivation-only sensitive, nonextractable private key |
| `AesKeyRequest` | Private, sensitive, nonextractable AES-128/192/256. `Encryption` or `Wrapping` purpose |
| `generate_mac_key` | Persistent HMAC or AES-CMAC key |

```no_run
use pkcs11_client::{
    SecretText,
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication,
    EcdhKeyPairRequest, NamedCurve, Pin, Provider, SessionMode,
};

let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let token = "pkcs11:serial=123".parse()?;
let choices = provider.generation_capabilities(&token)?;
assert!(choices.ecdh.contains(&NamedCurve::P256));
assert!(choices.aes.contains(&AesKeySize::Bits256));
// Obtain this from the application's secret source.
let pin = SecretText::from("example-only");
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

ECDH and AES IDs and labels require 1–128 bytes. Generation checks for
existing public or private key IDs for ECDH and secret key IDs for AES.

## Encryption

| API | Profile and constraints |
| --- | --- |
| `aes_gcm_capabilities`, `encrypt_aes_gcm`, `decrypt_aes_gcm` | AES secret key with direction permission. 12-byte nonce, separate AAD, ciphertext followed by full 16-byte tag |
| `oaep_options`, `encrypt`, `decrypt` | RSA 2048–16384 bits, SHA-256/384/512 with matching MGF1 and empty label. One block |
| `aes_capabilities`, `encrypt_aes`, `decrypt_aes` | ECB/CBC/CBC-PAD. See request rustdoc for IV, padding and input bounds |

- **Session and limits**. Read-only sessions work. Plaintext is limited to
  16 MiB and AAD to 1 MiB. Either may be empty.
- **Keys**. Use a generated encryption key or an HKDF AES output with the
  appropriate permission.
- **Nonce and format**. Ensure nonce uniqueness per key across writers, restarts,
  and key copies, including after an encryption error. Store the nonce and AAD
  separately. Applications handle nonce tracking and framing.

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

| Decryption | Contract |
| --- | --- |
| AES-GCM | Returns zeroizing, redacted `Plaintext` after provider success. Authentication failure invalidates the session. Preflight rejection alone leaves it usable. Failed cryptoki calls can leave temporary buffers unwiped |
| RSA-OAEP | Uses `PublicKeyRef`/`EncryptRequest` and `PrivateKeyRef`/`DecryptRequest`. With RSA-2048 and SHA-256, up to 190 plaintext bytes produce 256 ciphertext bytes. Use for small payloads and authenticate the sender separately |
| OAEP authentication and padding | A per-operation-authenticated key fails before initialization because the binding cannot interleave context login and single-part decryption. A provider failure preserves the requested padding policy |

## Derivation and key transfer

`key_operation_options` returns advisory permissions/mechanisms/bounds without
crypto. Execution checks every selector again.

| API | Input and result |
| --- | --- |
| `derive` / `DeriveRequest` | Validated P-256/P-384/P-521 `EcdhPeer` SPKI. Null KDF. Persistent derivation-only generic secret |
| `wrap` / `WrapRequest` | AES CKA_WRAP key plus extractable AES-128/192/256 target. Honor CKA_WRAP_WITH_TRUSTED |
| `unwrap` / `UnwrapRequest` | AES CKA_UNWRAP key plus 24/32/40-byte RFC 3394 blob. Persistent AES encryption/decryption key |

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

- **ECDH**. Use matching curves and a base key without per-operation authentication.
  Authenticate peers and apply a subsequent KDF.
- **RFC 3394**. Uses the default IV and carries no metadata. The wrapping key
  must satisfy the target's trust and extractability requirements.
- **New keys**. Derivation and unwrapping require a read-write session and a new
  1–128-byte ID and label. Outputs are private, sensitive, and nonextractable.
  The provider must accept the template.

## ML-DSA

- **Request**. `MlDsaRequest` and `MlDsaSigningPolicy` cover ML-DSA-44/65/87
  independently of classical policy. Supply the original message, a 0–255-byte
  context, and required, preferred, or deterministic hedging. Required hedging
  needs token randomness.
- **Generation**. Query `Provider::ml_dsa_generation_options` for advisory choices.
  Use `ManagementSession::generate_ml_dsa_key_pair` for a persistent pair.

```no_run
use pkcs11_client::{
    SecretText,
    Authentication, MlDsaHedging, MlDsaParameterSet, MlDsaRequest,
    MlDsaSigningPolicy, Pin, Provider, SigningPolicy,
};
use std::num::NonZeroUsize;

let provider = Provider::load("/absolute/path/to/trusted-pkcs11.so")?;
let client = provider.client(&"pkcs11:serial=123".parse()?,
    NonZeroUsize::new(1).unwrap(), SigningPolicy::default())?;
// Obtain this from the application's secret source.
let pin = SecretText::from("example-only");
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

| Area | Contract |
| --- | --- |
| Example | Use an existing ML-DSA-65 key and matching certificate. IDs and labels can differ. Supply separate context authentication for an always-authenticate key |
| Token verification | `verify_ml_dsa` returns `SignatureMismatch` on mismatch. Requests are validated before checkout and capabilities are checked again during execution |
| Software verification | `MlDsaVerifyingKey` accepts raw public bytes or RFC 9881 SPKI, and checks the message and context without a module. Verification is independent of hedging. Malformed or noncanonical signatures return `SignatureMismatch` |
| Certificate and export | `MlDsaCertificate` retains exact DER with absent algorithm parameters and a correctly sized, byte-aligned public key. Typed public export writes RFC 9881 SPKI DER |
| Binding | `bind_ml_dsa_identity` proves association with a domain-separated probe and required hedging. `sign_ml_dsa_identity` checks every signature against the retained leaf and discards the lease on mismatch. Callers decide certificate trust |

## ML-KEM

| Area | Contract |
| --- | --- |
| Supported profiles | ML-KEM-512/768/1024 generation, capability inspection, public import/export, encapsulation, and decapsulation. Private keys are sensitive and nonextractable |
| SPKI | `MlKemPublicKey::from_spki_der` checks RFC 9935 encoding, absent parameters, byte alignment, length, and canonical FIPS 203 coefficients. `to_spki_der` returns that encoding |
| Import | Use read-write mode and an explicit ID and label. Existing objects are preserved. Duplicate IDs can make selection ambiguous |

```no_run
use pkcs11_client::{ SecretText, Authentication, Error, MlKemParameterSet, MlKemRequest,
    Pin, Pkcs11Uri, Provider, PublicKeyRef, SessionMode};

fn encapsulate(
    provider: &Provider, token: &Pkcs11Uri, key: &PublicKeyRef, pin: &SecretText,
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

- **Operations**. `encapsulate_ml_kem` returns public ciphertext for
  `decapsulate_ml_kem`. Both require read-write mode, the expected parameter set,
  and a new secret ID and label. They create a persistent, sensitive,
  nonextractable 32-byte derivation secret.
- **Decapsulation**. Checks ciphertext length before crypto and requires a key
  without per-operation authentication. Implicit rejection can produce a
  different secret for altered same-length ciphertext without reporting failure.
- **Protocol**. Authenticate the peer, confirm agreement, and apply a protocol KDF.

## HKDF

Use `hkdf_options` to list permitted hash profiles or `hkdf_capabilities` to
check an explicit digest. `hkdf_options` omits unsupported profiles and
propagates selector or provider errors. `derive_hkdf` performs token-side
extract-and-expand on a sensitive, nonextractable generic/HKDF base with CKA_DERIVE.
The base must match the hash length: 20/28/32/48/64 bytes for SHA-1/224/256/384/512.
Use SHA-256 for a 32-byte ML-KEM secret.

```no_run
use pkcs11_client::{ SecretText, Authentication, DigestAlgorithm, Error, HkdfOutput,
    HkdfRequest, ObjectRef, Pin, Pkcs11Uri, Provider, SessionMode};

fn derive_encryption_key(
    provider: &Provider, token: &Pkcs11Uri, base: &ObjectRef, pin: &SecretText,
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
| Salt/context | Public. At most 4096 bytes each. Empty salt means zero salt and empty context is permitted |
| Output | AES-128/192/256 for encryption/decryption, or `DerivationSecret` for further derivation |
| Length | 1 through 255 times the hash length |
| Identity | New nonempty ID/label, at most 128 bytes each. Existing secret IDs rejected |
| Ownership | Persistent private, sensitive, nonextractable output. Bases remain until explicitly deleted |

Peer authentication and context selection belong to the protocol. Single-input
HKDF does not authenticate ciphertexts or combine classical/PQC inputs.

## Application hybrid derivation

| Area | Contract |
| --- | --- |
| API and order | `derive_hybrid_hkdf(classical, post_quantum, request)` concatenates P-256 ECDH then ML-KEM-768 secrets and applies HKDF-SHA512 |
| Inputs | Two distinct 32-byte sensitive, nonextractable generic secrets that permit derivation and concatenation |
| Request | SHA-512, up to 128 bytes of salt, and a nonempty protocol context of at most 4096 bytes. Output permissions follow HKDF |
| Ownership | Destroys the temporary concatenated secret. Inputs remain on the token. Cleanup failure can leave the persistent output |
| Protocol | Establish independent component provenance, authenticate peers, and bind identities, roles, algorithms, and transcript in the protocol context. This is an application primitive. X-Wing, wire protocols, and the TLS key schedule are separate |

See the [runtime contract](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-runtime/README.md#application-hybrid-derivation).

## Additional mechanisms

| Family | Application API |
| --- | --- |
| Capabilities | `Provider::mechanism_capabilities`, `function_availability` |
| Digest/MAC | `digest`, `digest_chunks`, `mac`, `verify_mac`. Management also supports multipart MAC |
| Token verification | `verify`, `verify_signature` and family-specific verification for EdDSA/ML-DSA/SLH-DSA/hash-PQC |
| SP 800-108 | Management `kbkdf_options`, `kbkdf_capabilities`, `derive_kbkdf` |
| SLH-DSA/hash-PQC | Generation, signing, verification and public parameter inspection. HashSLH-DSA uses a separate HashSLH-only pair |
| EdDSA | Pure Ed25519/Ed448 generation, sign/verify, public import/export, `EdDsaVerifyingKey`, `EdDsaCertificate`, `EdDsaIdentity` |
| Montgomery | X25519/X448 generation, validated RFC 8410 public import/export and `derive_montgomery` |

EdDSA supports software verification with Ed25519 and Ed448 certificates.
Token-side EdDSA signing requires a key without per-operation authentication.
See the [mechanism matrix](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/oasis-compatibility.md)
for application coverage and the API rustdoc for request contracts.

## Ownership, authentication and failure handling

| API | Contract |
| --- | --- |
| `Provider::load` | Own one explicitly trusted module. A URI never loads code |
| `Provider::client` / `Client::connect` | Create a read-only pool. `Client::new` accepts an existing pool |
| `Provider::management` | Open one borrowed session with explicit mode and authentication |
| `Provider::management_owned` | Retain the module owner across requests without borrowing the provider or retaining a PIN |
| `Client::close` / session `close` | Report cleanup failures. Drop is best effort |
| `Provider::finalize` | Requires closed consumers. Live owned sessions return `ProviderInUse` |

- The complete token URI is checked against the loaded module, slot, and token.
  Token selectors reject object criteria, credentials, and unsupported constraints.
- `object_reference`, `validate_token_uri`, and `token_uri` validate or convert
  selectors without opening a module.
- A borrowed client must be closed or dropped before finalizing its module.

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

- Share a client per token and authentication role. Pool exhaustion returns
  `Error::Runtime(PoolExhausted)` immediately.
- Login and logout are token-wide. `Authentication::None` leaves login state
  unchanged. An already logged-in role may proceed without a fresh PIN check.
  Drop does not log out explicitly. Closing the last session may reset
  authentication. SO requires read-write mode.
- `Pin::Value` borrows a `SecretText`. `Pin::ProtectedPath` requires token support.
  Always-authenticate keys need separate context credentials for each supported
  operation, including a certificate-binding probe.
- Execution resolves selectors again and checks capabilities. Advisory plans
  are subject to provider acceptance. Failed calls are issued once, and
  uncertain sessions follow runtime invalidation rules.
- Failed mutations can leave persistent objects or partial updates. Duplicate-ID
  checks can race with other writers.
- To check cleanup, capture the operation result, close the client or session,
  finalize the provider, then release the output. Cleanup errors take precedence.
  Failed management authentication also attempts checked closure.
- Use `Error::kind` for programmatic error handling and diagnostic strings for display.

## Random bytes and examples

`generate_random(RandomRequest)` requests 1–1048576 bytes from the token once.
Invalid lengths fail before allocation. Authentication is explicit and subject to
token policy. `RandomBytes` zeroizes on drop and redacts its debug output.
Borrow the bytes with `expose_secret()` and check session closure before releasing them.

[Runnable examples](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/examples.md) cover generic signing, certificate
binding and shutdown with PIN files.

## Tests

```sh
cargo test -p pkcs11-client --locked
cargo doc -p pkcs11-client --no-deps --locked
```

| Suite | Coverage |
| --- | --- |
| Unit and doctests | Certificate and key parsing, signature verification, signing policy, redaction, and compile-fail checks for ownership |
| SoftHSM and Kryoptic | Signing and binding, token administration, key generation, AES-GCM, ML-DSA, ML-KEM, and persistent HKDF |

See the [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md) for disposable provider suites.
