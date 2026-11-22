# pkcs11-client

A high-level Rust API for PKCS#11. Use it to discover tokens, select keys
and certificates, sign, and manage token objects. It resolves URI selectors
and pools signing sessions without exposing Cryptoki handles. Applications
supply authentication and control object lifetime and cleanup.

Use [pkcs11-runtime](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/crates/pkcs11-runtime/README.md)
directly for session and mechanism control.

## Installation

Requires Rust 1.88 or newer.

```toml
[dependencies]
pkcs11-client = "0.1.0"
```

## Sign with an existing key

From the checkout, run the [sign example](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/crates/pkcs11-client/examples/sign.rs)
with a trusted module, a key that supports RSA PKCS#1 v1.5 with token SHA-256
hashing, a USER PIN file, and a message. Use a fresh output path.

```sh
cargo run --locked --quiet -p pkcs11-client --example sign -- \
  /path/to/trusted-pkcs11.so 'pkcs11:serial=123;id=%01;type=private' \
  /secure/user.pin message.bin > signature.bin
```

The example opens a signing client with `Provider::client` and signs through
`Client::sign`. The [SoftHSM quickstart](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/docs/quickstart.md#sign-from-rust-with-the-same-key)
shows how to create a disposable key and verify the signature.

## Signing with a certificate

Bind an RSA signing key to a matching certificate when every signature must
verify against its public key. The application validates certificate trust
separately.

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

### Signing policy and binding

- The default policy uses token hashing, SHA-256/384/512, and RSA keys of at
  least 2048 bits. SHA-1 and SHA-224 require explicit opt-in. Software certificate
  verification also requires its own SHA-1 opt-in. Use `signing_options` or
  `plan` to inspect the mechanism and hashing location before signing.
- `SignInput::Digest` takes an exact-length digest without rehashing it. RSA
  returns a raw modulus-width signature. ECDSA returns fixed-width `r || s`.
  Bound PSS requires matching message and MGF1 digests. Generic signing can
  use separate MGF1 parameters.
- `CertificateDocument` parses exact DER for import and inspection.
  `Certificate` verifies supported RSA and named-curve EC signatures in
  software. `bind_identity` signs one probe to prove association.
  `sign_identity` checks each signature against the retained certificate and
  discards the lease on mismatch, including after a key replacement.

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

Use `objects` and `inspect` for metadata and `export_public` for public
certificate, data, or supported SPKI output. Public export rejects private
and secret keys. `export_value` reads raw values only from certificates
and data objects.

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

AES-GCM decryption returns zeroizing, redacted `Plaintext` after provider
success. Authentication failure invalidates the session. A preflight rejection
leaves it usable. Failed cryptoki calls can leave temporary buffers unwiped.

For RSA-OAEP, authenticate the sender separately. Per-operation-authenticated
keys fail before initialization because the binding cannot interleave context
login and single-part decryption.

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

Use an existing ML-DSA-65 key and matching certificate. Their IDs and labels
can differ. Supply a separate context credential for an always-authenticate
key. `bind_ml_dsa_identity` uses a hedged probe and `sign_ml_dsa_identity`
checks every signature against the retained leaf.

Use `verify_ml_dsa` for token verification or `MlDsaVerifyingKey` for
software verification from raw public bytes or RFC 9881 SPKI. Supply the
same message and context on both sides.

## ML-KEM

Use ML-KEM-512, -768, or -1024 for token-held key establishment. Public keys
use RFC 9935 SPKI. Import requires a read-write session, ID, and label. Choose
an unambiguous ID when importing alongside existing keys.

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

See the [runtime contract](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/crates/pkcs11-runtime/README.md#application-hybrid-derivation).

## Additional mechanisms

Use `Provider::mechanism_capabilities` to inspect advertised and typed
support. The [mechanism matrix](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/docs/oasis-compatibility.md)
covers digest and MAC operations, SP 800-108, EdDSA, X25519/X448 agreement,
and the post-quantum profiles.

HashSLH-DSA uses a separate HashSLH-only key pair. Software verification
supports Ed25519 and Ed448 certificates. Token-side EdDSA signing requires a
key without per-operation authentication.

## Ownership, authentication and failure handling

A provider owns the module opened through `Provider::load`. A URI selects a
token or object in that module. `Provider::client` creates a read-only pool.
Use `management` for a scoped session or `management_owned` when the session
must retain the module across requests. Close all consumers before
`Provider::finalize`. A live owned session yields `ProviderInUse`.

Token URIs enforce module, slot, and token constraints and reject object
criteria and credential queries. Use `object_reference`, `validate_token_uri`,
or `token_uri` to work with selectors without opening a module.

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

[Runnable examples](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/docs/examples.md) cover generic signing, certificate
binding and shutdown with PIN files.

## Tests

```sh
cargo test -p pkcs11-client --locked
cargo doc -p pkcs11-client --no-deps --locked
```

See the [API reference](https://docs.rs/pkcs11-client/0.1.0).
From a checkout, generate it with the command above.

See the [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/v0.1.0/tests/README.md) for disposable provider suites.
