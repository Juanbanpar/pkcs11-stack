# pkcs11-runtime

Synchronous PKCS#11 module and session management over cryptoki. Discover tokens
and objects, authenticate, pool sessions, generate signing keys, administer PINs
and sign with RSA PKCS#1 v1.5, RSA-PSS or ECDSA.

```no_run
use pkcs11_locator::Pkcs11Uri;
use pkcs11_runtime::{Module, ObjectRef, SessionMode, Authentication, Pin, AttributeType};
use secrecy::SecretString;

let module = Module::load("/absolute/path/to/trusted-pkcs11.so")?;
let locator: Pkcs11Uri = "pkcs11:token=production;serial=123".parse()?;
let token = module.resolve_token(locator.token_selector())?;
let mut session = token.open_session(SessionMode::ReadOnly)?;
// Example only: the application obtains the PIN from its chosen secret source.
let pin = SecretString::from("example-only");
session.authenticate(Authentication::User(Pin::Value(&pin)))?;
let key = ObjectRef::new("pkcs11:serial=123;object=server-key;type=private".parse()?)?;
{
    let object = session.resolve(&key)?;
    let metadata = object.read_attributes(&[AttributeType::Label, AttributeType::Class])?;
    // The wrapper's Debug contains attribute types, not potentially secret values.
    println!("{metadata:?}");
}
session.close()?;
module.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Ownership and shutdown

`Module::load` canonicalizes an explicitly supplied, trusted library path and uses
cryptoki's safe loading API. Successful OS-locking initialization establishes
ownership. Already-initialized errors are returned without adoption or finalization;
share the existing Module instead of loading a second owner. There is no process
global registry. A failed metadata query after successful initialization attempts
cleanup; a failed cleanup preserves both errors.

Sessions opened from borrowed tokens borrow their module. An explicit Session
Drop keeps that borrow active through destruction, so the module cannot finalize
while such a session is alive, even if it is not used again:

```compile_fail,E0505
use pkcs11_runtime::{Module, SessionMode};
fn invalid_shutdown(module: Module) {
    let slot = module.slots(true).unwrap()[0];
    let token = module.token(slot).unwrap();
    let _session = token.open_session(SessionMode::ReadOnly).unwrap();
    module.finalize().unwrap(); // session destruction still needs the module
}
```

`SessionPool::new_owned(Arc<Module>, &token_uri, mode, maximum)` supports consumers
that need static ownership, including TLS signers. It checks full token URI
constraints and shares the existing initialization owner. Each idle/leased session
retains that owner until its raw session closes. It uses the same bounded pool,
authentication and recovery as borrowed pools. To finalize explicitly, stop all
operations, drop consumers and pools, then unwrap the application's final module
Arc and call `finalize`. Dropping the final Arc instead performs best-effort cleanup.

Object handles remain inside objects borrowing their original session. Closing a
session while subsequently using its object is likewise rejected:

```compile_fail,E0505
use pkcs11_runtime::{Session, AttributeType};
fn invalid_object_use(mut session: Session<'_>) {
    let objects = session.find_objects(&[]).unwrap();
    session.close().unwrap();
    objects[0].read_attributes(&[AttributeType::Label]).unwrap();
}
```

Session close and module finalize report typed errors. Drop attempts cleanup but
cannot report errors to callers; cryptoki itself can log/retry a failed session
close during its Drop. The runtime does not retry authentication or object
operations. All callers sharing a vendor library must respect one lifecycle
owner; independent raw contexts, external finalizers and nonconforming vendor
initialization behavior are outside this ownership guarantee.

## Discovery and identity

Slots and token flags use cryptoki's representations directly. Tokens expose
locator-compatible stable metadata separately from their diagnostic slot ID.
`resolve_token(TokenSelector)` intentionally resolves token-only criteria within
this explicitly loaded module, distinguishing no match, one match and ambiguity.
`resolve_token_uri(&Pkcs11Uri)` also checks module and slot constraints, rejects
object/PIN/unsupported criteria, and accepts `module-path` only as an exact match
against the loaded canonical path. Slot IDs are allowed for current discovery,
not persistent object identity. Discovery includes uninitialized tokens where reported. Disappearance during
enumeration is skipped only for CKR_TOKEN_NOT_PRESENT; other errors are retained.

Token metadata is rechecked before operations and before/after session opening.
This detects changed label/manufacturer/model/serial metadata, not a
cryptographic identity substitution with identical metadata. Physical removal,
slot races or token-wide logout can still invalidate a session/handle; errors are
propagated without a hidden recovery attempt.

`ObjectRef` owns locator data, not an ObjectHandle. It requires token and object
constraints, rejects PIN queries, unknown path constraints and slot IDs, and
supports module-path only among query attributes. Logical module-name resolution
is not implemented. Module-path must match the canonical loaded path exactly.
Every resolve searches anew in the selected session, requires CKA_TOKEN=true,
checks module/slot/token/object metadata and rejects ambiguous matches. It does
not establish uniqueness across other tokens; token resolution is explicit.

`find_objects` supports arbitrary cryptoki templates and returns session-bound
objects, including session objects. It never produces persistent references from
session-object handles. Unavailable attributes may be omitted by cryptoki's
`read_attributes`; use `attribute_info` for per-attribute Sensitive/TypeInvalid/
Unavailable status. `AttributeValues` Debug redacts values. Explicit
`expose_values` grants access to raw cryptoki attributes, which may include
extractable secrets and are not themselves zeroizing containers. Callers must
protect such data and must not log it. Templates and values are never logged by
the runtime. Errors retain operation and upstream return-value context without
formatting upstream input buffers in Debug.

## Authentication and concurrency

Authentication explicitly supports no state change, USER login, SO login and
protected authentication paths. PINs are borrowed SecretStrings for the duration
of the call, never cached. SO requires RW access; cross-session SO/RO conflicts
remain typed PKCS#11 errors. Already-logged-in state is not silently accepted as
ownership of a previous login. `None` is not an implicit logout.

USER/SO login and logout affect other sessions on the same token. Drop does not
issue logout, although closing the last session can reset authentication.
Context-specific login is performed inside signing for always-authenticate keys
using combined multipart RSA or ECDSA hashing mechanisms. Raw/prehashed requests
for such keys are rejected because cryptoki 0.12.1 cannot interleave login in
single-part sign. A provider must actually implement the multipart mechanism;
SoftHSM 2.7 advertises combined ECDSA but rejects its multipart operations.
No authentication is silently omitted.

Module can be shared across scoped threads; each session is used exclusively.
The pool shares only accounting; leases own separate sessions. Objects cannot
migrate between sessions. No executor or worker thread is created.

## Pooling and signing

```no_run
use std::num::NonZeroUsize;
use pkcs11_locator::Pkcs11Uri;
use pkcs11_runtime::*;
use secrecy::SecretString;

let module = Module::load("/absolute/path/to/trusted-pkcs11.so")?;
let uri: Pkcs11Uri = "pkcs11:serial=123;object=signer;type=private".parse()?;
let token = module.resolve_token(uri.token_selector())?;
let key = PrivateKeyRef::new(uri)?;
let pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(4).unwrap());
let pin = SecretString::from("example-only");
let mut lease = pool.try_acquire(Authentication::User(Pin::Value(&pin)))?;
let request = SignRequest {
    algorithm: SignatureAlgorithm::RsaPss,
    digest: DigestAlgorithm::Sha256,
    input: SignInput::Message(b"message to sign"),
    pss: Some(PssParameters { mgf_digest: DigestAlgorithm::Sha256, salt_len: 32 }),
};
let policy = SigningPolicy::default(); // messages must be hashed on the token
let capabilities = lease.session().key_capabilities(&key)?;
let plan = capabilities.plan(&request, &policy)?;
assert_eq!(plan.hash_location(), HashLocation::Token);
let signature = lease.session().sign(&key, &request, &policy, None)?;
drop(lease); // healthy session becomes available to another caller
// `discard()` before drop instead closes a suspect session.
pool.close()?; // checks idle and discarded session closure before finalization
module.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`try_acquire` immediately returns PoolExhausted at capacity. It checks health,
replaces stale idle sessions once, and ensures the requested login role. A matching
existing role does not validate the supplied PIN again. Failed login/open returns
capacity. Drop returns healthy sessions and closes explicitly discarded, failed or
panicking leases. Returned sessions are checked against the pool's module/token/mode.
Pool poisoning is a typed error.

For checked pool shutdown, release all leases and call `SessionPool::close` before
module finalization. It attempts every idle session close and reports failures,
including a failure recorded when a stale or failed lease was discarded. A failed
close blocks further checkouts with `PoolCleanupFailed`; it does not trigger an
operation retry or token-wide logout. Dropping a pool remains best effort.

A failed signing/search operation, failed metadata read or failed identity check
invalidates the session for further operations, including discovery and login.
Such calls return `Error::Closed`; explicit close still attempts cleanup. Ordinary
login failures (such as an incorrect PIN) remain reportable without invalidating
a standalone session; the runtime never retries the PIN.

No handle or plan is cached for execution. A signing failure never triggers a
retry; the caller decides whether a new operation is appropriate. Changed token
identity and module failures propagate. Recovery does not automatically search a
new slot, reload a module or accept a replacement token with different metadata.
Coordinate logout with all sessions because authentication remains token-wide.

Objects cannot survive return of their lease, and pools keep the module alive:

```compile_fail,E0505
use pkcs11_runtime::{SessionLease, AttributeType};
fn return_with_object(mut lease: SessionLease<'_, '_>) {
    let objects = lease.session().find_objects(&[]).unwrap();
    drop(lease);
    objects[0].read_attributes(&[AttributeType::Label]).unwrap();
}
```

```compile_fail,E0505
use pkcs11_runtime::{Module, SessionMode, SessionPool};
use std::num::NonZeroUsize;
fn finalize_with_pool(module: Module) {
    let token = module.token(module.slots(true).unwrap()[0]).unwrap();
    let _pool = SessionPool::new(token, SessionMode::ReadOnly, NonZeroUsize::new(1).unwrap());
    module.finalize().unwrap();
}
```

Signing policy intersects token mechanism flags/bounds with key type/size/curve,
CKA_SIGN, CKA_ALLOWED_MECHANISMS and request parameters. Required unknown metadata
fails closed. The module remains authoritative for parameter combinations not
expressed by mechanism information. Pure snapshots support planning by clients and
adapters; `sign` rechecks the live key and plans again before executing.

`TokenOnly` is the default message policy. `AllowSoftware` permits software SHA-2
when a combined mechanism is unavailable; `SoftwareOnly` explicitly selects it.
`SignInput::Digest` accepts only the exact selected digest length and never hashes
again. These caller-provided digests already crossed a software hashing boundary.
PSS always requires explicit salt and MGF1 parameters. RSA raw PKCS#1 v1.5 includes
DigestInfo; ECDSA returns fixed-width `r || s` for P-256/P-384/P-521, without DER
conversion. SHA-256/384/512 are supported. Signing input Debug redacts bytes; PINs
stay borrowed SecretStrings. Message/digest buffers are not zeroizing storage.

`PrivateKeyRef`, `PublicKeyRef` and `CertificateRef` require explicit URI classes.
Public metadata exposes only RSA public components, EC parameters/point and optional
token SPKI; it never requests private exponents/scalars. A CertificateRef reads DER
from an independently selected object. There is no implicit association, certificate
trust validation, certificate SPKI extraction or missing-SPKI construction. Consumers
must validate associations; matching IDs/labels alone do not establish them.

## RSA-OAEP encryption

`Session::rsa_oaep_capabilities` checks a unique public/private key's permissions,
allowed mechanisms and provider bounds. `encrypt_rsa_oaep` and `decrypt_rsa_oaep`
resolve again and perform one RSA-OAEP operation with matching SHA-2/MGF1 digest
and an empty label. RSA sizes are limited to 2048–16384 bits; plaintext must fit
the OAEP bound and ciphertext must be modulus-width. An error or panic during a
provider operation prevents session reuse.

Per-operation-authentication decryption keys are rejected before init. Successful
plaintext is redacted and zeroizing, but cryptoki's transient buffers from failed
provider calls cannot currently be guaranteed zeroized.

## AES-GCM encryption

`Session::encrypt_aes_gcm` and `decrypt_aes_gcm` use CKM_AES_GCM with a supplied
12-byte nonce and full 16-byte tag. Output/input is ciphertext followed by the tag;
the nonce and AAD are separate. This fixed profile follows
[PKCS#11 AES-GCM](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.pdf)
and [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
`AesGcmEncryptRequest` and `AesGcmDecryptRequest` borrow their inputs and redact
all buffers in Debug. Plaintext is bounded to 16 MiB and AAD to 1 MiB; empty
plaintext/AAD are permitted. Ciphertext includes exactly 16 tag bytes.

The caller must ensure nonce uniqueness per key across writers and restarts,
including equivalent copies of a key. No nonce is generated, persisted or tracked.
An error does not authorize reusing a nonce. There is no retry, multipart plaintext
release, software fallback or envelope format. Applications store and authenticate
their protocol context and manage key lifetimes.

`aes_gcm_capabilities` checks secret/AES class and type, 16/24/32-byte length,
direction permission, allowed mechanisms, provider flags/bounds and native init
and single-part entry points. Execution rechecks these constraints. Both RO and RW
sessions are supported. Generated encryption keys and HKDF AES outputs qualify;
wrapping-only keys and raw generic secrets do not. No key values are read.

Decryption returns redacted, zeroizing plaintext only after provider success and
exact-length checks. Tag, AAD, nonce or ciphertext corruption returns no plaintext.
Provider errors/unwinds or malformed outputs invalidate the session; request
validation and policy rejection precede crypto. cryptoki's transient buffers from
failed calls cannot be guaranteed zeroized. Check explicit session closure before
releasing output. Testing does not establish formal algorithm validation.

## ECDH and AES key generation

`Token::ecdh_generation_options` reports P-256/P-384/P-521 generation choices;
`Token::aes_generation_options` reports AES-128/192/256 sizes. Both check native
entry points, advertised generation flags and bounds. EC bounds are in bits;
AES bounds and CKA_VALUE_LEN are in bytes. Choices do not guarantee template
acceptance or later operation support.

RW sessions accept `EcdhKeyPairRequest` through `generate_ecdh_key_pair` and
`AesKeyRequest` through `generate_aes_key`. The EC public key is public; its
private key is sensitive, nonextractable and derivation-only, with per-operation
authentication disabled. AES keys are private, sensitive and nonextractable.
`AesKeyPurpose::Encryption` permits encryption/decryption only; `Wrapping`
permits wrapping/unwrapping only. No key values are read or returned.

Both requests require nonempty ID/label fields of at most 128 bytes. Generation
rechecks capabilities and rejects existing persistent public/private IDs for EC
pairs or secret IDs for AES, without a uniqueness guarantee against concurrent
writers. Provider failures invalidate the session and can leave persistent effects;
there is no retry or rollback. Check session closure. The signing-generation API
continues to create signing-only keys.

## Derivation and key transfer

`Session::key_operation_profile` validates current key class, usage permissions,
allowed mechanisms and provider bounds. `derive_ecdh_secret` uses raw ECDH with
an explicit null KDF on P-256/P-384/P-521. Callers must validate the peer point
on the same curve before supplying `EcdhDerivation`; `pkcs11-client` provides
SPKI parsing and validation. The result is a private, sensitive, nonextractable
token generic secret with derivation permission only. A later KDF and peer
authentication remain the application's responsibility. Context authentication
for ECDH is unsupported.

`wrap_aes_key` and `unwrap_aes_key` use RFC 3394 with the default IV and
AES-128/192/256 keys. Wrapping requires CKA_WRAP, an extractable AES target and
compatible CKA_WRAP_WITH_TRUSTED policy. No key values are read. Unwrapping
creates a private, sensitive, nonextractable AES token key with only encryption/
decryption permission. Derived/unwrapped identities have bounded nonempty labels
and IDs; an existing secret-key ID is rejected, without a cross-process lock.

Derivation and unwrapping require RW mode. Failed native operations invalidate
the session; no retry or rollback is attempted. Provider templates and
permissions may narrow these profiles. Blobs carry ciphertext only, not metadata.

## Random bytes

`Session::generate_random` fills a nonempty caller-owned buffer using the token's
advertised RNG. It validates token identity and current capability before calling
the provider once. No software fallback, authentication or retry is added.
Discard the buffer after an error; a failed provider call invalidates the session.

## Administration

`Module::initialize_token(&mut self, slot, so_pin, label)` initializes or erases
an explicit diagnostic slot. It can destroy existing token contents. Exclusive
module access prevents initialization while a borrowed token/session is live:

```compile_fail,E0502
use pkcs11_runtime::{Module, SessionMode};
use secrecy::SecretString;
fn invalid_initialization(mut module: Module) {
    let slot = module.slots(true).unwrap()[0];
    let token = module.token(slot).unwrap();
    let session = token.open_session(SessionMode::ReadOnly).unwrap();
    module.initialize_token(slot, &SecretString::from("example"), "new").unwrap();
    drop(session);
}
```

RW sessions expose `initialize_pin`, `change_pin`, `create_object` with an explicit
template, and `generate_signing_key_pair` for persistent RSA/named EC signing keys.
Generated private keys are sensitive and nonextractable. IDs/labels are explicit;
uniqueness is not assumed. Returned objects remain bound to their original session.
Objects expose `update_attributes` and consuming `destroy`. SO/USER authorization
is enforced by the provider. PIN mutation requires host PINs with the current
upstream API. Credentials are borrowed for each call.

Mutations validate session/token health and RW mode before execution. A provider
failure or unwind leaves the session unusable; there is no retry or rollback.
Template updates may partially succeed before returning an error. Only a new
session can be used after such a failure. Caller templates may contain secrets and
are never logged. `validate_token_uri` provides the same pure constraint validation
used by module resolution, so callers can reject unsupported input before loading.

## ML-DSA

Pure ML-DSA uses `MlDsaRequest` with an expected parameter set, the original message,
a context of at most 255 bytes, and an explicit hedging choice. It has no external
digest or prehash field. `MlDsaSigningPolicy` restricts allowed parameter sets
independently of the RSA/EC `SigningPolicy`; its default permits ML-DSA-44/65/87.

`Token::ml_dsa_generation_options` reports advertised choices. RW sessions provide
`generate_ml_dsa_key_pair` with explicit ID/label and optional always-authenticate.
Generated private keys are sensitive and nonextractable. `ml_dsa_capabilities`
intersects key permissions, allowed mechanisms and token flags/bounds; ML-DSA
mechanism bounds are public-key bytes, not bits.

`sign_ml_dsa` rediscovers the key, checks its parameter set and policy, then signs
once with CKM_ML_DSA. Always-authenticate keys use signing initialization, context
login and multipart signing. Other keys use single-part signing. Returned signature
length must match the selected parameter set. No private value or seed is read.
`ml_dsa_public_key` reads only an explicitly public, non-private public-key object
and checks its encoding length.

`verify_ml_dsa` verifies on the token. A malformed or nonmatching signature returns
`Error::SignatureMismatch`; a completed C_Verify mismatch leaves the session usable.
Other backend failures invalidate it. Verification does not bind a private key to
a public key or establish certificate trust. Software verification and certificate
binding belong to `pkcs11-client`. HashML-DSA and external-mu signing are not implemented.

## Testing

```sh
cargo test -p pkcs11-runtime --locked
./tools/test-softhsm.sh
```

Unit tests cover selection, redaction and signing plans; compile-fail examples
check module, session and object lifetimes. The SoftHSM runner provisions disposable
tokens for discovery, authentication, signing and mutation tests. See the
[test guide](../../tests/README.md) for provider configuration.

## ML-KEM

`MlKemParameterSet` selects ML-KEM-512/768/1024. `Token::ml_kem_generation_options`
checks advertised generation flags and public-key byte bounds.
`Session::generate_ml_kem_key_pair` creates a persistent public encapsulation key
and a sensitive, nonextractable private decapsulation key with explicit ID/label.
Duplicate key-pair IDs remain possible; selection must resolve exactly one object.

`MlKemPublicKey::from_bytes` validates the parameter-set length and the FIPS 203
modulus check. `Session::ml_kem_public_key` exports only public, non-private
objects and applies the same validation to provider output.
`Session::import_ml_kem_public_key` creates a persistent public encapsulation key
in an RW session. Its explicit ID/label follows the generation contract; existing
objects are not overwritten. These checks do not authenticate the key's owner.

`Session::ml_kem_capabilities` checks the selected class, parameter set, direction,
key permission, allowed mechanisms, token flags/bounds and the PKCS#11 entry point.
Always-authenticate decapsulation is unsupported by this single-call profile.
The typed methods do not weaken these checks for vendor metadata errors.

`encapsulate_ml_kem` returns only public ciphertext; `decapsulate_ml_kem` accepts
that ciphertext and returns no key bytes. Both take `MlKemRequest`, with an
expected parameter set and a new secret ID/label, and require an RW session.
Secret identity fields are nonempty and at most 128 bytes; an existing secret ID
is rejected before crypto. The result is a persistent private 32-byte generic
secret with sensitive/nonextractable attributes and only derivation enabled.
No private seed or shared-secret value is read or exported.

Raw shared secrets require a protocol KDF and peer authentication before use.
ML-KEM implicit rejection can produce a different secret for altered same-length
ciphertext without reporting an error. Success alone does not authenticate a peer.
These KEM calls do not apply a KDF; use `derive_hkdf` separately. There is no
retry, rollback or software fallback. Provider failures
invalidate the session, and even an error can leave persistent effects.

## HKDF

`HkdfRequest` selects SHA-256/384/512, public salt/context, output type and a new
secret ID/label. `Session::derive_hkdf` always runs extract-and-expand through
CKM_HKDF_DERIVE in an RW session. An empty salt uses RFC 5869's zero salt; empty
context is permitted. Salt and context are each bounded to 4096 bytes, and output
is limited to 255 times the hash length.

`Session::hkdf_capabilities` checks secret class, generic/HKDF key type,
CKA_DERIVE, allowed mechanisms, sensitivity, nonextractability and the provider's
HKDF derive support. Under PKCS#11 section 6.62.3 the base key must match the hash
length: 32, 48 or 64 bytes. ML-KEM's 32-byte shared secret therefore uses SHA-256.
Advertised support is advisory; provider parameter/template rejection is returned
without retry or software fallback.

Outputs are persistent private, sensitive, nonextractable keys. `HkdfOutput`
selects AES-128/192/256 with encryption/decryption permissions, or a generic
secret permitting only further derivation. Signing, verification, wrapping and
unwrapping are disabled. Existing secret IDs are checked before derivation;
the check is not a transaction against concurrent writers. No key values are
read. Base keys remain on the token until explicitly deleted. Failures can leave
persistent effects, and session closure must be checked when cleanup matters.

Applications authenticate the peer and define salt/context within their protocol.
HKDF does not authenticate ML-KEM ciphertexts or combine classical/PQC secrets.

## Application hybrid derivation

`Session::derive_hybrid_hkdf` combines a P-256 ECDH secret followed by an
ML-KEM-768 secret, then applies HKDF-SHA512 on the same token. This uses the
classical || auxiliary construction described by
[NIST SP 800-56C Rev. 2](https://doi.org/10.6028/NIST.SP.800-56Cr2).
It defines neither a wire protocol nor the X-Wing or TLS key schedule.

Both selectors must resolve to distinct 32-byte generic secrets with derivation
permission, sensitive/nonextractable attributes and permission for
CKM_CONCATENATE_BASE_AND_KEY. Metadata cannot prove their origin: the caller must
establish component provenance, independent generation and authenticated peers.
Use ECDH and ML-KEM outputs from the same protocol exchange, with agreed ordering.

Pass `HkdfRequest` with SHA-512, public salt of at most 128 bytes and nonempty
context of at most 4096 bytes. The protocol must bind identities, algorithm choices,
roles and the exchange transcript as appropriate. Output profiles, duplicate-ID
checks and persistent effects follow `derive_hkdf`.

The concatenated 64-byte input is a private, sensitive, nonextractable session
object destroyed before return. Cleanup failure invalidates the session and takes
precedence over derivation success/failure; a persistent output may already exist.
No base is deleted, no value is read, and there is no retry or software fallback.
This implementation does not establish formal algorithm validation.
