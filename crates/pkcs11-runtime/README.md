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

## Interface compatibility

`Module::load` requests the standard `PKCS 11` interface in order: 3.2, 3.1,
3.0, then the legacy 2.40 function list. The default vendor interface is never
interpreted as a standard table. Null pointers, mismatched versions and missing
lifecycle functions are rejected before initialization. Unsupported versions do
not cause reads beyond a known function-table layout.

`Module::load_with_options` accepts `ModuleOptions` with
`InterfaceSelection::Exact(InterfaceVersion::V2_40)` (or a supported 3.x version).
An exact selection never downgrades. `Module::interface` reports the selected
table independently of `C_GetInfo`, together with its `reported_version` field.
A known 3.x version reported through `C_GetFunctionList` is tolerated, but only
the legacy prefix is read and no newer functions are exposed through it. An exact
2.40 selection requests that legacy layout. `supports_function` reports pointer presence,
not proof that a provider implements an operation. A provider may return
`CKR_FUNCTION_NOT_SUPPORTED` from a non-null stub. Pre-OASIS versions are outside
the supported interface range.

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
Mechanism discovery and allowed-mechanism attributes preserve all numeric IDs,
including unknown and vendor-defined values. Object class, key type, certificate
type, profile ID and validation type/authority attributes also retain unknown
numeric values. Mixed object discovery keeps unfamiliar objects alongside known
ones; malformed scalar lengths and provider errors still fail the read.
Representability does not enable typed execution of an unsupported algorithm. The
workspace uses a locally patched [cryptoki 0.12.1](../../vendor/cryptoki/PATCHES.md) for this behavior.
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

`Object::read_attributes_bounded` applies a caller-supplied byte limit to each
attribute before allocation. Returned pointers and types must remain unchanged,
and lengths must fit the allocated buffers;
length growth is not retried. Malformed scalars, oversized values and provider
failures invalidate the session. Validation versions require exactly two bytes.
`resolve_bounded` also limits identity attribute reads before matching an object;
ordinary `resolve` retains its existing allocation behavior.

`Object::template_metadata(TemplateAttribute::Wrap)` reads the structure of a
wrap, unwrap or derive template. It returns member IDs, byte lengths and nested
templates without requesting leaf values. Reads allow at most four template
levels, 128 total entries and 65,536 bytes of native array storage. Changed types,
lengths or pointers, malformed array sizes and exceeded limits invalidate the
session. Unknown IDs and non-template arrays remain opaque. Sensitive and invalid
roots retain their status; unavailable members cannot be assigned either cause
because the native return code covers the whole request. These metadata reports
cannot be passed as operation templates; providers enforce those constraints.

`Session::session_validation_flags` queries `CKS_LAST_VALIDATION_OK` through the
selected 3.2 table. It returns the provider's full numeric flags, including unknown
bits. `None` means an older table, missing pointer or unsupported native query;
`Some(0)` is an available zero. Other native errors invalidate the session. Query
immediately after the operation of interest in the same session. Flags from a
fresh session do not describe another session's operations. They do not establish
independent validation, certification or trust. See specification sections
[4.15.3 and 5.6.11](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.pdf).

## Authentication and concurrency

Authentication explicitly supports no state change, USER login, SO login and
protected authentication paths. PINs are borrowed SecretStrings for the duration
of the call, never cached. SO requires RW access; cross-session SO/RO conflicts
remain typed PKCS#11 errors. Already-logged-in state is not silently accepted as
ownership of a previous login. `None` is not an implicit logout.

USER/SO login and logout affect other sessions on the same token. Drop does not
issue logout, although closing the last session can reset authentication.
Context-specific login is performed inside signing for always-authenticate keys
between operation initialization and single-part signing. Combined, software-hashed
and caller-prehashed RSA/ECDSA requests all preserve this ordering; multipart
support is not required. Missing context credentials are rejected before signing.
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

`TokenOnly` is the default message policy. `AllowSoftware` permits software SHA-2/SHA-3
when a combined mechanism is unavailable; `SoftwareOnly` explicitly selects it.
`SignInput::Digest` accepts only the exact selected digest length and never hashes
again. These caller-provided digests already crossed a software hashing boundary.
PSS always requires explicit salt and MGF1 parameters. RSA raw PKCS#1 v1.5 includes
DigestInfo; ECDSA returns fixed-width `r || s` for P-256/P-384/P-521, without DER
conversion. SHA-256/384/512 are enabled by default. Add `DigestAlgorithm::Sha224`
or `Sha3_224`/`Sha3_256`/`Sha3_384`/`Sha3_512` to `SigningPolicy::digests`
to permit those signature and MGF1 digests explicitly. SHA-224/SHA3-224 prehashes
contain 28 bytes; the other SHA-3 prehashes contain 32/48/64 bytes. OAEP and KDF
profiles remain SHA-256/384/512. Signing input Debug redacts bytes; PINs stay
borrowed SecretStrings. Message/digest buffers are not zeroizing storage.

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

`encrypt_rsa_oaep_with_parameters` and `decrypt_rsa_oaep_with_parameters`
accept `RsaOaepParameters` with independently selected SHA-256/384/512 hashes
for OAEP and MGF1, and a binary label bounded to 4096 bytes. Empty labels use
the standard null-pointer/zero-length representation. The plaintext bound
depends only on the OAEP hash. The parameters must be conveyed separately from
the ciphertext and matched for decryption. Provider rejection never changes
the selected parameters. See [OASIS OAEP parameters](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc234407225).

`decrypt_rsa_oaep_with_context` supports always-authenticate private keys with a
separate context credential. The sequence is decrypt initialization, context login,
then single-part completion. Ordinary `decrypt_rsa_oaep` requires no context
credential and rejects keys that need one before initialization. Both paths use
bounded zeroizing plaintext storage, including on native failure.

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
validation and policy rejection precede crypto. Native decryption buffers are
bounded and zeroize on failure or drop. Check explicit session closure before
releasing output. Testing does not establish formal algorithm validation.

## RSA encryption key generation

`RsaEncryptionKeyPairRequest` and `generate_rsa_encryption_key_pair` create
persistent RSA pairs for encryption/decryption only, with exponent 65537 and
2048..=16384 bits in multiples of eight. Public keys are public; private keys are
private, sensitive and nonextractable. Signing, recovery, wrapping and derivation
permissions are disabled. Context authentication may be required for decryption.

Both objects share nonempty ID/label fields bounded to 128 bytes. Existing
public/private IDs, read-only sessions and unsupported generation bounds are
rejected before generation. Checks are not transactional with concurrent writers;
failures may leave objects and are never retried. Advertised generation choices
do not establish support for any OAEP digest profile.

## HMAC

`Session::hmac_capabilities(key, MacOperation::Generate|Verify)` reports permitted
full-tag HMAC profiles based on SHA-224/256/384/512, SHA-512/224, SHA-512/256
and SHA3-224/256/384/512. Keys must be sensitive, nonextractable
secret objects with generation or verification permission, and either
CKK_GENERIC_SECRET or the matching hash-specific HMAC key type. This application
accepts 16–4096-byte keys. Allowed mechanisms, native entry points and operation
flags are checked; missing metadata and provider errors propagate.

`mac_hmac(key, algorithm, message)` creates a full 28/32/48/64-byte tag in bounded
storage. `verify_hmac(key, algorithm, message, tag)` verifies natively without
creating a comparison tag. Messages may be empty and are bounded to 16 MiB.
Both work in RO sessions. Incorrect tag length or a completed verification
mismatch returns `Error::MacMismatch` and leaves the session reusable. Other
native failures, unwinds and malformed output invalidate it. Check session closure.
No software truncation, fallback or algorithm substitution occurs.

`hmac_general_capabilities` inspects general-tag algorithms; `hmac_options`
inspects full and general mechanisms independently. `mac_hmac_with_profile` and
`verify_hmac_with_profile` accept `HmacTagProfile::Full` or
`General { tag_length }`. General tags use the corresponding native
CKM_*_HMAC_GENERAL and a CK_MAC_GENERAL_PARAMS byte length, including when the
requested length equals the full hash output. No full-tag fallback occurs.
The application accepts half the hash output through its full length:
14–28, 16–32, 24–48 or 32–64 bytes. This applies the minimum recommended in
[RFC 2104 section 5](https://www.rfc-editor.org/rfc/rfc2104.html#section-5);
PKCS #11 itself permits shorter tags. Agree on one algorithm and tag length
before communicating and keep them fixed for the key's lifetime.

HMAC definitions do not assign units to mechanism key-size bounds, and providers
may report 0/0. These fields are not interpreted as HMAC key limits. The provider
may reject an otherwise permitted key length; rejection is returned without retry.

`Token::hmac_generation_options` checks CKM_GENERIC_SECRET_KEY_GEN and its native
generation entry point, flags and **bit-based** bounds, plus each HMAC mechanism's
signing/verification flags and native entry points. `generate_hmac_key` accepts
`HmacKeyRequest` and creates a hash-length generic secret, restricted to the chosen
HMAC mechanism and signing/verification only. Other operations are disabled. It
uses the generic generator available in 2.40; hash-specific generators are not
substituted. Generation requires RW mode and a new ID/label of 1–128 bytes each.
Duplicate secret IDs are rejected without a transaction against concurrent
writers. Failure can leave persistent effects; no key value, retry or rollback
is exposed. Advertised generation support does not promise HMAC acceptance. A provider
reporting 0/0 generic-generation bounds has no positive-length generation choices.
`hmac_general_generation_options` and `generate_hmac_general_key` apply the same
checks and template policy while allowing only the selected general mechanism.
The token's allowed-mechanism attribute does not encode a tag length; callers
must enforce their agreed length. Existing full-tag keys retain their restriction.

## AES-CMAC

`Session::aes_cmac_capabilities(key, MacOperation::Generate|Verify)` checks a
sensitive, nonextractable AES secret, its length, direction-specific permission,
allowed mechanisms, provider flags and native entry points. AES mechanism bounds
are in bytes. Metadata and provider failures propagate; advertised support is advisory.

`mac_aes_cmac(key, message)` uses CKM_AES_CMAC and returns a full 16-byte tag.
`verify_aes_cmac(key, message, tag)` uses native verification with CKA_VERIFY;
it does not generate a tag for comparison. Messages may be empty and are bounded
to 16 MiB. Both permit RO sessions and never read key values. Incorrect tag length
or a completed native verification mismatch returns `Error::MacMismatch`, leaving
the session usable. Other native failures, unwinds and malformed outputs invalidate
it. Generation uses fixed-size output storage without a provider-length allocation.
Check session closure before releasing results. Software fallback and retries are
not exposed. A shared-key MAC does not identify an individual signer.

`AesCmacProfile::General { tag_length }` selects native CKM_AES_CMAC_GENERAL
through `aes_cmac_capabilities_with_profile`, `mac_aes_cmac_with_profile` and
`verify_aes_cmac_with_profile`. This application accepts 8–16 bytes, including
16-byte general tags; the original calls keep CKM_AES_CMAC without parameters.
The token receives CK_MAC_GENERAL_PARAMS in bytes and produces/verifies the
selected tag directly. No full-tag generation followed by software truncation
occurs. Both profiles retain fixed 16-byte storage, exact native output bounds,
direction-specific permissions and checked session cleanup.

`aes_cmac_options` reports permitted full/general profiles. Unsupported profiles
are omitted; selection/provider errors propagate. General support is advisory
until the native call checks the selected length. Agree on a tag length before
communication and keep it fixed for the key's lifetime, as specified in
[RFC 4493 section 2.1](https://www.rfc-editor.org/rfc/rfc4493.html#section-2.1).
A mismatch never changes the length or retries with another profile.

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
permits wrapping/unwrapping only. `Authentication` permits MAC generation and
verification only, restricted by CKA_ALLOWED_MECHANISMS to CKM_AES_CMAC.
`AuthenticationGeneral` instead restricts the key to CKM_AES_CMAC_GENERAL.
`aes_cmac_general_generation_options` intersects generator sizes with native
general-CMAC support and bounds; generation rechecks it. Existing authentication
keys keep their full-tag restriction.
No key values are read or returned.

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

`X25519PublicKey::from_bytes` validates 32-byte RFC 7748 public inputs, including
high-bit/noncanonical encodings, and rejects noncontributory points. It uses
`curve25519-dalek` with a fixed public scalar for input validation; token private
keys are never supplied to software. `x25519_public_key` reads an existing
`CKK_EC_MONTGOMERY` public key with id-X25519 OID parameters and raw CKA_EC_POINT.
Identity and metadata reads are bounded to 4096 bytes per attribute.
`derive_x25519_secret` accepts a checked peer and uses CKM_ECDH1_DERIVE/CKD_NULL.
Its existing private base must be private, sensitive, nonextractable, permit
derivation and have always-authenticate disabled. The persistent output is a
complete 32-byte generic secret permitting derivation only, suitable for the
existing HKDF-SHA256 profile. Mechanism bounds use 255 field bits.
`generate_x25519_key_pair` creates persistent RFC 8410 pairs using the parameterless
Montgomery mechanism. Private keys permit only ECDH derivation and are sensitive
and nonextractable. `x25519_generation_supported` reports advisory native support;
execution rechecks it. `import_x25519_public_key` stores checked public input with
operation permissions disabled and does not establish trust or key association.
Both mutations require RW mode and nonempty IDs/labels of at most 128 bytes;
generation rejects existing public/private IDs and import rejects public IDs.
Concurrent writers can race; no retry or rollback occurs after provider failures.
Check session closure before releasing results. curveName parameters remain
outside this profile.

For existing RFC 8410 id-X448 keys, `X448PublicKey::from_bytes` checks 56-byte
public input using Curve448 field normalization and low-order checks from
`ed448-goldilocks-plus`, without selecting its signing features. Noncanonical
encodings are preserved and the high bit is not masked. `x448_public_key` checks
bounded metadata and requires Montgomery keys with OID parameters and raw points.
`derive_x448_key` shares the protected base-key, permission, native-function and
session-health checks with X25519, using 448-bit mechanism bounds.
`X448Derivation` requires explicit `X448Kdf` and `X448Output` selections. The null
KDF preserves the complete 56-byte derivation-only secret and accepts no context.
ANSI X9.63 and NIST SP 800-56A SHA-512 accept up to 4096 bytes of public context
and produce either AES-128/192/256 encryption keys or a 64-byte derivation secret.
Raw X448 output cannot feed this app's hash-length PKCS #11 HKDF profile; choose
the SHA-512/64-byte profile explicitly for later HKDF-SHA512. No truncation,
KDF substitution or secret extraction occurs.
`generate_x448_key_pair` accepts `X448KeyPairRequest` and creates a persistent
RFC 8410 pair using the parameterless Montgomery mechanism with 448-bit bounds.
Its private key is sensitive, nonextractable and restricted to ECDH derivation;
per-operation authentication is disabled. `x448_generation_supported` reports
advisory generation support. `import_x448_public_key` stores checked public input
with operation permissions disabled. Both mutations require RW mode and nonempty
IDs/labels of at most 128 bytes. Generation rejects existing public/private IDs;
import rejects public IDs and does not establish trust or private-key association.
Concurrent writers can race; no retry/rollback occurs after provider failures.
Check session closure before releasing results. This profile requires OID
parameters; desktop workflows remain deferred.

`MontgomeryNamedCurve::{Curve25519, Curve448}` explicitly selects the DER
PrintableString profile required by PKCS #11 sections 6.3.7–6.3.8. These objects
are distinct from the RFC 8410 OID profiles accepted by the X25519/X448 APIs.
`MontgomeryNamedPublicKey::from_bytes` validates raw public input, including
length and noncontributory points. There is no SPKI conversion in this profile.

`generate_named_montgomery_key_pair`, `import_named_montgomery_public_key` and
`named_montgomery_public_key` retain the existing protected generation/import
policy and bounded metadata reads. `derive_named_montgomery_secret` requires
matching curveName parameters and derives a full 32/56-byte sensitive,
nonextractable generic secret with derivation permission only. Use a protocol KDF
and authenticate peers separately. The 56-byte curve448 result cannot feed the
HKDF-SHA512 profile requiring a 64-byte input; SP 800-108 accepts either width.
Provider rejection is returned without retry, fallback or rollback. The client exposes these operations with explicit raw peer input.

`derive_ecdh_key` accepts `EcdhKeyRequest` with explicit `EcdhKdf` and
`EcdhOutput`. ANSI X9.63 and NIST SP 800-56A KDFs support SHA-256/384/512 and
up to 4096 bytes of public shared info. They create either AES-128/192/256 keys
with encryption/decryption permission only, or 1–4096-byte generic secrets with
derivation permission only. The null KDF accepts no shared info and preserves
the complete raw secret; it cannot directly create AES keys. P-521 raw output
remains 66 bytes. An explicit SHA-2 KDF can instead create a 64-byte generic
secret suitable for the separately selected HKDF-SHA512 profile.

Mechanism flags do not advertise individual ECDH KDF parameters. Unsupported
parameters fail without retry, KDF substitution or software fallback. All
outputs remain persistent, private, sensitive and nonextractable.

`wrap_aes_key` and `unwrap_aes_key` use RFC 3394 with the default IV and
AES-128/192/256 keys. Wrapping requires CKA_WRAP, an extractable AES target and
compatible CKA_WRAP_WITH_TRUSTED policy. No key values are read. Unwrapping
creates a private, sensitive, nonextractable AES token key with only encryption/
decryption permission. Derived/unwrapped identities have bounded nonempty labels
and IDs; an existing secret-key ID is rejected, without a cross-process lock.

Derivation and unwrapping require RW mode. Failed native operations invalidate
the session; no retry or rollback is attempted. Provider templates and
permissions may narrow these profiles. Blobs carry ciphertext only, not metadata.

`aes_key_wrap_capabilities` queries KW and KWP separately for the selected Wrap
or Unwrap direction. Both require current key permission, allowed mechanisms,
provider flags/bounds and the native entry point. `wrap_aes_key_with_algorithm`
and `unwrap_aes_key_with_algorithm` accept `AesKeyWrapAlgorithm::Kw` or `Kwp`.
KWP uses `CKM_AES_KEY_WRAP_KWP`, not deprecated `CKM_AES_KEY_WRAP_PAD`.
Both use their standard default IV. Only AES-128/192/256 targets and outputs are
accepted, with 24/32/40-byte blobs. The selected algorithm must be conveyed
separately and matched for unwrapping; no fallback or retry occurs. See
[OASIS AES key wrap](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html#_Toc234407356).

## Token digests

`HashAlgorithm` covers SHA-224/256/384/512, SHA-512/224, SHA-512/256 and
SHA3-224/256/384/512 independently of signing and MGF profiles.
`Token::digest_algorithms(DigestMode)` checks advertised mechanisms, CKF_DIGEST
and the entry points required for single-part or multipart operation.
`Session::digest` hashes one message; `start_digest` returns an exclusive
`DigestOperation` accepting chunks through `update` and producing the hash with
`finish`. Empty messages/chunks are permitted. No key digest, SHA-1, operation
state export or software fallback is exposed by these APIs.

Native output allocations are fixed by the selected hash, at most 64 bytes.
Successful finalization restores session reuse. Abandoning a multipart guard or
any native error leaves the session unusable and causes a pooled lease to be
discarded. Explicit close remains available. The provider may require ordinary
login; these APIs do not change authentication implicitly.

```compile_fail
use pkcs11_runtime::{HashAlgorithm, Session};
fn exclusive(session: &mut Session<'_>) {
    let operation = session.start_digest(HashAlgorithm::Sha256).unwrap();
    session.info().unwrap(); // The operation retains exclusive access.
    operation.finish().unwrap();
}
```

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

`Session::derive_hkdf_with_mode` also accepts `HkdfMode::ExtractOnly` or
`ExpandOnly`. Extraction creates a hash-length `HkdfOutput::DerivationSecret`
containing the PRK; nonempty context and other output profiles are rejected.
Expansion requires empty salt and a caller-established PRK. Key type and length
cannot prove PRK provenance. Neither stage reads key values or changes stages
after a provider rejection. Both retain the same base-key requirements below.
`derive_hkdf_with_salt_key(base, salt_key, request, mode)` supplies a token salt
through `CKF_HKDF_SALT_KEY`. The byte salt must be empty and extraction enabled;
conflicting salts and expand-only mode are rejected. Both references resolve
freshly in the same session. This application accepts sensitive, nonextractable
CKK_GENERIC_SECRET/CKK_HKDF salt keys of 1–4096 bytes with CKA_DERIVE and allowed
HKDF use; unlike the base, the salt need not match the hash length. Salt values
are never read. Missing/ambiguous selections and policy failures precede the
native call. HKDF data objects are not exposed.

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

## SP 800-108 KDF

`Session::kbkdf_capabilities` inspects a generic or matching SHA-256/384/512 HMAC
secret. This application requires a 16–4096-byte sensitive, nonextractable base
with derivation permission and permitted CKM_SP800_108_COUNTER_KDF use. Native
derive support and mechanism key-size bounds are checked; OASIS section 6.42
specifies these bounds in bits. Capability results are advisory: the provider
checks individual PRF parameters and output templates during derivation.
Standalone HMAC signing permission and entry points are not required.

`Session::derive_kbkdf` takes `KbkdfRequest` and derives one key in an RW session.
Its fixed profile uses HMAC-SHA-256/384/512 with the PRF input
`[i]_32 || kdf_label || 0x00 || context || [L]_32`. Both integers are big-endian;
L is the requested output length in bits, using CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS.
There are no additional keys. Public label/context are each at most 4096 bytes
and may be empty or binary. The KDF label is separate from the new object's label.
Callers define unambiguous protocol encodings and authenticate peers separately.

`KbkdfOutput` selects AES-128/192/256 with encryption/decryption permission only,
or a 1–4096-byte generic secret permitting only further derivation. Outputs are
persistent private, sensitive and nonextractable. IDs/labels are 1–128 bytes;
existing secret IDs are rejected, without a transaction against concurrent writers.
No values are read, no base is deleted, and no retry, rollback or software
fallback occurs. Native errors invalidate the session and may leave persistent
effects. Check session closure before reporting success.

`Session::derive_kbkdf_with_mode(base, request, mode, iv)` also supports
`KbkdfMode::Feedback`. Its PRF input is
`K(i-1) || [i]_32 || kdf_label || 0x00 || context || [L]_32`, with K(0) equal
to the supplied IV. Counter and sum-of-keys output bit length remain 32-bit
big-endian. This application accepts an omitted IV or exactly one PRF output
block (32/48/64 bytes). An empty IV is passed as native NULL/0, without supplying
initial bytes. Counter mode rejects a nonempty IV. Mode/IV errors are rejected
before native derivation; no failed mode is replaced with another.

`kbkdf_capabilities_with_mode` checks one explicit mode. `kbkdf_options` inspects
both modes on the same selected key, omitting unsupported profiles while
propagating selection/provider errors. Each mode checks its own native mechanism,
allowed mechanisms, derive flag and bit-based key-size bounds. A token may support
only one mode. The original capability and derivation methods retain counter mode.

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

## Native RSA/ECDSA verification

`Session::verification_capabilities` inspects a `PublicKeyRef` using `CKA_VERIFY`,
`CKF_VERIFY`, available entry points, key size and `CKA_ALLOWED_MECHANISMS`.
`VerificationCapabilities::plan` applies a `SigningPolicy` to the same RSA/ECDSA
parameters and message/digest boundaries used for signing. It never grants
signing permissions. `VerifyRequest` combines those parameters with a modulus-width
RSA or fixed-width ECDSA `r || s` signature.

`Session::verify` executes `C_VerifyInit`/`C_Verify` once. A signature or length
mismatch returns `Error::SignatureMismatch`; completed mismatch operations leave
the session usable. Other native failures discard it. No certificate is required,
no trust decision is made, and no software verification or execution retry occurs.

## Pure EdDSA

`EdDsaCurve::{Ed25519, Ed448}` and `EdDsaRequest` are independent of ECDSA,
`DigestAlgorithm` and classical signing policy. Requests contain the expected
curve and original message; empty messages are valid. Context and prehash
variants use the separate curveName APIs below. RFC 8410 OID keys imply pure EdDSA without mechanism parameters. For RFC 8032
curve-name keys, Ed25519 uses no parameter and Ed448 uses `CK_EDDSA_PARAMS`
with `phFlag=false` and an empty context. Execution preserves this distinction
from [PKCS #11 3.2 sections 6.3.5 and 6.3.14](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).

`Token::eddsa_generation_options` reports advertised generation choices using
255/448-bit mechanism bounds. `Session::generate_eddsa_key_pair` requires RW mode,
explicit 1–128-byte ID/label and no existing pair ID. Templates restrict keys to
EdDSA signing/verification; private material is sensitive and nonextractable.
Concurrent writers can race; generation is never retried or rolled back.

`Session::eddsa_capabilities` accepts a public/private object selector and reads
bounded metadata. `sign_eddsa` and `verify_eddsa` recheck the curve, key permissions,
allowed mechanisms, flags and native entry points. Signing initializes once,
performs context login when required, then completes into a fixed 64/114-byte
buffer without a length query. Errors after initialization discard the session;
verification mismatches remain reusable. `eddsa_public_key` reads only public,
non-private CKA_EC_POINT values with the exact DER OCTET STRING encoding. The
client adds canonical point validation and RFC 8410 SPKI encoding.

## RFC 8032 curveName EdDSA

`EdDsaNamedRequest` explicitly selects `EdDsaNamedScheme::{Ed25519, Ed25519ctx,
Ed25519ph, Ed448, Ed448ph}`, an original message and 0–255 public context bytes.
Ed25519 requires an empty context; Ed25519ctx remains distinct even with an empty
context. The token performs prehashing for ph schemes. Caller-supplied digests
and automatic substitutions are not part of this API.

`sign_named_eddsa`, `verify_named_eddsa` and `named_eddsa_capabilities` require
exact RFC 8032 curveName metadata; RFC 8410 OID keys are rejected before native
initialization. The existing pure APIs retain their behavior. Sign/verify share
the bounded output, context-login ordering, mismatch reuse and failed-session
handling of the pure implementation.

`generate_named_eddsa_key_pair` creates a protected signing pair with explicit
curveName parameters. `import_named_eddsa_public_key` stores length-checked raw
public bytes for verification only; the client additionally validates the point.
`named_eddsa_public_key` requires raw CKA_EC_POINT of exactly 32/57 bytes, a public
non-private object and bounded metadata. No SPKI conversion or private-key export
occurs. Generation/import require RW mode and bounded nonempty identities, reject
existing IDs and perform no retry/rollback. Check closure before releasing results.

The Kryoptic validation build enables Edwards support and records a patch for
255/448-bit mechanism bounds while preserving its 32/57-byte storage widths.
All published RFC 8032 section 7 vectors run in the provider suite.

## Explicit session cancellation

`Session::cancel_operations(CancelFlags)` calls `C_SessionCancel` once on a
healthy, exclusively owned session. Flags cover object search, encryption,
decryption, digest, signing/MAC generation and verification; combine them with
`|`. Empty flags leave native state unchanged, and inactive classes are ignored.
Unknown flags are rejected before provider access. Support depends on the
selected 3.x function table and pointer, not the reported library version.

`DigestOperation::cancel` consumes an active digest guard and requests only
`CKF_DIGEST`. A successful native result restores session reuse. Missing support,
unsupported stubs, partial cancellation failures, pending results and other errors
leave the session unusable until closure. Cancellation never repairs an earlier
native update/final failure. Only the requested classes are confirmed terminated;
success does not assert that other operation classes are idle.

Drop and reader failures retain close/discard behavior, including on providers
with cancellation support. There is no implicit cancellation, retry, logout,
global session teardown or use of legacy `C_CancelFunction`/`C_GetFunctionStatus`.
Cancellation follows [PKCS #11 3.2 section 5.6.5](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).
