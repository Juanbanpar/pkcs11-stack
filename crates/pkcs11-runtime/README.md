# pkcs11-runtime

Synchronous PKCS#11 execution over `cryptoki`: module ownership, token/object
discovery, authentication, bounded session pools and typed cryptographic operations.
For application workflows and certificate binding, use
[pkcs11-client](https://github.com/Juanbanpar/pkcs11-stack/blob/main/crates/pkcs11-client/README.md).

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

`Module::load` canonicalizes an explicit trusted library path and initializes with
OS locking. An already-initialized module is not adopted or finalized; share the
existing owner. Failed metadata discovery after initialization attempts cleanup,
preserving both errors if cleanup also fails. There is no global owner registry.

| Resource | Lifetime and cleanup |
| --- | --- |
| Borrowed `Token` / `Session` | Module borrow remains active through session destruction |
| `Object` | Borrows its original session; handles cannot migrate between sessions |
| Borrowed `SessionPool` | Keeps the module borrowed through pool destruction |
| `SessionPool::new_owned` | Each idle/leased session retains the existing `Arc<Module>` owner |
| Explicit `close` / `finalize` | Report typed cleanup errors; Drop is best effort |

A module cannot finalize while its borrowed session is alive:

```compile_fail,E0505
use pkcs11_runtime::{Module, SessionMode};
fn invalid_shutdown(module: Module) {
    let slot = module.slots(true).unwrap()[0];
    let token = module.token(slot).unwrap();
    let _session = token.open_session(SessionMode::ReadOnly).unwrap();
    module.finalize().unwrap(); // session destruction still needs the module
}
```

Nor can an object outlive its session:

```compile_fail,E0505
use pkcs11_runtime::{Session, AttributeType};
fn invalid_object_use(mut session: Session<'_>) {
    let objects = session.find_objects(&[]).unwrap();
    session.close().unwrap();
    objects[0].read_attributes(&[AttributeType::Label]).unwrap();
}
```

For owned pools, stop operations, drop consumers/pools, unwrap the final module
Arc and call `finalize`. Dropping the final Arc performs best-effort cleanup.
cryptoki may log/retry a failed session close during its own Drop. Runtime never
retries authentication or object operations. Independent raw contexts, external
finalizers and nonconforming provider initialization are outside this guarantee.

## Discovery and selectors

| API | Scope |
| --- | --- |
| `resolve_token(TokenSelector)` | Token-only criteria inside the explicitly loaded module |
| `resolve_token_uri(&Pkcs11Uri)` | Full module/slot/token criteria; rejects object, PIN and unsupported constraints |
| `ObjectRef` | Persistent selector with token/object criteria; no cached handle |
| `find_objects` | Arbitrary cryptoki templates, including session objects; returns session-bound objects |
| `validate_token_uri` | Pure validation before module loading |

Resolution distinguishes zero, one and multiple matches. `module-path` must exactly
match the loaded canonical path; logical module-name resolution is unsupported.
Object references reject PIN queries, slot IDs and unknown path constraints.
Each resolve searches anew, requires CKA_TOKEN=true and checks the full identity.
Slot IDs serve current discovery, not persistent object identity.

Discovery includes reported uninitialized tokens and skips disappearance only for
CKR_TOKEN_NOT_PRESENT. Identity metadata is checked before operations and around
session opening. This detects changed label/manufacturer/model/serial, not an
identical replacement device. Removal, slot races and token-wide logout still
propagate errors without hidden rediscovery or module reload.

`read_attributes` can omit unavailable values; `attribute_info` distinguishes
Sensitive, TypeInvalid and Unavailable. `AttributeValues` redacts Debug output,
but `expose_values` can reveal extractable secrets in nonzeroizing cryptoki
containers. Protect these values and caller templates; runtime never logs them.
Public metadata reads only public components, parameters/points and optional SPKI.
Certificate DER is read independently: matching labels/IDs do not bind a key or
validate certificate trust.

## Authentication and concurrency

- Authentication explicitly selects no change, USER, SO or a protected path.
  PINs are borrowed `SecretString`s and never cached; SO requires RW mode.
- Login/logout are token-wide. `None` does not log out, and Drop never explicitly
  logs out, though closing the last session can reset authentication.
- Standalone login does not silently adopt an existing login. Pool checkout
  ensures the requested role; a matching role does not revalidate a supplied PIN.
- Sessions are exclusive; leases own separate sessions. Modules can be shared
  across scoped threads. Runtime creates no executor or worker thread.

Always-authenticate classical signing uses init, context login and combined
multipart RSA/ECDSA hashing. Raw/prehashed requests are rejected because the
binding cannot interleave login and single-part completion. Actual provider
multipart support is required; SoftHSM 2.7 advertises combined ECDSA but rejects
its multipart form. EdDSA context authentication is unsupported.

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

`try_acquire` fails immediately with `PoolExhausted` at capacity. It checks health,
replaces a stale idle session once and ensures the requested role. Failed open/login
returns capacity. Lease Drop returns healthy sessions and closes discarded, failed
or panicking sessions. Module/token/mode and pool poisoning are checked explicitly.

Release all leases before `SessionPool::close`. It attempts every idle close and
reports earlier discarded-session closure failures. A failed close blocks further
checkout with `PoolCleanupFailed`; replace the pool after resolving cleanup.
Drop remains best effort and never initiates token-wide logout.

Failed signing/search, metadata reads or identity checks invalidate a session;
further operations return `Closed`, while explicit close still attempts cleanup.
Ordinary standalone login failures remain reportable without invalidation. No
failed signature or PIN attempt is retried. Token replacement/slot rediscovery
and coordination with external logout remain the caller's responsibility.

Objects cannot survive lease return, and pools keep the module alive:

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

Signing intersects mechanism flags/bounds, key type/size/curve, CKA_SIGN,
CKA_ALLOWED_MECHANISMS, policy and parameters. Missing required metadata fails
closed. Plans are advisory; execution resolves and plans again without caching
handles. The provider remains authoritative for parameter combinations.

| Input or policy | Contract |
| --- | --- |
| `TokenOnly` (default) | Hash messages on the token |
| `AllowSoftware` / `SoftwareOnly` | Explicit software hash selection before signing; no retry after failure |
| `SignInput::Digest` | Exact selected digest length; never hash again |
| RSA-PSS | Explicit salt length and MGF1 digest |
| RSA PKCS#1 v1.5 | Modulus-width signature; raw signing includes DigestInfo |
| ECDSA | Fixed-width `r \|\| s` for P-256/P-384/P-521, without DER conversion |
| Default digests | SHA-256/384/512; SHA-1 and SHA-224 require `policy.digests` opt-in |

SHA-224 PSS has no combined mechanism; use explicit software/caller hashing.
SHA-1 DigestInfo uses OID `1.3.14.3.2.26`. Signing inputs redact Debug, but borrowed
message/digest buffers are not zeroizing. `PrivateKeyRef`, `PublicKeyRef` and
`CertificateRef` require explicit URI classes.

## Encryption

| Operation | Profile |
| --- | --- |
| `rsa_oaep_capabilities`, `encrypt_rsa_oaep`, `decrypt_rsa_oaep` | RSA 2048–16384 bits; SHA-256/384/512 with matching MGF1 and empty label; plaintext must fit OAEP, ciphertext is modulus-width |
| `aes_gcm_capabilities`, `encrypt_aes_gcm`, `decrypt_aes_gcm` | AES-128/192/256; 12-byte nonce, separate AAD and full 16-byte tag appended to ciphertext; RO or RW session |
| `aes_capabilities`, `encrypt_aes`, `decrypt_aes` | ECB/CBC/CBC-PAD, single-part and multipart; request rustdoc defines IV, padding and bounds |

OAEP rejects per-operation-authenticated decryption before init. GCM requires a
secret AES key with direction permission, allowed mechanisms, advertised bounds
and native entry points. Encryption keys and HKDF AES outputs qualify; wrapping-only
keys and raw generic secrets do not. Plaintext is limited to 16 MiB, AAD to 1 MiB;
empty input/AAD are accepted. Ciphertext contains exactly 16 tag bytes.

**Never reuse a GCM nonce with the same key**, including across writers, restarts
and key copies. An encryption error does not permit reuse. No nonce tracking,
software fallback, multipart plaintext release or envelope format is supplied.

Successful plaintext is redacted and zeroizing; GCM releases none on authentication
failure. Provider errors, unwinds and malformed output invalidate the session;
preflight rejection precedes crypto. cryptoki failed-call buffers cannot be
guaranteed zeroized. Check session closure before releasing output when cleanup
errors must be reported.

## Key generation and administration

| API | Result or constraint |
| --- | --- |
| `generate_signing_key_pair` | Persistent RSA/named-EC pair; sensitive, nonextractable private key |
| `generate_ecdh_key_pair` | P-256/P-384/P-521 public key and derivation-only sensitive, nonextractable private key; no per-operation authentication |
| `generate_aes_key` | Private, sensitive, nonextractable AES-128/192/256; `Encryption` or `Wrapping` purpose |
| `generate_mac_key` | Persistent HMAC or AES-CMAC key |
| `create_object`, `update_attributes`, consuming `destroy` | Explicit templates/objects, authorized by the provider |
| `initialize_pin`, `change_pin` | USER/SO PIN administration; host PINs required by the binding |

Generation choices check native entry points, flags and bounds but cannot guarantee
template acceptance or later operation support. EC bounds are bits; AES bounds and
CKA_VALUE_LEN are bytes. ECDH/AES requests require 1–128-byte IDs/labels and reject
existing public/private IDs for ECDH or secret IDs for AES. This does not guarantee
uniqueness against concurrent writers; signing generation can create duplicate IDs.

Mutations need healthy RW sessions and provider authorization. Failure/unwind
invalidates the session; there is no retry or rollback. Even errors can leave
persistent objects or partial attribute updates. Generated/derived key values are
never read. Arbitrary caller templates may contain secrets and must be protected.

`Module::initialize_token` can erase an explicit diagnostic slot. Exclusive module
access prevents initialization while borrowed consumers are live:

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

Use the client's checked initialization API for confirmation flows that also
recheck captured token metadata.

## Derivation and key transfer

`key_operation_profile` checks key class, usage, allowed mechanisms and bounds.
Execution resolves selectors and checks capabilities again.

| API | Contract |
| --- | --- |
| `derive_ecdh_secret` | P-256/P-384/P-521 raw ECDH, explicit null KDF; caller validates the same-curve peer point; no context authentication |
| `derive_montgomery` | X25519/X448; length/low-order-checked peer; CKD_NULL or X9.63/SP 800-56A SHA-2 KDF |
| `wrap_aes_key` | RFC 3394 default IV; AES wrapping key and extractable AES target; honor CKA_WRAP_WITH_TRUSTED |
| `unwrap_aes_key` | RFC 3394 default IV; persistent private, sensitive, nonextractable AES encryption/decryption key |

Raw ECDH produces a persistent derivation-only private generic secret that is
sensitive and nonextractable. Authenticate peers and apply a protocol KDF;
`pkcs11-client` supplies SPKI peer validation. Derivation/unwrapping need RW mode
and bounded nonempty new IDs/labels; existing secret IDs are rejected without a
cross-process lock. Wrapping blobs carry ciphertext only. Provider templates and
permissions can further restrict these operations.

## ML-DSA, EdDSA and SLH-DSA

| Family | Typed profile |
| --- | --- |
| Pure ML-DSA | `MlDsaRequest`: ML-DSA-44/65/87, original message, context up to 255 bytes, explicit hedging; separate `MlDsaSigningPolicy` |
| EdDSA | Pure Ed25519/Ed448 message signing, verification and public import/export; RFC 8410 OID or RFC 8032 curveName parameters accepted |
| Pure SLH-DSA | Parameter-set-specific generation/sign/verify and public export |
| HashML-DSA / HashSLH-DSA | SHA-2/SHA-3/SHAKE token-hashed message profiles; only SHA-2 caller digests are representable by the binding |

ML-DSA generation uses explicit ID/label and optional always-authenticate;
private keys are sensitive/nonextractable. Capabilities intersect permissions,
allowed mechanisms and flags/bounds; ML-DSA mechanism bounds are public-key bytes.
`sign_ml_dsa` rechecks the parameter set/policy and validates signature length.
Always-authenticate uses init/context-login/multipart signing; ordinary keys use
single-part. Public-key reads require public, non-private objects and valid lengths.
External-mu signing is unsupported.

`verify_ml_dsa` maps malformed/nonmatching signatures to `SignatureMismatch`;
a completed C_Verify mismatch leaves the session usable. Other backend failures
invalidate it. Verification alone does not bind a private key or establish trust;
software verification and certificate binding belong to `pkcs11-client`.

EdDSA has no prehash/context scheme or per-operation authentication. Pure SLH-DSA
and HashSLH-DSA require separate generated key pairs with disjoint allowed
mechanisms. Generated HashSLH-only pairs allow raw prehash and SHA-2/SHA-3
message mechanisms, excluding SHAKE. SLH-DSA context authentication depends on
provider multipart support.

## ML-KEM

`MlKemParameterSet` selects ML-KEM-512/768/1024. Generation checks flags and
public-key byte bounds, then creates a persistent public encapsulation key and a
sensitive, nonextractable private decapsulation key. Duplicate pair IDs can remain
ambiguous. Public import needs RW mode and explicit ID/label, preserving existing
objects. `MlKemPublicKey::from_bytes` and public export validate length and the
FIPS 203 modulus check; public reads reject private objects.

`ml_kem_capabilities` checks class, parameter set, direction, permissions,
mechanisms, bounds and entry points. Always-authenticate decapsulation is unsupported.
`encapsulate_ml_kem` returns public ciphertext; `decapsulate_ml_kem` takes it.
Both require RW mode and `MlKemRequest` with an expected parameter set and new
1–128-byte secret ID/label. Existing secret IDs are rejected. Outputs are private,
persistent 32-byte generic secrets, sensitive/nonextractable and derivation-only.

Authenticate peers and apply a KDF separately. Implicit rejection can produce a
different secret for altered same-length ciphertext without an error. Success
alone authenticates neither a peer nor agreement. No seed or shared-secret value
is read; errors can leave persistent effects.

## HKDF

`derive_hkdf` performs CKM_HKDF_DERIVE extract-and-expand in RW mode. Capabilities
require a sensitive, nonextractable generic/HKDF base with CKA_DERIVE, allowed
mechanisms and native derive support.

| Parameter | Contract |
| --- | --- |
| Digest/base length | SHA-1/224/256/384/512 with 20/28/32/48/64-byte base respectively; ML-KEM uses SHA-256 |
| Salt/context | Public, at most 4096 bytes each; empty salt means RFC 5869 zero salt; empty context allowed |
| Output | AES-128/192/256 encryption/decryption key, or generic derivation-only secret |
| Output length | 1 through 255 times the hash length |
| Identity | New nonempty ID/label up to 128 bytes; reject existing secret IDs |

Outputs are persistent, private, sensitive and nonextractable. Base keys remain
until deleted. No values are read; duplicate checks are not transactions against
other writers. Advertisement does not guarantee parameter/template acceptance.
Applications define protocol salt/context and authenticate peers; single-input
HKDF neither authenticates ML-KEM ciphertexts nor combines classical/PQC secrets.

## Application hybrid derivation

`derive_hybrid_hkdf` concatenates P-256 ECDH then ML-KEM-768 secrets and applies
HKDF-SHA512 on the same token. It uses a classical || auxiliary construction;
it follows the construction described in [NIST SP 800-56C Rev. 2](https://doi.org/10.6028/NIST.SP.800-56Cr2)
and defines neither a wire protocol nor X-Wing or the TLS key schedule.

Both selectors must resolve to distinct 32-byte generic secrets permitting
derivation and CKM_CONCATENATE_BASE_AND_KEY, with sensitive/nonextractable
attributes. Metadata cannot prove origin or independent generation; callers must
establish provenance and authenticate peers in the same protocol exchange.

Use `HkdfRequest` with SHA-512, public salt up to 128 bytes and nonempty context up
to 4096 bytes. Bind identities, algorithms, roles and transcript as required by the
protocol. Output profiles/identity checks follow HKDF. The temporary 64-byte
concatenation is a private, sensitive, nonextractable session object destroyed
before return. Cleanup failure invalidates the session and takes precedence over
the operation result; persistent output may already exist. Inputs are not deleted.

## Other mechanisms and random bytes

| API | Supported profile |
| --- | --- |
| `mechanism_capabilities` | Advertised family, flags, bounds, typed operations and `executable` flag |
| `Module::function_availability` | Functions available through the negotiated interface |
| `digest` / `digest_chunks` | SHA-1, SHA-224/256/384/512 |
| `mac` / `verify_mac` and multipart variants | Full-tag HMAC-SHA-1/2 and AES-CMAC |
| `derive_kbkdf` | SP 800-108 counter/feedback/double-pipeline with HMAC-SHA-1/2 or AES-CMAC |
| `verify` / `verify_signature` | Token RSA/ECDSA verification; signature-first path depends on interface support |
| `generate_random` | Fill a nonempty caller buffer from the advertised token RNG; discard after any error |

`executable` means a typed path exists, not that a provider accepts every parameter.
A signature-first stub returning CKR_FUNCTION_NOT_SUPPORTED maps to
`UnsupportedVerification` and leaves the session usable. RNG calls add no login,
software fallback or retry; a provider failure invalidates the session.
See the [compatibility matrix](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/oasis-compatibility.md) for application
coverage and binding limits. Individual API rustdoc defines request bounds and errors.

## Documentation and tests

```sh
cargo doc -p pkcs11-runtime --no-deps --locked
cargo test -p pkcs11-runtime --locked
```

Doctests check ownership and lifetime errors. The [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md)
provides disposable SoftHSM/Kryoptic integration commands. Provider tests do not
establish formal algorithm validation or hardware compatibility.
