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
drop(pool); // closes all idle sessions before module finalization
module.finalize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`try_acquire` immediately returns PoolExhausted at capacity. It checks health,
replaces stale idle sessions once, and ensures the requested login role. A matching
existing role does not validate the supplied PIN again. Failed login/open returns
capacity. Drop returns healthy sessions and closes explicitly discarded, failed or
panicking leases. Returned sessions are checked against the pool's module/token/mode.
Pool poisoning is a typed error. Closing failures during Drop are best effort.
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

## Testing

```sh
cargo test -p pkcs11-runtime --locked
./tools/test-softhsm.sh
```

Unit tests cover selection, redaction and signing plans; compile-fail examples
check module, session and object lifetimes. The SoftHSM runner provisions disposable
tokens for discovery, authentication, signing and mutation tests. See the
[test guide](../../tests/README.md) for provider configuration.
