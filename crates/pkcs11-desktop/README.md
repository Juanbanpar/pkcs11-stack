# pkcs11-desktop

Native PKCS#11 browser and object manager built with Iced and `pkcs11-client`.
Load trusted vendor libraries, inspect module and slot metadata, and view token
identity, initialization, authentication flags and PIN limits. Log in as USER or
SO to browse visible persistent objects. Filter object lists and advertised
mechanisms, then select an entry for metadata details.

## Usage

Select **Add Module**, choose a library with **Browse**, or enter its path, then
select **Load**.
The sidebar lists loaded modules and their tokens. Select a module for library and
slot information, or a token for its overview. The token header identifies the
provider, serial number and current login role. **Show PKCS#11 locator** expands
the technical identifier when needed.

Tab and Shift+Tab move between enabled controls. Enter or Space activates buttons;
arrows, Home and End move within navigation, resource lists, tabs and choices.
Moving focus through resources does not read details until activation. Escape
closes the current dialog or form. Ctrl+O opens Add Module, Ctrl+F focuses the
resource filter, Ctrl+R refreshes the current resource and Ctrl+Q quits. Use
Command instead of Ctrl on macOS.

**Appearance** offers System, Light and Dark. System follows the desktop theme
when available and otherwise uses Light. Appearance is not saved. Resource lists
and details appear side by side in wider windows; smaller windows show a separate
detail view with **Back to List**, which returns focus to the selected row.
Column headings sort without reading the token. The object inspector shows its
identity, actions and attributes; locators are collapsed initially.

**Refresh** on the module overview re-enumerates the selected module's slots and
tokens. Removed or replaced tokens clear their selection. **Unload** finalizes the selected module;
quitting finalizes all loaded modules.

If a session cannot be closed, the module's tokens and cached objects are cleared
and further token operations are blocked. Unload the module before using it again.
This also applies when the operation itself failed; a change may still have applied.

Select **Objects** to list persistent objects visible to the current role. Filter by
label, class, hexadecimal ID or locator, then select an object to read its metadata.
Listing requests only class, label and ID; detail reads use a small metadata
allowlist and never fetch object values or private key material. Missing,
sensitive and unsupported attributes remain distinguishable. Objects with
duplicate locators or unsupported identities show their summary without a detail
read. **Refresh** on Objects clears selection and reads a new list.

Use **USER login** or **SO login** on the selected token, enter its PIN and select
**Login**. Locked or uninitialized PINs disable their role; SO also needs writable
session support. A token that advertises a protected authentication path defaults
to that path; complete authentication on the token, or switch to host PIN entry.
Each submission makes one attempt. The form clears after submission, cancellation
or navigation. **Logout** clears object selections and details before the worker
logs out. Refresh the object list after changing authentication.

PINs are held in zeroizing application state and worker commands, excluded from
diagnostics and never saved. Masked input disables copying and cutting. Iced's
text editing internals create transient plaintext copies that are not guaranteed
to be zeroized.

Select **Mechanisms** to browse provider-advertised names, identifiers, flags and
key-size bounds. Filter by name, hexadecimal identifier or flag, and use
**Refresh** on Mechanisms to re-enumerate. Bounds retain the provider's units;
the browser does not plan or execute cryptographic operations.

Linux requires Wayland; X11 is not built. The native file picker uses the desktop
portal, with a Zenity fallback.
Manual path entry also works when no picker service is available. Modules are
loaded only after an explicit Load action; paths are not saved or loaded on startup.

Use **Operations** to choose a key generation, certificate import or random
generation task. Each task opens its own form. Key generation and certificate
import require USER login on a writable token. Generation uses the client's shared
capability query to offer RSA/EC and ML-DSA-44/65/87 signing pairs,
ML-KEM-512/768/1024 encapsulation/decapsulation pairs, P-256/P-384/P-521 ECDH pairs
and AES-128/192/256 keys. Unsupported choices are omitted. Each choice names its
purpose. ECDH private keys permit only derivation; AES keys permit either
encryption/decryption or wrapping/unwrapping.
Private and secret keys are sensitive and nonextractable. Per-signature
authentication is available only for signing keys and clears when another purpose
is selected. A provider may reject an advertised choice or template; operations
are never retried automatically.

Supply a label and hexadecimal ID. ECDH/AES identity fields each require 1–128
bytes. Existing public/private IDs are rejected for ECDH pairs, and secret IDs for
AES, without a uniqueness guarantee against concurrent writers. Signing pairs
and ML-KEM pairs permit duplicate IDs; ambiguous selectors are rejected. Key
pairs share their ID and label. ML-KEM does not permit per-operation PIN
authentication. Use `pkcs11ctl` for KEM operations; those workflows are not yet
exposed in the desktop.

Certificate import accepts one X.509 DER file up to 16 MiB and an explicit label/ID.
It parses certificate metadata without establishing trust or binding the
certificate to a key. PEM, bundles and private-key import are not supported.

On **Objects**, select an unambiguous object and use **Delete object**. Confirm the
shown locator to permanently delete that single object. Related keys and
certificates are kept. **Export public object** saves public certificate/data
values, or RSA, P-256/P-384/P-521, ML-DSA-44/65/87 and ML-KEM-512/768/1024 public
keys as SPKI DER. The client selects the encoder from token metadata and validates
the public key. Public export does not require login or authenticate a peer.
Private objects and private/secret key classes cannot be exported. Export creates a new file and
never overwrites one; a write failure can leave a partial file. On Unix, new
export files are created with permissions 0600.

Management clears selections and refreshes the object list, including after a
failure that might have partial effects. Labels can collide, and existing signing
generation permits duplicate IDs; ambiguous selectors are rejected. Mutation commands
and export finish before another operation can start; navigation remains available.

Key actions follow the key type read with the selected object's attributes:
RSA offers signing and OAEP, EC offers signing and ECDH, ML-DSA offers signing,
and AES offers GCM and wrapping. ML-KEM and generic secret keys do not offer those
actions. Permissions and provider capabilities are checked again in the worker.

To sign a file, log in as USER and select an unambiguous private key on **Objects**.
For RSA/EC, choose **Sign file**, select a client-provided SHA-2 signature choice, and provide
a message file and a new signature output path. Token hashing is required by
default; **Allow software hashing** permits a fallback planned before signing.
The displayed mechanism and hashing location are advisory and checked again at
execution. PSS choices use a matching MGF1 digest and digest-length salt.

For ML-DSA-44/65/87, **Sign file** uses the observed parameter set and the original
message, up to 16 MiB, including an empty file. Pure ML-DSA requires fresh token
randomness and has no prehash, deterministic or software-hashing fallback. An
optional domain context accepts up to 255 UTF-8 bytes; this is separate from the
per-operation PIN. Always-authenticate keys use the same one-attempt PIN or
protected-path form as classical signing. Protected-path behavior requires a
supporting token and has not been tested with hardware.

The output is a raw ML-DSA signature. Keep the domain context with the message for
verification: the signature file contains no context or metadata. Existing files
are never overwritten. The worker checks session closure before writing the
signature; a failed signing operation may leave an empty file.

Keys with CKA_ALWAYS_AUTHENTICATE require a per-operation PIN or supported
protected authentication path. This credential is cleared on submission,
cancellation or navigation. Each submission signs once; failures are never retried.
The worker reserves a new output file before signing and checks session closure
before writing the signature. Existing files are preserved;
a failed signature or write can leave an empty or partial file. Signing refreshes
token status and object inventories, including after authentication failures.

Select a supported certificate and choose **Verify signature** to check a message
and signature in software using its RSA/EC or ML-DSA public key. ML-DSA uses the
parameter set encoded in the certificate and the original message, with the exact
domain context used for signing (empty unless one was supplied). No login,
per-operation PIN or token verification mechanism is required for a visible public
certificate. Both input files are read without modification. Verification does not establish
certificate trust or prove association with a token key. Editing the form or
changing selection invalidates pending verification results, including changes to
the ML-DSA domain context.

Message files are limited to 16 MiB and signature inputs to 16 KiB. RSA signatures
use raw modulus-width bytes; EC signatures use fixed-width `r || s`, not ASN.1 DER.
File contents, signature bytes and credentials remain on the worker.

For AES-GCM, log in as USER and select an AES secret key on **Objects**. Choose
**Encrypt AES-GCM** or **Decrypt AES-GCM**. Supply exactly 24 hexadecimal nonce
digits, an input file, a new output path and, optionally, an AAD file. The worker
checks key permissions and provider support again before execution. Wrapping-only
keys cannot encrypt/decrypt.

Output/input is raw ciphertext followed by a full 16-byte tag. Nonce and AAD are
separate: retain them for decryption. Plaintext is limited to 16 MiB and AAD to
1 MiB; empty files and absent AAD are supported. Nonces must never repeat for the
same key, including across applications, restarts and copies of key material.
After an encryption error, use a new nonce. This interface does not generate or
track nonces and does not define a file envelope.

Decryption writes no plaintext before successful authentication and checked
session closure. Altered nonce, AAD, ciphertext or tag fails. Existing output files
are preserved; failures can leave an empty output, or a partial file after a write
error. Input and plaintext use zeroizing storage on the worker. Parameter forms
clear after submission or navigation, and stale capability/picker results are
ignored. Operations are not retried.

On **Objects**, select a public RSA key and choose **Encrypt RSA OAEP**, or log in
as USER and select a private RSA key for **Decrypt RSA OAEP**. Client-provided
choices display SHA-2 digest and byte limits. OAEP uses a matching MGF1 digest and
empty label; output is one raw RSA block, with no header. Select the same digest
when decrypting. This handles small payloads, not bulk files or sender authentication.

Permissions, allowed mechanisms and bounds are checked again at execution. Keys
requiring authentication for each decrypt operation are unsupported by the binding
and rejected before decrypt init. Vendor digest-parameter rejection never causes
a retry, SHA-1 fallback or padding downgrade. Input and successful plaintext stay
in zeroizing storage on the worker; cryptoki's transient buffers after a failed
provider call cannot currently be guaranteed zeroized.

The worker creates a new output file before the token call and reports session
close failures before writing bytes. Existing files are preserved. Failures may
leave an empty or partial file. Operations finish before another command can start;
navigation remains available, and inventories refresh after failures as well as success.

On **Operations**, use **Generate token random bytes** for an initialized token
that advertises its own RNG. Enter a byte count from 1 to 1048576 and a new output
path, then select **Generate and save**. The provider may require USER login; no
authentication attempt or software fallback is made automatically.

Random output stays in redacted, zeroizing storage on the worker and is written
only to the requested file. The worker reserves the file before generation and
reports session-close failures before writing bytes. Unix output permissions are
0600. Existing files are never overwritten; failures can leave an empty or partial
file. Generation and its file write finish before another operation can start;
navigation remains available.

## Development

Rust 1.88 or newer. Iced 0.14 uses `tiny-skia`, `thread-pool`, `wayland`, `advanced`
and `linux-theme-detection`, with default features disabled. `iced_aw` enables only `badge` and `spinner`.
`iced_fonts` enables only the Lucide icon font.

```sh
cargo run -p pkcs11-desktop --locked
cargo test -p pkcs11-desktop --locked
```

Linux build dependencies on Ubuntu:

```sh
sudo apt-get install pkg-config libxkbcommon-dev libwayland-dev libegl1-mesa-dev
```

## Derivation and key transfer

After USER login, select an EC private key with derivation permission and choose
**Derive ECDH secret**. Supply a peer public key in SPKI DER, a new label and a
hexadecimal ID. The client validates the peer point and requires the same named
curve as the base key. P-256/P-384/P-521 use the explicitly selected null KDF.
The result is a persistent private, sensitive, nonextractable generic secret,
with derivation permission only. It cannot be encrypted, signed or wrapped.
A subsequent KDF is required before cryptographic use; KDF application is not
implemented. Authenticate the peer separately; ECDH alone does not establish
its identity. Per-operation-authentication base keys are unsupported.

Select an AES key with wrapping permission and choose **Wrap AES key**. Select
another secret key as the target and a new output file. The client requires an
extractable AES-128/192/256 target and honors CKA_WRAP_WITH_TRUSTED. Candidates
are checked on submission; the app never changes a key's extractability or trust
policy. Wrapped output uses RFC 3394 with the default IV and contains no object
metadata. Files are never overwritten; a failed operation may leave an empty or
partial file.

Choose **Unwrap AES key** on an AES key with unwrapping permission, select a
24/32/40-byte wrapped file, and provide a new label and hexadecimal ID. It creates
an AES-128/192/256 token key with encryption/decryption permission only. The key
is private, sensitive and nonextractable. Existing secret key IDs are rejected.
Unwrapping and derivation require a writable token. The app does not generate
wrapping or ECDH base keys yet; provision compatible keys separately.

All three operations execute once on the worker and refresh inventories on
success or failure. Once submitted, they cannot be cancelled or superseded.
Navigation remains available. There is no retry or rollback: a failed provider
call or session close may still leave a created object. Refresh before retrying.

## Administration

Select **Administration** on a writable token. **Initialize / erase token** sets
its label and SO PIN on first initialization. For an initialized token it requires
the current SO PIN, erases its objects and resets USER PIN initialization. The
review shows the module path, slot, token identity and role; type `ERASE` to apply.
All of this app's sessions for that module close first, including other tokens.
The client rechecks the confirmed slot, identity, initialized state and PIN bounds
before the call. Identical replacement devices or a swap after the check cannot
be detected; ensure exclusive physical access. Refresh and select the resulting
token before initializing its USER PIN.

After SO login, **Initialize / reset USER PIN** sets a new USER PIN. After USER
or SO login, **Change current role's PIN** changes that role's credential using
its current PIN. New PINs require a matching confirmation and available provider
byte bounds. Review the target and type `CHANGE` to submit. Successful and failed
PIN attempts close this app's authenticated session on that token; log in again
with the applicable PIN. Failed calls may still apply changes; no retry or rollback
occurs. If session cleanup fails, unload the module before using it again.

Administration accepts host PINs only. Protected-path tokens, read-only tokens,
and locked roles are disabled, except that an uninitialized token can establish
its first SO PIN. PIN forms clear on submission, cancellation, navigation and
shutdown. Confirmation is invalidated by role or target changes. Submitted
administration cannot be cancelled or superseded; navigation remains available.

## Execution

One worker owns all client providers and performs module loading, discovery,
refresh, inspection, authentication, object management, signing, verification, derivation, key transfer,
file reads/writes and finalization. One client-owned session per logged-in token
keeps its role active without storing its PIN. Object browsing
opens scoped read-only sessions, or read-write sessions while SO is active, and
reports explicit close failures. The UI receives metadata snapshots and local
resource IDs, without providers, sessions or raw handles. An unchanged token keeps
its ID across module refreshes; a replacement receives a new ID. Object IDs last
for one list snapshot. Details resolve their client locator again in a fresh session.

Request IDs reject cancelled or superseded results. Refresh cancellation ignores
its eventual result. Token/page/object changes invalidate pending reads. Load,
unload, login, logout, management, signing, encryption, key transfer and random-file generation finish before
another operation can start; navigation remains available. Closing the window
drains queued work, closes authentication sessions, finalizes providers and joins
the worker off the UI thread.

Tests cover state transitions, stale responses, picker results, backend errors,
shutdown, lazy details, ambiguous objects, metadata redaction and isolated SoftHSM
module/object/mechanism, USER/SO authentication, object management, signing/verification, AES-GCM, RSA-OAEP, ECDH and RFC 3394 workflows:

```sh
PKCS11_TEST_DESKTOP=1 ./tools/test-softhsm.sh
```

The required PQC provider CI job also runs desktop generation tests for all six
ML-DSA/ML-KEM parameter sets, private-key permissions, authentication settings and
public export without login. Export tests also reject private keys and stale
object IDs, preserve existing files and check Unix file permissions.

## License

This application is available under either [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
