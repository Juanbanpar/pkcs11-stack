# pkcs11-desktop

Native PKCS#11 browser and object manager built with Iced and `pkcs11-client`.
Load trusted vendor libraries, inspect module and slot metadata, and view token
identity, initialization, authentication flags and PIN limits. Log in as USER or
SO to browse visible persistent objects. Filter object lists and advertised
mechanisms, then select an entry for metadata details.

Unknown classes remain in the object list with their numeric IDs. Unknown key and
certificate types appear numerically in details. Classes without an RFC 7512
object type have no selectable locator; unfamiliar key types offer no crypto actions.

Browsing reads bounded class/label/ID summaries and public metadata snapshots for
profile and validation objects. Those entries have no object locator or key
actions. Other objects read unique IDs, SPKI size and validation flags in their
selected details. Optional fields retain available/empty, sensitive, unsupported
and unavailable states. Each public attribute is limited to 65,536 bytes. Validation
URIs are plain metadata and are not opened or fetched. These provider reports do
not establish certification or trust; unique IDs do not replace object selectors.

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

Use **Operations** to choose key generation, public object import, file hashing
or random generation. Each task opens its own form. Key generation and public
object import require USER login on a writable token. Generation uses the client's shared
capability query to offer RSA/EC and ML-DSA-44/65/87 signing pairs,
ML-KEM-512/768/1024 encapsulation/decapsulation pairs, P-256/P-384/P-521 ECDH pairs
and AES-128/192/256 keys. Unsupported choices are omitted. Each choice names its
purpose. ECDH private keys permit only derivation; AES keys permit either
encryption/decryption, wrapping/unwrapping or AES-CMAC authentication.
Private and secret keys are sensitive and nonextractable. Per-operation
authentication is available for signing and RSA decryption keys; the control
clears when a purpose without that support is selected. A provider may reject an advertised choice or template; operations
are never retried automatically.

Supply a label and hexadecimal ID. ECDH/AES identity fields each require 1–128
bytes. Existing public/private IDs are rejected for ECDH pairs, and secret IDs for
AES, without a uniqueness guarantee against concurrent writers. Signing pairs
and ML-KEM pairs permit duplicate IDs; ambiguous selectors are rejected. Key
pairs share their ID and label. ML-KEM does not permit per-operation PIN
authentication.

Use **Import RSA/EC Public Key** for one SPKI DER file up to 4096 bytes.
Choose signature verification or RSA encryption explicitly and supply a label
and hexadecimal ID of 1–128 bytes each. RSA sizes are 2048–16384 bits; named
curves are P-256/P-384/P-521. Invalid components/points, restricted RSA-PSS keys
and unsupported curves are rejected. RSA parameters and EC points normalize to
the client export representation. Wrapping, recovery and derivation are disabled;
existing public-key IDs are rejected. Private/certificate objects sharing the ID
are not changed or bound. Authenticate the key's owner separately.

Use **Import ML-KEM Public Key** on **Operations** for one ML-KEM-512/768/1024
SPKI DER file up to 2048 bytes. The parameter set comes from the encoded key;
the client rejects other algorithms and noncanonical encodings. Supply a label
of 1–128 UTF-8 bytes and an ID of 1–128 hexadecimal bytes. USER login and a
writable token are required. Import preserves existing objects; duplicate IDs
can make selection ambiguous. Authenticate the peer separately: parsing does
not prove identity or private-key possession. Export from **Objects** uses the
same SPKI format.

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
AES offers GCM and wrapping, and ML-KEM offers encapsulation or decapsulation
according to the object class. Generic/HKDF secrets offer HKDF derivation.
Permissions and provider capabilities are checked again in the worker.

To sign a file, log in as USER and select an unambiguous private key on **Objects**.
SHA-224 signature choices follow SHA-256/384/512 when the key and hashing policy
permit them. Existing choices retain their order; OAEP and KDF options are unchanged.

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
choices display SHA-2 digest and byte limits. MGF1 defaults to the OAEP digest;
it can independently use SHA-256/384/512. The optional hexadecimal label holds
up to 4096 binary bytes. Output is one raw RSA block, with no header. Supply the
same digests and label when decrypting. This handles small payloads, not bulk files
or sender authentication.

Permissions, allowed mechanisms and bounds are checked again at execution.
Always-authenticate keys require a separate per-operation PIN or protected
path. Changing the cipher choice, MGF1 digest or label, or leaving the form,
clears the credential.
Vendor digest-parameter rejection never causes a retry, SHA-1 fallback or padding
downgrade. Input and plaintext buffers, including failed decryption output, use
zeroizing storage.

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

After USER login on a writable token, select an ML-KEM public key and choose
**Encapsulate ML-KEM secret**. Enter a new secret label, hexadecimal ID and
ciphertext output path. To receive a ciphertext, select the corresponding ML-KEM
private key and choose **Decapsulate ML-KEM secret**, then provide the ciphertext
file and a new secret label/ID. The key determines ML-KEM-512/768/1024; the worker
checks its current parameter set, permissions and provider capabilities before use.

Both operations create a persistent private, sensitive, nonextractable 32-byte
generic secret with derivation permission only. Labels and IDs require 1–128
bytes; existing secret IDs are rejected. Shared-secret bytes never leave the
token. Encapsulation writes only raw public ciphertext, after checked session
closure, to a new file. Decapsulation requires exactly 768, 1088 or 1568 bytes
for ML-KEM-512, 768 or 1024 respectively and reads the input without modification.
ML-KEM implicit rejection can accept a changed ciphertext of the correct length
and produce a different secret. Completion does not confirm agreement or
peer identity. Always-authenticate decapsulation keys are unsupported.

Authenticate the peer and apply the protocol's KDF before using a raw secret.
Use the client or CLI for hybrid KEM workflows; these are not exposed in the
desktop. Failed encapsulation, session closure or
output writes may leave a token object and an empty or partial ciphertext file.
Existing files are preserved. Refresh the inventory before retrying.

Select a generic/HKDF secret on **Objects** and choose **Derive HKDF key**. The
client discovers a permitted SHA-2 profile: 32-byte bases use SHA-256, 48-byte
bases SHA-384 and 64-byte bases SHA-512. Other lengths have no profile; values
are never truncated or padded. The base must be sensitive, nonextractable and
permit derivation. USER login on a writable token is required.

The stage selector defaults to **Extract and expand**. **Extract PRK only**
creates a hash-length derivation secret and hides the context and output controls.
Select that secret for **Expand PRK only**, which hides both salt fields. Switching
stages clears parameters for the disabled stage; submitted requests reject any
nonempty disabled input. Expansion assumes the base is a PRK established by the
caller; matching key metadata cannot prove its origin.

For expansion, choose AES-128/192/256 for encryption/decryption, or a generic
secret for further derivation with a length from 1 through 255 times the hash length. Outputs are
persistent, private, sensitive and nonextractable. The provider may reject a
specific output template. Provide a new label/ID of 1–128 bytes each; duplicate
secret IDs are rejected. Supply public salt in hexadecimal or a salt-key
PKCS#11 URI from the same token. Supplying both is rejected. Salt keys must be
sensitive, nonextractable generic/HKDF secrets of 1–4096 bytes with derivation
permission and permitted HKDF use. The worker resolves them again; their values
stay on the token. Public salt and UTF-8 protocol context are each limited to
4096 bytes. With neither salt source, RFC 5869 zero salt is used. Agree on exact
protocol inputs and output parameters with the peer; HKDF does not establish peer identity and this form is not a hybrid combiner or TLS
key schedule. Base and output values remain on the token; there is no output
file or software fallback.

**Operations → Hash File on Token** reads advertised multipart digest choices.
Select a SHA-2 or SHA-3 algorithm and an input file. The worker streams it in
64 KiB chunks, checks session closure, then displays the hexadecimal digest.
Empty input is supported. No key, output file or software hash fallback is used.
Input buffers zeroize on return. Read/native failures display no digest and
close the failed session. Normal token login may be required by the provider.
Changing token, task or input clears the previous digest and stale file pickers.

After USER login, select an EC private key with derivation permission and choose
**Derive ECDH secret**. Supply a peer public key in SPKI DER, a new label and a
hexadecimal ID. The client validates the peer point and requires the same named
curve as the base key. P-256/P-384/P-521 offer an explicit null KDF, or ANSI
X9.63 and NIST SP 800-56A with SHA-256/384/512. The null KDF preserves the full
raw secret, including 66 bytes on P-521, with derivation permission only; apply
a protocol KDF before cryptographic use. SHA-2 KDFs accept up to 4096 bytes of
public UTF-8 shared info and create an AES encryption/decryption key or a generic
derivation secret of an explicit length. A 64-byte generic output can feed
HKDF-SHA512. These are persistent private, sensitive, nonextractable keys.
Authenticate the peer separately. Individual KDF support is checked by the token
on submission, with no parameter downgrade or software fallback.
Per-operation-authentication base keys are unsupported.

Select an AES key with wrapping permission and choose **Wrap AES key**. Select
another secret key as the target and a new output file. The client requires an
extractable AES-128/192/256 target and honors CKA_WRAP_WITH_TRUSTED. Candidates
are checked on submission; the app never changes a key's extractability or trust
policy. Select AES-KW (RFC 3394) or AES-KWP (RFC 5649) from the permitted choices.
KW remains the default when available. Both use standard default IVs; KWP has
its own mechanism and never substitutes deprecated `AES_KEY_WRAP_PAD`.
Wrapped output contains no algorithm identifier or object
metadata. Files are never overwritten; a failed operation may leave an empty or
partial file.

Choose **Unwrap AES key** on an AES key with unwrapping permission, select a
24/32/40-byte wrapped file, select the algorithm used for wrapping, and provide
a new label and hexadecimal ID. It creates
an AES-128/192/256 token key with encryption/decryption permission only. The key
is private, sensitive and nonextractable. Existing secret key IDs are rejected.
Unwrapping and derivation require a writable token. Generate ECDH and AES wrapping
keys from **Operations** when the provider advertises those choices.

All key operations execute once on the worker and refresh inventories on
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
./tools/test-softhsm.sh
```

The workspace [default test suite](../../tests/README.md) includes desktop tests
without opt-in flags. Required ML-DSA and ML-KEM provider jobs cover all six
ML-DSA/ML-KEM parameter sets, private-key permissions, authentication settings and
public export without login. ML-KEM operation tests cover ciphertext lengths,
implicit rejection, derivation-only secret permissions, duplicate IDs, authentication
and file preservation. Import tests check bounded SPKI files, authentication,
round-trip export and ambiguous duplicate IDs. Export tests also reject private keys and stale
object IDs, preserve existing files and check Unix file permissions.

The Kryoptic CI job also runs the desktop flow from public-key export/import
through ML-KEM and HKDF to AES-GCM, for all three ML-KEM parameter sets, all AES
output sizes and further derivation using SHA-384/SHA-512. It checks output
permissions, duplicate IDs, login requirements and stale references. Run it with
a trusted provider supporting persistent ML-KEM, HKDF and AES-GCM:

```sh
PKCS11_TEST_KDF_MODULE=/path/to/libkryoptic_pkcs11.so ./tools/test-kem-hkdf.sh
```

Generation choices also include RSA encryption/decryption pairs. They disable
signing, wrapping and derivation, and keep private keys sensitive/nonextractable.
The per-operation authentication option applies to their private decryption key.
Public export and RSA-OAEP workflows use these generated keys directly.

## License

This application is available under either [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.

RSA and EC public-key objects offer **Verify on token**. Choices come from native
verification permissions and capabilities; software hashing requires the form's
explicit opt-in. Certificate objects retain their software verification workflow.

## AES-CMAC

Generate an AES key with the **AES-CMAC authentication** purpose, then select the
secret on **Objects** and choose **Create AES-CMAC** or **Verify AES-CMAC**. The
key must be sensitive and nonextractable, with the appropriate signing or
verification permission. Generated authentication keys permit only CKM_AES_CMAC.
USER login is required; these operations also work on write-protected tokens.

Select a message file (empty through 16 MiB) and a new tag output file for creation,
or an existing raw 16-byte tag for verification. The worker rechecks capabilities
and writes a generated tag after checked session closure. Existing outputs are
preserved. A mismatch is reported separately from a provider failure. No key values or software MACs are exposed. A shared-key MAC does not identify
an individual signer.

For general tags, generate an **AES-CMAC general authentication** key. This
purpose is offered only for sizes with advertised generator and general-CMAC
support. These keys permit only the general mechanism and MAC operations;
existing authentication keys retain their full-tag restriction.

The MAC form offers the permitted tag profiles. General tags range from 8 to
16 bytes, defaulting to 16 when the full profile is unavailable. Select the
agreed length before use and keep it fixed for that key's lifetime. The worker
checks the exact tag length, permissions and native profile again. It generates
and verifies general tags directly on the token, without software truncation,
profile substitution or retry. Stale profile edits are discarded.

## SP 800-108 KDF

Select a generic or SHA-256/384/512 HMAC secret on **Objects**, then choose
**Derive SP 800-108 key…**. USER login and a writable token are required. The
base must be sensitive, nonextractable, 16–4096 bytes and permit native
derivation. The form offers compatible HMAC hashes and rechecks the selected
key's capabilities before execution.

Select **Counter** or **Feedback** from the available mode profiles. Counter is
selected when available. Feedback also offers a public hexadecimal IV, empty or
32/48/64 bytes matching the hash. It prepends the previous PRF output before the
counter; the supplied IV provides the initial bytes. Omission supplies none.
Changing modes clears the IV. Each mode checks its own native support, and a
rejected mode is never replaced by another.

Choose AES-128/192/256 for encryption/decryption, or a generic derivation secret
of 1–4096 bytes. Enter a new object ID and label. Separate KDF label and context
fields contain public UTF-8 protocol inputs, each at most 4096 bytes; empty inputs
are permitted. The object label does not enter the KDF. Counter mode uses
`[i]_32 || label || 0x00 || context || [L]_32`, with big-endian integers and L in
bits. Agree on unambiguous protocol encodings and authenticate peers separately.

Outputs remain private, sensitive and nonextractable on the token. Capability
inspection is advisory; native rejection never changes parameters or retries.
A failed native call may leave an object; refresh before deciding how to proceed.

## HMAC

Generate an HMAC authentication key using SHA-224/256/384/512, SHA-512/224,
SHA-512/256 or SHA3-224/256/384/512, then choose **Create HMAC** or **Verify HMAC** on its object. Generated keys are
hash-length generic secrets, private, sensitive, nonextractable and restricted
to the selected HMAC. Other operations and context authentication are disabled.
Generation requires USER login and a writable token.

Existing generic or matching hash-specific HMAC secrets also qualify if they are
sensitive, nonextractable, 16–4096 bytes long and permit the requested direction.
The algorithm selector lists only currently permitted profiles and preserves the
explicit choice. It does not change to another algorithm on rejection.
The tag-profile selector offers full and native general tags independently.
General lengths range from half the hash output through its full length (14–28,
16–32, 24–48 or 32–64 bytes). Changing the hash resets an incompatible tag length
to the first permitted profile. Agree on one algorithm and length per key before
communicating; the token does not encode this length in key attributes.
Generation choices distinguish full-tag and general-tag authentication keys and
restrict each key to its selected mechanism. Existing keys retain their restrictions.

Select a message file (empty through 16 MiB) and a new tag output path, or an
existing exact selected-length tag file for verification. Full tags are 28/32/48/64 bytes according to the selected hash.
The worker rechecks support and releases generated output after checked session
closure. Existing outputs are preserved. Verification mismatches are separate
from provider failures. These operations require USER login and also work on
write-protected tokens. There is no software truncation, software MAC or retry.
