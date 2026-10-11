# pkcs11-desktop

Native PKCS#11 browser and object manager built with Iced and `pkcs11-client`.
Load trusted vendor libraries, inspect module and slot metadata, and view token
identity, initialization, authentication flags and PIN limits. Log in as USER or
SO to browse visible persistent objects. Filter object lists and advertised
mechanisms, then select an entry for metadata details.

## Usage

Choose a module with **Browse**, or enter its file path, then select **Load**.
The sidebar lists loaded modules and their tokens. Select a module for library and
slot information, or a token for its overview and locator.

**Refresh module** re-enumerates the selected module's slots and tokens. Removed or
replaced tokens clear their selection. **Unload** finalizes the selected module;
quitting finalizes all loaded modules.

Select **Objects** to list persistent objects visible to the current role. Filter by
label, class, hexadecimal ID or locator, then select an object to read its metadata.
Listing requests only class, label and ID; detail reads use a small metadata
allowlist and never fetch object values or private key material. Missing,
sensitive and unsupported attributes remain distinguishable. Objects with
duplicate locators or unsupported identities show their summary without a detail
read. **Refresh objects** clears selection and reads a new list.

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
**Refresh mechanisms** to re-enumerate. Bounds retain the provider's units;
the browser does not plan or execute cryptographic operations.

On Linux, the native file picker uses the desktop portal, with a Zenity fallback.
Manual path entry also works when no picker service is available. Modules are
loaded only after an explicit Load action; paths are not saved or loaded on startup.

Use **Operations** to generate a signing key pair or import a certificate. Log in
as USER on a writable token first. Generation offers common RSA sizes and named
EC curves within the client's advertised bounds. Supply a label and nonempty
hexadecimal ID; the public and private keys share them. Private keys are sensitive
and nonextractable. The per-operation authentication option sets
CKA_ALWAYS_AUTHENTICATE. A provider may reject an advertised choice or template;
operations are never retried automatically.

Certificate import accepts one X.509 DER file up to 16 MiB and an explicit label/ID.
It parses certificate metadata without establishing trust or binding the
certificate to a key. PEM, bundles and private-key import are not supported.

On **Objects**, select an unambiguous object and use **Delete object**. Confirm the
shown locator to permanently delete that single object. Related keys and
certificates are kept. **Export public object** saves public certificate/data
values, or RSA/P-256/P-384/P-521 public keys as SPKI DER. Private objects and
private/secret key classes cannot be exported. Export creates a new file and
never overwrites one; a write failure can leave a partial file. On Unix, new
export files are created with permissions 0600.

Management clears selections and refreshes the object list, including after a
failure that might have partial effects. Labels and IDs are not uniqueness
constraints: collisions can produce ambiguous locators. Mutation commands and
export finish before another operation can start; navigation remains available.

To sign a file, log in as USER and select an unambiguous private key on **Objects**.
Choose **Sign file**, select a client-provided SHA-2 signature choice, and provide
a message file and a new signature output path. Token hashing is required by
default; **Allow software hashing** permits a fallback planned before signing.
The displayed mechanism and hashing location are advisory and checked again at
execution. PSS choices use a matching MGF1 digest and digest-length salt.

Keys with CKA_ALWAYS_AUTHENTICATE require a per-operation PIN or supported
protected authentication path. This credential is cleared on submission,
cancellation or navigation. Each submission signs once; failures are never retried.
The worker reserves a new output file before signing. Existing files are preserved;
a failed signature or write can leave an empty or partial file. Signing refreshes
token status and object inventories, including after authentication failures.

Select a supported certificate and choose **Verify signature** to check a message
and signature in software using its public key. Verification does not establish
certificate trust or prove association with a token key. Editing the form or
changing selection invalidates pending verification results.

Message files are limited to 16 MiB and signature inputs to 16 KiB. RSA signatures
use raw modulus-width bytes; EC signatures use fixed-width `r || s`, not ASN.1 DER.
File contents, signature bytes and credentials remain on the worker. Encryption,
decryption, derivation, wrapping, unwrapping and random generation await client APIs.

## Development

Rust 1.88 or newer. Iced 0.14 uses `tiny-skia`, `thread-pool`, `x11` and `wayland`,
with default features disabled.

```sh
cargo run -p pkcs11-desktop --locked
cargo test -p pkcs11-desktop --locked
```

Linux build dependencies on Ubuntu:

```sh
sudo apt-get install pkg-config libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libegl1-mesa-dev
```

## Execution

One worker owns all client providers and performs module loading, discovery,
refresh, inspection, authentication, object management, signing, verification,
file reads/writes and finalization. One client-owned session per logged-in token
keeps its role active without storing its PIN. Object browsing
opens scoped read-only sessions, or read-write sessions while SO is active, and
reports explicit close failures. The UI receives metadata snapshots and local
resource IDs, without providers, sessions or raw handles. An unchanged token keeps
its ID across module refreshes; a replacement receives a new ID. Object IDs last
for one list snapshot. Details resolve their client locator again in a fresh session.

Request IDs reject cancelled or superseded results. Refresh cancellation ignores
its eventual result. Token/page/object changes invalidate pending reads. Load,
unload, login, logout, management and signing finish before another operation can
start; navigation remains available. Closing the window drains queued work, closes
authentication sessions, finalizes providers and joins the worker off the UI thread.

Tests cover state transitions, stale responses, picker results, backend errors,
shutdown, lazy details, ambiguous objects, metadata redaction and isolated SoftHSM
module/object/mechanism, USER/SO authentication, object management and signing/
verification workflows:

```sh
PKCS11_TEST_DESKTOP=1 ./tools/test-softhsm.sh
```

## License

This application is available under either [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
