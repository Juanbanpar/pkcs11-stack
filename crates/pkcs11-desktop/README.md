# pkcs11-desktop

Native Iced application for PKCS#11 token browsing, object management, signing,
verification, encryption and key derivation through `pkcs11-client`.

## Build and run

Rust 1.88 or newer. Linux requires Wayland; X11 is not built. The file picker uses
the desktop portal with a Zenity fallback; manual path entry is also available.

```sh
# Ubuntu build dependencies
sudo apt-get install pkg-config libxkbcommon-dev libwayland-dev libegl1-mesa-dev
cargo run --release -p pkcs11-desktop --locked
```

Iced defaults are disabled; enabled features are `tiny-skia`, `thread-pool`,
`wayland`, `advanced` and `linux-theme-detection`. `iced_aw` enables `badge` and
`spinner`; `iced_fonts` enables the Lucide icon font.

## Navigation and browsing

Choose **Add Module**, browse or enter a trusted library path, then **Load**.
Modules are executable code; loading is explicit and paths are not saved or
loaded on startup. The sidebar lists modules and tokens. Module overviews show
library/slot metadata; token overviews show identity, initialization, authentication
flags and PIN limits. **Show PKCS#11 locator** expands the technical identifier.

| View or control | Behavior |
| --- | --- |
| **Objects** | List visible persistent objects; filter by label, class, hexadecimal ID or locator |
| Object details | Read a metadata allowlist; distinguish missing, sensitive and unsupported attributes; no object values/private key material |
| **Mechanisms** | Filter advertised names, IDs and flags; show provider bounds, family, typed operations and executable-path support |
| Column headings | Sort locally without reading the token |
| Module **Refresh** | Re-enumerate slots/tokens; clear removed or replaced selections |
| Objects **Refresh** | Clear selection and read a new inventory |
| **Unload** / quit | Close sessions and finalize the selected/all modules |
| **Appearance** | System, Light or Dark; System falls back to Light; choice is not saved |

Duplicate locators or unsupported object identities retain summaries without
performing a detail read. Wider windows show list/details side by side; narrower
windows use **Back to List**, returning focus to the selected row. Mechanism
advertisement alone does not imply executable support or parameter acceptance.

| Key | Action |
| --- | --- |
| Tab / Shift+Tab | Move through enabled controls |
| Enter / Space | Activate focused control |
| Arrows / Home / End | Navigate lists, tabs and choices; activate a resource to read details |
| Escape | Close dialog/form |
| Ctrl+O / Ctrl+F | Add Module / focus resource filter |
| Ctrl+R / Ctrl+Q | Refresh / quit |

Use Command instead of Ctrl on macOS.

## Authentication and execution

Choose **USER login** or **SO login**, then submit once. Locked/uninitialized PINs
disable their role; SO also requires writable sessions. Protected-path tokens
default to on-token authentication, with host entry available. **Logout** clears
object selection/details; refresh the inventory after authentication changes.

PINs are zeroizing, excluded from diagnostics and never saved. Masked inputs
disable copying/cutting; forms clear on submission, cancellation or navigation.
Iced's transient text-editing copies cannot be guaranteed zeroized. Protected-path
behavior requires a supporting token and has not been verified on hardware.

One worker owns providers, sessions and file operations. A retained authenticated
session per token keeps the role active without retaining its PIN. Scoped browsing
sessions report explicit close failures. The UI receives metadata and local IDs,
not handles or live providers; details resolve selectors again. Changed selections
invalidate pending reads and picker results.

Submitted mutations and cryptographic/file operations finish before another can
start; navigation remains available. They are not retried or rolled back and cannot
be cancelled after submission. Inventories refresh after success or failure because
changes may have applied. Shutdown drains work, closes sessions and finalizes
providers off the UI thread. If a session cannot close, further operations on that
module are blocked and its cached resources are cleared; unload it before reuse.

## Generation, import and object management

**Operations** opens generation, import and random-byte forms. Key generation and
imports require USER login on a writable token. Choices come from client capability
queries; unsupported choices are omitted and execution checks capabilities again.
An advertised choice does not guarantee provider template acceptance.

| Key family | Choices and permissions |
| --- | --- |
| Classical signing | RSA, P-256/P-384/P-521 signing pairs |
| ML-DSA | ML-DSA-44/65/87 signing pairs |
| EdDSA | Pure Ed25519/Ed448 signing pairs; no per-operation authentication |
| SLH-DSA / HashSLH-DSA | Separate pure and HashSLH-only signing pairs |
| ECDH | P-256/P-384/P-521 derivation-only private keys |
| Montgomery | X25519/X448 agreement pairs |
| ML-KEM | ML-KEM-512/768/1024 encapsulation/decapsulation pairs; no per-operation authentication |
| AES | AES-128/192/256 for encryption/decryption or wrapping/unwrapping |

Private/secret keys are sensitive and nonextractable. Supply a label and hexadecimal
ID; pairs share both. ECDH/AES identity fields require 1–128 bytes, with existing
pair/secret IDs rejected respectively. Classical/ML-DSA and ML-KEM pairs can have duplicate
IDs; all selectors must resolve uniquely. Duplicate checks are not atomic against
concurrent writers. Per-signature authentication is available only where supported
and clears when another purpose is selected.

| Action | Input and result |
| --- | --- |
| Import certificate | One X.509 DER file up to 16 MiB, label and ID; parse metadata without trust/binding; no PEM or bundles |
| Import public key | RSA, named EC, EdDSA or Montgomery SPKI DER; explicit verification or RSA-encryption purpose |
| **Import ML-KEM Public Key** | Validated ML-KEM SPKI DER up to 2048 bytes; 1–128-byte label/ID; parameter set comes from key |
| **Delete object** | Confirm the shown locator; delete one object, retaining related keys/certificates |
| **Export public object** | Raw public certificate/data values or validated RSA/EC/ML-DSA/ML-KEM/SLH-DSA SPKI; no login required |

Imports preserve existing objects. Public-key validation does not establish peer
identity or private-key possession. Private objects and private/secret-key classes
cannot be exported. Related objects are never inferred from shared IDs/labels.

## Signing and verification

On **Objects**, select an unambiguous private key and **Sign file** after USER login.
Supply a message file and new signature output path. Permissions and mechanism
choices are advisory and checked again by the worker.

| Family | Signing profile |
| --- | --- |
| RSA/EC | Client-provided SHA-2 choices; token hashing by default; **Allow software hashing** selects an allowed plan before signing; PSS uses matching MGF1 and digest-length salt |
| ML-DSA | Observed parameter set, original message, required fresh token randomness, optional context up to 255 UTF-8 bytes; no prehash/deterministic fallback |
| EdDSA | Original message; no external digest, domain context or hashing policy |
| SLH-DSA / hash-PQC | Pure SLH-DSA, HashSLH-DSA or HashML-DSA; SHA-256/384/512 message or caller-digest choices and bounded context |

CKA_ALWAYS_AUTHENTICATE keys require a separate per-operation PIN/protected-path
submission where supported. RSA signatures are modulus-width; ECDSA is fixed-width
`r || s`, without ASN.1 DER. PQC files are raw signatures without context/metadata;
retain the exact domain context for verification.

Select a classical, ML-DSA or EdDSA certificate and **Verify signature** for software
verification. Public-key verification uses the selected token key, including
SLH-DSA/hash-PQC. Certificate verification needs no login for a visible public
certificate and makes no trust or key-association decision. Input files are read
without modification. Editing parameters or changing selection invalidates results.
Messages are limited to 16 MiB and signature inputs to 64 KiB.

## Encryption

| Action on selected key | Profile |
| --- | --- |
| **Encrypt AES-GCM** / **Decrypt AES-GCM** | USER login; AES secret key; exactly 24 hexadecimal nonce digits, optional AAD file, input and new output path |
| **Encrypt RSA OAEP** | Public RSA key; client-provided SHA-2 digest and payload limits |
| **Decrypt RSA OAEP** | USER login; private RSA key without per-operation authentication |

GCM uses ciphertext followed by a full 16-byte tag; retain the separate nonce/AAD
for decryption. Plaintext is limited to 16 MiB and AAD to 1 MiB; empty input and
absent AAD are accepted. Wrapping-only keys cannot encrypt/decrypt.

**Never repeat a GCM nonce for the same key**, across applications, restarts or key
copies. Use a new nonce after an encryption error. The app does not generate/track
nonces or define an envelope format. Decryption releases no plaintext before
successful authentication and checked session closure.

OAEP uses matching SHA-2/MGF1 digests and an empty label, producing one raw RSA
block. Choose the same digest for decryption. This handles small payloads, not bulk
files or sender authentication; provider rejection never causes a padding downgrade.

## Derivation and key transfer

After USER login on a writable token, select the base/public/private key on
**Objects**. New secret identities require 1–128-byte labels and hexadecimal IDs;
existing secret IDs are rejected. Derived secrets remain private, sensitive and
nonextractable on the token. Authenticate peers separately and agree on protocol
inputs; successful derivation alone does not establish peer identity.

| Action | Input and output |
| --- | --- |
| **Encapsulate ML-KEM secret** | ML-KEM public key; new secret identity and ciphertext output path |
| **Decapsulate ML-KEM secret** | Matching private key and ciphertext file; new secret identity |
| **Derive HKDF key** | Generic/HKDF derivation base; AES encryption key or further derivation secret |
| **Derive ECDH secret** | Derivation-enabled EC private key and validated same-curve SPKI peer; raw null-KDF generic secret |
| Montgomery agreement | X25519/X448 private key, raw/SPKI peer, X9.63/SP 800-56A KDF, shared info and AES/derivation-secret output |
| **Wrap AES key** | AES CKA_WRAP key, extractable AES-128/192/256 target, new output path; honor CKA_WRAP_WITH_TRUSTED |
| **Unwrap AES key** | AES CKA_UNWRAP key, 24/32/40-byte RFC 3394 file; AES encryption/decryption key |

ML-KEM creates a 32-byte derivation-only generic secret and writes only public
ciphertext. Input lengths are 768/1088/1568 bytes for ML-KEM-512/768/1024. Implicit
rejection can accept altered same-length ciphertext and produce a different secret;
completion does not confirm agreement. Apply a protocol KDF before use.
Always-authenticate decapsulation is unsupported. Use the client/CLI for hybrid
combining; it is not exposed here.

HKDF requires a hash-length, sensitive, nonextractable derivation base: SHA-1/224/
256/384/512 for 20/28/32/48/64 bytes respectively. Values are never padded/truncated.
Choose AES-128/192/256 or a derivation secret of 1–255 times the hash length. Salt
is hexadecimal and context UTF-8, each up to 4096 bytes; empty salt means zero salt.
HKDF is extract-and-expand, without a file output, hybrid combiner or TLS schedule.

Raw ECDH supports P-256/P-384/P-521 and needs a subsequent KDF compatible with the
base length. Per-operation-authenticated base keys are unsupported. RFC 3394 uses
the default IV and carries no metadata; wrapping does not change extractability
or trust policy. Failed creation/cleanup can leave objects; inspect the inventory
before submitting another operation.

## Random bytes and file output

**Generate token random bytes** requires an initialized token advertising RNG
support. Request 1–1048576 bytes and a new path. The provider may require USER
login; no automatic login, software fallback or seeding is added.

All output files are created exclusively with Unix mode 0600; existing files are
preserved. Crypto/random output follows checked session closure. Failures can leave
empty or partial files, and token mutations may already have occurred. Export write
failures can also leave partial files. File contents and credentials remain on the
worker. Random output, encryption inputs and plaintext use zeroizing storage;
cryptoki's failed-call temporary buffers cannot be guaranteed zeroized.

## Administration

Select **Administration** on a writable token. Review the module path, slot, token
identity and role before submitting.

| Action | Requirements and effects |
| --- | --- |
| **Initialize / erase token** | Establish label/SO PIN for a new token, or use current SO PIN to erase objects/reset USER PIN state; type `ERASE` |
| **Initialize / reset USER PIN** | SO login, new PIN and confirmation; type `CHANGE` |
| **Change current role's PIN** | USER/SO login, current PIN, new PIN and confirmation; type `CHANGE` |

Initialization closes all app sessions for the module and rechecks captured token
identity, initialized state and PIN bounds. Identical replacements or swaps after
the check cannot be detected; ensure exclusive physical access. Refresh/select the
resulting token before initializing USER PIN.

Administration accepts host PINs only. Protected-path/read-only tokens and locked
roles are disabled, except first SO PIN establishment on an uninitialized token.
Available byte bounds are checked. PIN changes close this app's authenticated
session on success or failure; log in again with the applicable PIN. Forms clear on
submission, cancellation, navigation and shutdown; role/target changes invalidate
confirmation. Failed calls may still apply changes and are not retried.

## Tests

```sh
cargo test -p pkcs11-desktop --locked
```

The [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md) covers headless worker tests and disposable
SoftHSM/Kryoptic suites for management, classical/PQC cryptography, authentication,
file preservation and stale UI responses. Provider tests do not establish hardware
compatibility.

## License

[MIT](https://github.com/Juanbanpar/pkcs11-stack/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Juanbanpar/pkcs11-stack/blob/main/LICENSE-APACHE), at your option.
