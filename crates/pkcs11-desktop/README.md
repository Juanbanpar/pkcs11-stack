# pkcs11-desktop

A native Iced app for inspecting PKCS#11 tokens and working with individual keys
and certificates. Use it to see what a device supports, provision objects, or
sign and verify files interactively.

- Browse token information, object metadata, and advertised mechanisms.
- Generate signing, agreement, and AES keys. Import certificates and public keys,
  export public objects, or delete selected objects.
- Sign and verify files, encrypt and decrypt, derive secrets, wrap and unwrap
  AES keys, and generate random bytes. Actions depend on the token and key.
- Initialize or erase a token and manage USER and security officer (SO) PINs
  through explicit confirmation dialogs.

## Build and run

Use Rust 1.88 or newer. Linux requires Wayland. The file picker uses the desktop
portal with a Zenity fallback. You can also enter paths manually.

```sh
# Ubuntu build dependencies
sudo apt-get install pkg-config libxkbcommon-dev libwayland-dev libegl1-mesa-dev
cargo run --release -p pkcs11-desktop --locked
```

| Dependency | Enabled features |
| --- | --- |
| Iced | `tiny-skia`, `thread-pool`, `wayland`, `advanced`, `linux-theme-detection`. Default features are disabled |
| `iced_aw` | `badge` and `spinner` |
| `iced_fonts` | Lucide icon font |

## Navigation and browsing

1. Choose **Add Module**, select a trusted PKCS#11 library, and choose **Load**.
   Modules are executable code. Load them explicitly after each launch.
2. Select a module for library and slot metadata, or a token for its identity,
   initialization state, authentication flags, and PIN limits.
3. Expand **Show PKCS#11 locator** to copy the URI.

| View or control | Behavior |
| --- | --- |
| **Objects** | List visible persistent objects. Filter by label, class, hexadecimal ID or locator |
| Object details | Read a metadata allowlist. Distinguish missing, sensitive and unsupported attributes. No object values/private key material |
| **Mechanisms** | Filter advertised names, IDs and flags. Show provider bounds, family, typed operations and executable-path support |
| Column headings | Sort locally without reading the token |
| Module **Refresh** | Re-enumerate slots/tokens. Clear removed or replaced selections |
| Objects **Refresh** | Clear selection and read a new inventory |
| **Unload** / quit | Close sessions and finalize the selected/all modules |
| **Appearance** | System, Light or Dark. System falls back to Light. Choice is not saved |

- Ambiguous or unsupported locators show object summaries only.
- Wide windows show the list and details together. In a narrow window, use
  **Back to List** to return focus to the selected row.
- Mechanism listings describe advertised support. The provider checks parameters
  when an operation runs.

| Key | Action |
| --- | --- |
| Tab / Shift+Tab | Move through enabled controls |
| Enter / Space | Activate focused control |
| Arrows / Home / End | Navigate lists, tabs and choices. Activate a resource to read details |
| Escape | Close dialog/form |
| Ctrl+O / Ctrl+F | Add Module / focus resource filter |
| Ctrl+R / Ctrl+Q | Refresh / quit |

Use Command instead of Ctrl on macOS.

## Authentication and execution

| Area | Behavior |
| --- | --- |
| Roles | USER for private objects and user operations. SO requires a writable token. Locked or uninitialized PINs disable their role |
| Protected path | Defaults to device authentication where supported, with host entry available. Hardware behavior has not been verified |
| PIN handling | Masked fields disable copying and cutting and clear on submission, cancellation, or navigation. PINs use zeroizing storage and stay out of diagnostics. Iced's transient editor copies may escape zeroization |
| Login state | One session per token preserves the active role without retaining the PIN. **Logout** clears the selection and details. Refresh **Objects** after login or logout |
| Worker | Owns providers, sessions, and file operations. The UI receives metadata and local IDs. Selection changes invalidate pending reads and picker results |
| Operations | Submitted work finishes before another operation starts. Navigation stays available. No cancellation, retry, or rollback after submission |
| Recovery | Inventory refreshes after success or failure. Inspect it before retrying a mutation. A session close failure blocks the module and clears cached resources. Unload it before reuse |
| Shutdown | Drains work, closes sessions, and finalizes modules off the UI thread |

## Generation, import and object management

Open **Operations** to generate keys, import objects, or request random bytes.
Generation and import require USER login on a writable token. Available choices
depend on the token. The provider checks the selected parameters at execution.

| Key family | Choices and permissions |
| --- | --- |
| Classical signing | RSA, P-256/P-384/P-521 signing pairs |
| ML-DSA | ML-DSA-44/65/87 signing pairs |
| EdDSA | Pure Ed25519/Ed448 signing pairs. No per-operation authentication |
| SLH-DSA / HashSLH-DSA | Separate pure and HashSLH-only signing pairs |
| ECDH | P-256/P-384/P-521 derivation-only private keys |
| Montgomery | X25519/X448 agreement pairs |
| ML-KEM | ML-KEM-512/768/1024 encapsulation/decapsulation pairs. No per-operation authentication |
| AES | AES-128/192/256 for encryption/decryption or wrapping/unwrapping |

- **Key protection**. Generated private and secret keys are sensitive and nonextractable.
- **Identity**. Both keys in a pair share a label and hexadecimal ID. ECDH and AES
  identity fields require 1–128 bytes. They check for existing pair or secret
  IDs respectively. Other pairs can share IDs, and concurrent writers can race
  duplicate checks. Every selector must resolve uniquely.
- **Always authenticate**. Available for supported key types. Changing the key
  purpose clears the option.

| Action | Input and result |
| --- | --- |
| Import certificate | One X.509 DER file up to 16 MiB, label and ID. Parse metadata without trust/binding. No PEM or bundles |
| Import public key | RSA, named EC, EdDSA or Montgomery SPKI DER. Explicit verification or RSA-encryption purpose |
| **Import ML-KEM Public Key** | Validated ML-KEM SPKI DER up to 2048 bytes. 1–128-byte label/ID. Parameter set comes from key |
| **Delete object** | Confirm the shown locator. Delete one object, retaining related keys/certificates |
| **Export public object** | Raw public certificate/data values or validated RSA/EC/ML-DSA/ML-KEM/SLH-DSA SPKI. No login required |

- Import preserves existing objects. Public-key validation checks the encoding.
  Verify peer identity or private-key possession separately.
- Delete affects one selected object. Related objects are kept even when IDs or labels match.

## Signing and verification

On **Objects**, select an unambiguous private key and **Sign file** after USER login.
Supply a message file and a new signature output path.

| Family | Signing profile |
| --- | --- |
| RSA/EC | Client-provided SHA-2 choices. Token hashing by default. **Allow software hashing** selects an allowed plan before signing. PSS uses matching MGF1 and digest-length salt |
| ML-DSA | Observed parameter set, original message, required fresh token randomness, optional context up to 255 UTF-8 bytes. No prehash/deterministic fallback |
| EdDSA | Original message. No external digest, domain context or hashing policy |
| SLH-DSA / hash-PQC | Pure SLH-DSA, HashSLH-DSA or HashML-DSA. SHA-256/384/512 message or caller-digest choices and bounded context |

CKA_ALWAYS_AUTHENTICATE keys require a separate per-operation PIN/protected-path
submission where supported. RSA signatures are modulus-width bytes and ECDSA
signatures use raw fixed-width `r || s`. Keep signing parameters and any domain
context separately for verification.

| Verification | How it works |
| --- | --- |
| Certificate | Select an RSA, EC, ML-DSA, or EdDSA certificate and choose **Verify signature**. Software verification can use a visible public certificate without login. Check trust and key association separately |
| Token public key | Select a public key for token verification, including SLH-DSA and hash-PQC |
| Files and results | Messages up to 16 MiB and signature inputs up to 64 KiB. The app preserves inputs. Changing the selection or parameters invalidates results |

## Encryption

| Action on selected key | Profile |
| --- | --- |
| **Encrypt AES-GCM** / **Decrypt AES-GCM** | USER login. AES secret key. Exactly 24 hexadecimal nonce digits, optional AAD file, input and new output path |
| **Encrypt RSA OAEP** | Public RSA key. Client-provided SHA-2 digest and payload limits |
| **Decrypt RSA OAEP** | USER login. Private RSA key without per-operation authentication |

- **AES-GCM format**. Ciphertext followed by a 16-byte tag. Keep the nonce and
  AAD separately. Plaintext is limited to 16 MiB and AAD to 1 MiB. Both may be
  empty. Use an AES key with encryption or decryption permission.
- **AES-GCM nonce**. Never repeat a nonce for the same key across applications,
  restarts, or key copies, including after an encryption error. The caller
  generates and tracks the nonce and defines any file envelope.
- **AES-GCM decryption**. Releases plaintext only after authentication and
  checked session closure.
- **RSA-OAEP**. Uses matching SHA-2 and MGF1 digests and an empty label. Use for
  small payloads, producing one raw RSA block. Use the same digest for decryption
  and authenticate the sender separately. Provider failure preserves the padding
  policy.

## Derivation and key transfer

After USER login on a writable token, select the base/public/private key on
**Objects**. Supply a new hexadecimal ID and label, each 1–128 bytes. Derived
secrets remain private, sensitive, and nonextractable on the token. Agree on
protocol inputs and authenticate peers separately.

| Action | Input and output |
| --- | --- |
| **Encapsulate ML-KEM secret** | ML-KEM public key. New secret identity and ciphertext output path |
| **Decapsulate ML-KEM secret** | Matching private key and ciphertext file. New secret identity |
| **Derive HKDF key** | Generic/HKDF derivation base. AES encryption key or further derivation secret |
| **Derive ECDH secret** | Derivation-enabled EC private key and validated same-curve SPKI peer. Raw null-KDF generic secret |
| Montgomery agreement | X25519/X448 private key, raw/SPKI peer, X9.63/SP 800-56A KDF, shared info and AES/derivation-secret output |
| **Wrap AES key** | AES CKA_WRAP key, extractable AES-128/192/256 target, new output path. Honor CKA_WRAP_WITH_TRUSTED |
| **Unwrap AES key** | AES CKA_UNWRAP key, 24/32/40-byte RFC 3394 file. AES encryption/decryption key |

| Profile | Details |
| --- | --- |
| ML-KEM | Creates a 32-byte derivation-only generic secret and writes public ciphertext. Ciphertext is 768/1088/1568 bytes for ML-KEM-512/768/1024. Decapsulation requires a key without per-operation authentication |
| ML-KEM agreement | Implicit rejection can yield a different secret for altered same-length ciphertext without an error. Confirm agreement and apply a protocol KDF. Use the client or CLI for application hybrid derivation |
| HKDF base | Sensitive, nonextractable derivation base matching the hash length exactly. SHA-1/224/256/384/512 require 20/28/32/48/64 bytes respectively |
| HKDF output | Extract-and-expand into a token object. AES-128/192/256 or a derivation secret of 1–255 times the hash length. Hexadecimal salt and UTF-8 context are each limited to 4096 bytes. Empty salt means zero salt |
| Raw ECDH | Supports P-256/P-384/P-521 and needs a subsequent KDF compatible with the base length. Requires a base key without per-operation authentication |
| RFC 3394 | Default IV, raw bytes without metadata. Target extractability and trust rules still apply |

A failed creation or cleanup can leave objects. Inspect the inventory before
submitting another operation.

## Random bytes and file output

**Generate token random bytes** requires an initialized token advertising RNG
support. Request 1–1048576 bytes and a new path. Log in as USER if required
by the provider. The token supplies the bytes without software fallback or seeding.

| Area | Contract |
| --- | --- |
| Output paths | New files only. Unix mode 0600. A failure can leave an empty or partial new file, including on export |
| Cleanup | Cryptographic and random output follows checked session closure. A write or cleanup error can follow changes to the token |
| Sensitive buffers | File contents and credentials stay on the worker. Random output, encryption inputs, and plaintext use zeroizing storage. Failed cryptoki calls can leave temporary buffers unwiped |

## Administration

Select **Administration** on a writable token. Review the module path, slot, token
identity and role before submitting.

| Action | Requirements and effects |
| --- | --- |
| **Initialize / erase token** | Establish label/SO PIN for a new token, or use current SO PIN to erase objects/reset USER PIN state. Type `ERASE` |
| **Initialize / reset USER PIN** | SO login, new PIN and confirmation. Type `CHANGE` |
| **Change current role's PIN** | USER/SO login, current PIN, new PIN and confirmation. Type `CHANGE` |

- **Initialize**. The app closes all its sessions for the module and rechecks
  token identity, initialization state, and PIN bounds. Keep exclusive physical
  access because the check can miss identical replacements and later swaps.
  Refresh and select the token again before initializing the USER PIN.
- **PIN entry**. Administration uses host PINs. Read-only or protected-path
  tokens and locked roles are disabled, with an exception for first SO PIN
  establishment on an uninitialized token.
- **PIN changes**. Log in again after success or failure. Forms clear on
  submission, cancellation, navigation, or shutdown. Changing the role or
  target invalidates confirmation.

See the [desktop operation matrix](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/oasis-compatibility.md#application-surfaces).

## Tests

```sh
cargo test -p pkcs11-desktop --locked
```

| Suite | Coverage |
| --- | --- |
| Headless UI and worker tests | Navigation, stale responses, authentication state, and file preservation |
| SoftHSM and Kryoptic | Token management, authentication, file operations, and classical and post-quantum cryptography with disposable token stores |

See the [test guide](https://github.com/Juanbanpar/pkcs11-stack/blob/main/tests/README.md) for provider setup and commands. Use vendor modules and devices to validate hardware compatibility.

## License

[MIT](https://github.com/Juanbanpar/pkcs11-stack/blob/main/LICENSE-MIT) OR [Apache-2.0](https://github.com/Juanbanpar/pkcs11-stack/blob/main/LICENSE-APACHE), at your option.
