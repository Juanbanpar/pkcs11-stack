# pkcs11ctl

PKCS#11 inspection, signing, verification, random generation and administration
through `pkcs11-client`.

## Invocation

```sh
pkcs11ctl --module /absolute/path/to/trusted-pkcs11.so tokens
pkcs11ctl --module /absolute/path/to/trusted-pkcs11.so --format json info
pkcs11ctl sign --help
```

`--module` explicitly chooses trusted executable vendor code; a URI never loads a
library. `--module` and `--format text|json` may appear before or after a command.
Help/version and verification with `--certificate-file` need no module.

Use stable token serials and binary object IDs where possible. Token URI criteria
are checked in full. Object operations require stable token/object constraints;
unknown constraints, PIN queries and persistent slot IDs are rejected. Selection
returns an error for zero or multiple matches. Listed URIs are selectors, not a
promise of uniqueness: duplicate IDs/labels remain ambiguous. Empty labels and IDs
remain explicit empty URI criteria. Key selectors require `type=private`;
certificate selectors require `type=cert`. These are checked before loading the
module. Slot IDs are only
for current discovery and explicit initialization.

## Commands

| Command | Purpose |
| --- | --- |
| `info`, `slots`, `tokens` | Library, slot and token metadata; tokens include stable URI criteria |
| `mechanisms --token URI` | Advertised flags and provider key-size bounds |
| `generation-options --token URI` | Advisory signing, ECDH, AES and PQC generation choices; no login |
| `objects --token URI` | Persistent object summaries; no secret values |
| `public-metadata --token URI` | Bounded public metadata, including profile/validation objects |
| `session-validation --token URI` | Provider-reported validation flags in a fresh session |
| `inspect --object URI` | Unique object's attributes, defaulting to class/label/ID |
| `template-metadata --object URI --template wrap\|unwrap\|derive` | Bounded template structure without leaf values |
| `export --object URI --output PATH` | Raw certificate/data CKA_VALUE or public-key SPKI DER |
| `certificate --object URI` | Supported certificate key summary and SPKI through client |
| `capabilities --key URI` | Signing capabilities and available public key metadata |
| `plan --key URI ...` | Selected signing plan, without signing |
| `bind --key URI --certificate URI` | One signature proving explicit key/certificate association |
| `sign --key URI [--certificate URI] ...` | Generic signing, or binding followed by verified signing |
| `verify --certificate-file PATH ...` or `verify --certificate URI ...` | Software verification against a certificate public key |
| `random --token URI --length N --output PATH` | Token-generated random bytes |
| `aes-gcm-capabilities --object URI --operation encrypt\|decrypt [--multipart]` | Current AES key permissions and support for the requested execution mode |
| `encrypt-aes-gcm`, `decrypt-aes-gcm` | Bounded authenticated encryption/decryption; explicit nonce and optional AAD file |
| `key-wrap-capabilities --object URI --operation wrap\|unwrap` | Advisory AES-KW/KWP choices for a secret key |
| `wrap-aes-key --object URI --target URI --algorithm kw\|kwp --output PATH` | Wrap one extractable AES key |
| `unwrap-aes-key --object URI --algorithm kw\|kwp --input PATH --id HEX --label LABEL --confirm` | Create a sensitive nonextractable AES encryption/decryption key |
| `diagnose --token URI --pool-size N` | Bounded lease capacity/exhaustion/reuse and session role |
| `init-token --slot ID --expected-token URI --label LABEL --so-pin-file PATH --confirm` | Initialize or erase a token |
| `init-pin --token URI --role so --pin-file PATH --new-pin-file PATH --confirm` | Initialize/reset USER PIN |
| `set-pin --token URI --pin-file PATH --new-pin-file PATH --confirm` | Change the authenticated USER/SO PIN |
| `generate --token URI --kind KIND --id HEX --label LABEL --confirm` | Persistent nonextractable signing/ECDH/ML-KEM pair or AES key |
| `import --token URI --kind cert\|data\|ml-kem\|public-key --id HEX --label LABEL --input PATH --confirm` | Public certificate/key or data import; `public-key` requires `--purpose` |
| `set-label --object URI --label LABEL --confirm` | Relabel exactly one object |
| `delete --object URI --confirm` | Delete exactly one object |

Object summaries use the client's locator builder. Their `uri` is `null` when the
available metadata cannot form a supported selector; other summaries remain
available. Duplicate locators can still be ambiguous when passed to `inspect`.

Unknown object classes remain in `objects` with a numeric class and a null URI.
`inspect --attributes key-type` preserves unknown numeric key types. This metadata
does not enable unsupported key export or cryptographic operations.

`public-metadata` includes unique IDs, SPKI DER, profile IDs, validation metadata
and object validation flags when applicable. Each attribute is limited to 65,536
bytes. Empty values remain available; unavailable, sensitive and unsupported values
retain their status. Metadata URI values are returned as text/hex without fetching
them. Unknown numeric IDs and flag bits survive. Profile/validation objects have
null object URIs; CKA_UNIQUE_ID does not replace the CKA_ID selector. Nonempty SPKI
must parse as DER, but inspection does not enable unsupported key algorithms or
establish trust.

`template-metadata` returns template member IDs in hexadecimal, byte lengths and
nested `members`, without reading any leaf values. It permits four template
levels, 128 total entries and 65,536 bytes of native array storage. Unknown IDs and
other array types remain opaque. Sensitive, unsupported and unavailable roots are
distinct; unavailable members have no individual cause because the provider's
return code covers the entire request. Native errors or changed layouts fail the
command. Reports cannot be supplied as wrapping, unwrapping or derivation templates.

`session-validation` distinguishes unavailable queries from reported zero flags.
Its session is newly opened: the result does not describe previous CLI commands.
Applications needing flags for a cryptographic operation must use the client's
same-session query immediately after that operation and before closure. Validation
metadata and flags are provider reports, not independent certification or trust.

`inspect --attributes` accepts a comma-separated list: `class`, `label`, `id`,
`object-id`, `private`, `sign`, `verify`, `encrypt`, `decrypt`, `wrap`, `unwrap`,
`derive`, `sensitive`, `extractable`, `always-authenticate`,
`key-type`, `modulus`, `exponent`, `ec-params`, `ec-point`, `subject`, `issuer`,
`serial`, `value`. Values are explicit; requesting `value` can reveal sensitive
application data if the token permits it. Attribute statuses distinguish
available, unsupported, sensitive and unavailable. Byte attributes are encoded
as hexadecimal; labels also have a UTF-8 text field when valid. Defaults never
request secret key material. `export` refuses private/secret-key classes. Public-key
export validates RSA or P-256/P-384/P-521 public attributes and encodes SPKI DER;
`--key-family ml-dsa` exports an ML-DSA public key instead;
certificate/data export retains its raw-value behavior.

## AES key transfer

AES key transfer uses an explicit `--algorithm kw|kwp` and standard default IVs.
Both object and target selectors require `type=secret-key`. The target must be
an extractable AES-128/192/256 key permitted by the wrapping trust policy.
Unwrap accepts 24/32/40-byte blobs, requires a new ID/label of 1–128 bytes and
creates a persistent private, sensitive, nonextractable AES key with encryption/
decryption permission only. Carry and match the algorithm separately: the blob
contains no algorithm, ID, label or permissions. KWP never falls back to KW or
deprecated `AES_KEY_WRAP_PAD`. Native failure may have effects; refresh before
retrying. Output files are never overwritten, and binary output follows checked
session closure and module finalization.

## SP 800-108 KDF

Inspect a derivation base and create one token-held key:

```sh
pkcs11ctl --module /path/to/provider.so kbkdf-capabilities \
  --object 'pkcs11:token=example;id=%01;type=secret-key' --pin-file user.pin
pkcs11ctl --module /path/to/provider.so derive-kbkdf \
  --object 'pkcs11:token=example;id=%01;type=secret-key' \
  --digest sha256 --kind aes256 --kdf-label-file protocol-label.bin \
  --kdf-context-file protocol-context.bin --id 02 --label encryption-key \
  --pin-file user.pin --confirm
```

`--digest sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512` selects
HMAC. Counter mode uses the PRF input
`[i]_32 || label || 0x00 || context || [L]_32`, with big-endian integers and L in
bits. Each optional public input file accepts at most 4096 bytes; omission means
empty. Neither accepts stdin. The KDF label is separate from `--label`, which
names the new object. Agree on an unambiguous protocol encoding with the peer.

The base must be a sensitive, nonextractable generic or matching typed HMAC
secret of 16–4096 bytes with permitted derivation. Capabilities are advisory.
Derivation requires USER authentication, RW access and a new ID/label of
1–128 bytes. `--kind aes128|aes192|aes256` creates an encryption/decryption key;
`--kind derivation-secret --length 1..4096` creates a generic derivation-only key.
AES outputs reject `--length`. All outputs are persistent private, sensitive and
nonextractable. Native rejection causes no fallback or retry and may leave effects.

Both commands accept `--mode counter|feedback|double-pipeline`, defaulting to
counter. For feedback, add `--mode feedback` and optionally `--kdf-iv-file public-iv.bin`.
The raw IV file must be empty or exactly the selected hash output length (28/32/48/64 bytes)
and cannot be stdin. Feedback prepends the previous PRF output before the counter;
the initial input is the supplied IV, with no bytes supplied when omitted.
Counter and Double Pipeline modes reject `--kdf-iv-file`, including empty files.
Capabilities and execution check the selected mode independently; unsupported modes never fall
back to another. Output permissions and other bounds are identical.

Select `--prf aes-cmac` on either command to use an AES-128/192/256 derivation
base. Omit `--digest`; that option is rejected for AES-CMAC. Feedback's optional
IV is then empty or exactly 16 bytes. The base must permit the selected KDF and
be sensitive and nonextractable; standalone CMAC signing permission is unnecessary.
The existing `--prf hmac` default requires `--digest` for derivation and retains
the existing capability response and output policy when no capability hash is
selected. Add `--digest HASH` to `kbkdf-capabilities` to inspect one explicit HMAC
PRF, including SHA-224 and SHA-3 typed keys; this response includes `digest` and
`prf_output_length`. Individual PRF acceptance remains provider-dependent.

```sh
pkcs11ctl --module /trusted/provider.so derive-kbkdf \
  --object 'pkcs11:token=example;id=%01;type=secret-key' \
  --prf aes-cmac --mode counter --kind aes256 \
  --id 02 --label 'derived encryption key' --pin-file user.pin --confirm
```

Double Pipeline constructs `A(0) = label || 0x00 || context || [L]_32` inside
the token and derives each block using `A(i) || [i]_32 || label || 0x00 ||
context || [L]_32`. Both integers are big-endian, and L is in bits. It uses the
selected HMAC or AES-CMAC PRF and protected output choices.
NSS softoken tests cover generic-secret HMAC-SHA-256/384/512 and AES-CMAC; the pinned Kryoptic provider does not advertise
Double Pipeline. Unsupported mechanisms and missing required key metadata are
returned without a mode substitution.
Kryoptic tests cover all eight HMAC PRFs in Counter/Feedback with generic and
typed bases. SHA-224/SHA-3 Double Pipeline has native fixture coverage only.

```sh
pkcs11ctl --module "$MODULE" derive-kbkdf --object "$BASE_SECRET_URI" \
  --mode double-pipeline --digest sha256 --kind aes256 \
  --kdf-label-file protocol-label.bin --kdf-context-file protocol-context.bin \
  --id 0900 --label "Double Pipeline AES" --pin-file user.pin --confirm
```

## PKCS #5 PBKDF2

`pbkdf2-capabilities --token URI` reports advisory native generation support.
`generate-pbkdf2` uses `C_GenerateKey` with the corrected PARAMS2 layout. Select
`--digest sha224|sha256|sha384|sha512|sha512-224|sha512-256` and a positive
`--iterations` explicitly. SHA-512/224 and /256 are distinct hashes, not truncated
SHA-512 results. SHA-1, GOST and SHA-3 PBKDF2 profiles are not exposed.

```sh
pkcs11ctl --module "$MODULE" generate-pbkdf2 --token "$TOKEN_URI" \
  --password-file password.bin --salt-file protocol-salt.bin \
  --digest sha256 --iterations "$PROTOCOL_ITERATIONS" --kind aes256 \
  --id 1000 --label 'password-derived AES' --pin-file user.pin --confirm
```

Password files contain raw bytes, including NULs and final newlines, with no
normalization; 0–4096 bytes are accepted into zeroizing storage. Salt files are
public, nonempty and at most 4096 bytes. Neither accepts stdin. The password is
separate from the token PIN or protected authentication path. Only USER role is
accepted; normal token authentication requirements apply.

Outputs use `--kind aes128|aes192|aes256|derivation-secret`; only the last takes
`--length 1..4096`. Iterations times ceiling(output bytes / PRF bytes) must be
at most 10,000,000. This resource limit does not select a password policy; callers
choose appropriate protocol parameters. Inputs are validated before module loading.
Keys remain persistent, private, sensitive and nonextractable. AES keys permit
encryption/decryption; generic secrets permit derivation only. Native generation
is not retried and may leave effects on failure. Success metadata is withheld
until checked session closure and provider finalization; no password or salt
bytes are included in the response.

## Authentication

Commands that support authentication accept either `--pin-file PATH` or
`--protected-path`. `--role user|so` defaults to USER. A PIN file contains UTF-8
with one optional final LF/CRLF removed, at most 65536 bytes. Other whitespace is
significant. File-descriptor paths such as `/dev/fd/3` can be supplied. Protect PIN
sources through the operating system; the CLI never takes a plaintext PIN option
or silently prompts. Files and pipes are read once, not retried.

PIN buffers use zeroizing storage and are borrowed by library calls. No input
credentials are included in diagnostics. Token login is shared across sessions;
`Authentication::None` does not imply logout. SO commands open RW sessions, while
client signing uses USER/RO sessions. One invocation owns one client Provider.
It checks client/session closure on success and failure, then finalizes the
provider before releasing output. A close or finalization failure uses runtime exit code 5, retaining any primary operation
error in the diagnostic. Cleanup does not retry the operation.

Always-authenticate signing uses a separate `--context-pin-file PATH` or
`--context-protected-path`. A bound `sign` performs two signatures (binding then
message), so it uses context authentication twice. Raw/prehashed always-authenticate
is still unsupported by the upstream signing API. Protected-path availability is
checked by runtime. Token/PIN mutation APIs currently require host PIN files.

## Signing

```sh
pkcs11ctl --module /path/to/module.so sign \
  --key 'pkcs11:serial=123;id=%01;type=private' \
  --algorithm rsa-pkcs1 --digest sha256 --input message.bin \
  --output signature.bin --pin-file /secure/user.pin
```

For classical keys, `sign` and `plan` require `--algorithm rsa-pkcs1|rsa-pss|ecdsa`,
`--digest sha256|sha384|sha512` and `--input PATH`. `--input-kind message|digest`
defaults to message; digest input is never hashed again. Its length must match the
selected digest (32, 48 or 64 bytes), checked before output reservation or module
loading. `--hashing
token|allow-software|software` defaults to token. The client applies its default
2048-bit RSA minimum and supported curve/algorithm policy. An advertised mechanism
can still fail; there is no operation retry or fallback after failure.

PSS additionally requires `--mgf-digest` and `--salt-length`. Bound PSS requires
matching message/MGF digests. Generic signing forwards independent parameters to
the token, which may reject combinations it cannot implement. Unsupported bound
parameters and signing policy are checked before the binding probe.

`--certificate URI` opts into explicit binding and per-signature verification.
The association uses the client's domain-separated probe; matching ID/label alone
is insufficient. Parsing/binding does not establish issuer trust, validity, usage,
revocation or hostname correctness. `plan` does not perform binding and takes no
certificate option. `bind` accepts the same hashing-policy choices.

RSA signatures are modulus-width bytes. ECDSA is fixed-width `r || s`, not DER.
DER/PEM conversion is not implemented.

`sign --multipart` streams an original RSA/ECDSA message through the client's
zeroizing 64 KiB reader buffer, with a 64 MiB input limit. The selected hashing
policy still applies: token hashing uses native update/final calls; software
hashing is incremental and completes through the raw signing mechanism.
`--certificate` retains the binding probe and checks the completed signature
against that certificate using an incremental hash of the same message. Input is
read once, including stdin; no seek or plaintext staging file is used. Context
authentication still follows initialization for each signature.

`verify-token --multipart` uses the corresponding streaming token verification
path and hashing policy. `verify --multipart` incrementally hashes in software
and verifies against the selected token certificate or `--certificate-file`.
These modes also accept original ML-DSA messages as described below; caller
digests and EdDSA are rejected before provider loading. File/stdin limits are checked during
reading as well as regular-file preflight. Read errors return 6, oversized input
returns 2, and native failures are never retried through another hashing path.
Signatures and verification success follow checked session/client closure and
module finalization. Existing buffered workflows remain the default; `plan` and
`capabilities` continue to describe single-part execution.

`--input -` reads stdin. Binary commands require `--output PATH`; `-` writes raw
bytes to stdout. New output files use exclusive creation and mode 0600 on Unix;
existing files are never overwritten. An output destination is reserved before
loading the module. Incomplete new files are removed on failure. An output or
finalization error after signing does not undo the token operation: do not assume
an error means no signature or mutation occurred.

## ML-DSA

`generate --kind ml-dsa-44|ml-dsa-65|ml-dsa-87` generates a persistent,
sensitive, nonextractable key pair. `--bits` is RSA-only. The provider must support
the selected parameter set; no software generation or signing fallback is used.

```sh
pkcs11ctl --module /path/to/module.so generate \
  --token 'pkcs11:serial=123' --kind ml-dsa-65 --id 01 --label signing \
  --pin-file /secure/user.pin --confirm
pkcs11ctl --module /path/to/module.so sign \
  --key 'pkcs11:serial=123;id=%01;type=private' \
  --algorithm ml-dsa-65 --input message.bin --context-file context.bin \
  --hedging required --output signature.bin --pin-file /secure/user.pin
pkcs11ctl verify --certificate-file certificate.der \
  --algorithm ml-dsa-65 --input message.bin --context-file context.bin \
  --signature signature.bin
```

`sign`, `plan`, `verify` and `verify-token` accept `--algorithm ml-dsa-44|ml-dsa-65|ml-dsa-87`.
These are pure ML-DSA requests: digest input, `--digest`, PSS parameters and
`--hashing` are rejected. Messages are limited to 64 MiB; empty messages are valid.
`--context-file PATH` supplies up to 255 binary context bytes, defaulting to empty.
It requires a file path, while `--input -` can read the message from stdin.
Verification must use the same context as signing.

Add `--multipart` to `sign`, `verify` or `verify-token` for original-message
file/stdin streaming through zeroizing 64 KiB reader buffers. The 64 MiB limit
applies during reading, including growing files and stdin. `sign --certificate`
retains its binding probe and checks each streamed signature before release,
reading the input once. `verify` checks a token certificate or certificate file in
software using the pure ML-DSA internal message calculation; no HashML-DSA or
caller-digest mode is introduced.

`verify-token --multipart` supplies the signature before input through
`C_VerifySignatureInit`, `C_VerifySignatureUpdate` and `C_VerifySignatureFinal`.
It requires a selected 3.2 interface and
an implementing provider; it never falls back to the older verification API.
Without `--multipart`, token verification uses the existing single-part `C_Verify`
profile. The pinned SoftHSM accepts streaming signing but its signature-first
stubs reject verification with `CKR_FUNCTION_NOT_SUPPORTED` (exit 5); Kryoptic
implements that verification path. Empty signing streams send a zero-length
update before finalization. Existing context authentication, exact signature
lengths, no-clobber output and checked cleanup rules apply to both modes.

`sign` and `plan` accept `--hedging required|preferred|deterministic`, defaulting
to `required`. Required hedging demands fresh token randomness; preferred permits
the provider's hedged or deterministic implementation; deterministic requires
repeatable signing. Provider errors are returned without retry. `plan` validates
current capabilities and reports parameters, context length, hedging and context
authentication requirements without signing.

Use `--key-family ml-dsa` with `capabilities`, `certificate`, `bind`, and public-key
`export` to select the client's ML-DSA API. These commands default to `classical`.
ML-DSA public export requires a `type=public` URI and writes RFC 9881 SPKI DER.
Certificate import and raw certificate export need no family option.

`sign --certificate URI` binds before signing and verifies the resulting signature
in software. `bind --key-family ml-dsa` performs only the binding probe. Binding
always requires hedging, independently of the message's `--hedging` choice.
Always-authenticate keys use the separate context PIN options described above,
including two authentications for bound signing. Certificate verification is
available offline or against a token certificate and establishes no issuer trust.

HashML-DSA uses separate commands, with SHA-512 as the default:

```sh
pkcs11ctl --module /trusted/provider.so sign-hash-ml-dsa \
  --object 'pkcs11:token=example;id=%01;type=private' \
  --parameter-set ml-dsa-65 --input message.bin --output signature.bin \
  --pin-file user.pin

pkcs11ctl --module /trusted/provider.so verify-hash-ml-dsa \
  --object 'pkcs11:token=example;id=%01;type=public' \
  --parameter-set ml-dsa-65 --input message.bin --signature signature.bin
```

`--digest sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512` selects
the hash; omission retains SHA-512. `--input-kind message` is the default and
hashes the original message on the token with CKM_HASH_ML_DSA_<hash>.
`--input-kind digest` instead requires exactly 28/32/48/64 raw digest bytes
matching the selected hash and uses CKM_HASH_ML_DSA. Equal-length hashes are not
interchangeable. Neither mode substitutes
another mechanism or hashes in software. `hash-ml-dsa-capabilities --object URI`
reports advisory single-part signing support for the selected hash and `--input-kind`;
adding `--multipart` checks native signing streams instead.
Both signing and verification accept `--parameter-set ml-dsa-44|ml-dsa-65|ml-dsa-87`
and `--context-file`; signing additionally accepts `--hedging` and the separate
context PIN options. Contexts default to empty and must match during verification.
Message input is limited to 64 MiB. Input or signature may read stdin, one at a
time. Output is released only after checked session closure and module finalization.
Add `--multipart` to either command to stream original messages through native
update/final calls using zeroizing 64 KiB reader buffers, retaining the 64 MiB
limit. Verification uses C_VerifyUpdate/Final independently of the selected
table's 3.2 signature-first support. `--multipart --input-kind digest` is rejected
before input loading or module initialization: external digests remain single-part.
Single-part execution remains the default. These commands use token keys directly;
certificate binding, offline verification and TLS retain their existing pure
ML-DSA profile.

RSA/ECDSA signature commands accept explicit `--digest sha224|sha3-224|sha3-256|sha3-384|sha3-512`
and the same choices for PSS `--mgf-digest`. Caller digests must contain exactly
28/32/48/64 bytes for the selected hash. Selecting a digest enables it for that
command; equal-length SHA-2 and SHA-3 hashes remain distinct. Software certificate
verification requires matching PSS message/MGF digests. OAEP and KDF choices remain
SHA-256/384/512.

## ML-KEM and key derivation

`generate --kind ml-kem-512|ml-kem-768|ml-kem-1024` creates a persistent public
encapsulation key and a private, sensitive, nonextractable decapsulation key.
Use `export --key-family ml-kem` and `import --kind ml-kem` for RFC 9935 public
SPKI DER. Private-key import/export is unavailable. `--bits` and
`--always-authenticate` do not apply to ML-KEM generation.

```sh
pkcs11ctl --module /path/to/module.so encapsulate \
  --object 'pkcs11:serial=123;id=%01;type=public' \
  --parameter-set ml-kem-768 --id 0200 --label sender-secret \
  --pin-file /run/user/1000/token.pin --output ciphertext.bin --confirm
pkcs11ctl --module /path/to/module.so decapsulate \
  --object 'pkcs11:serial=456;id=%01;type=private' \
  --parameter-set ml-kem-768 --id 0201 --label recipient-secret \
  --pin-file /run/user/1000/token.pin --input ciphertext.bin --confirm
pkcs11ctl --module /path/to/module.so derive-hkdf \
  --object 'pkcs11:serial=123;id=%02%00;type=secret-key' \
  --digest sha256 --kind aes256 --id 03 --label application-key \
  --salt-file public-salt.bin --info-file protocol-context.bin \
  --pin-file /run/user/1000/token.pin --confirm
```

Run each command against its corresponding peer's module and token. Encapsulation
writes only public ciphertext, using exclusive output-file creation or binary
stdout. Decapsulation checks exact ciphertext length before loading a module.
Both store a private, sensitive, nonextractable 32-byte generic secret with only
derivation enabled. They require new secret IDs; existing IDs are rejected.
`kem-capabilities --object URI --operation encapsulate|decapsulate` reports the
selected key profile without creating a secret.

`hkdf-capabilities --object URI --digest sha256|sha384|sha512` checks the base-key
profile. `derive-hkdf` defaults to `--mode extract-and-expand`; the generic/HKDF base
must be sensitive, nonextractable, permit derivation and match the hash length.
ML-KEM secrets use SHA-256. `--kind aes128|aes192|aes256` creates encryption/decryption
keys; `--kind derivation-secret --length N` creates a generic derivation key.
Outputs remain private, sensitive and nonextractable. Salt/context files contain
public bytes and are bounded to 4096 bytes each. Omitted salt means zero salt;
omitted context is allowed for single-input HKDF. File paths must not be `-`.

`--mode extract` requires `--kind derivation-secret --length 32|48|64` matching
the digest, and empty context. It creates a derivation-only PRK. Select that
secret in a later `--mode expand` command, supplying context and the desired
output profile, with empty salt. The caller must establish the PRK's origin;
key metadata cannot prove it. Nonempty parameters for a disabled stage are
rejected. JSON derivation results include the selected `mode`.

`derive-hkdf --salt-key 'pkcs11:serial=123;id=%02;type=secret-key'` uses a
persistent salt key on the selected token. It conflicts with `--salt-file` and
requires extraction; expand-only mode rejects it. Salt keys must be sensitive,
nonextractable generic/HKDF secrets of 1–4096 bytes with derivation permission
and permitted HKDF use. The key is resolved again in the derivation session;
its value is never read. Wrong token, missing/ambiguous key and policy failures
produce no success result. The fixed hybrid combiner retains public byte salt.

`derive-hybrid --object CLASSICAL --post-quantum PQ --digest sha512` combines a
P-256 ECDH secret followed by an ML-KEM-768 secret using token-side concatenation
and HKDF-SHA512. Other output/identity options match `derive-hkdf`. Both inputs
must be distinct 32-byte sensitive, nonextractable generic secrets permitting
derivation and concatenation. Salt is limited to 128 bytes and `--info-file` must
supply nonempty protocol context. The temporary combined secret is destroyed
before return; inputs remain until explicitly deleted.

The caller authenticates peers and establishes component origin, independence,
ordering and protocol context. Metadata cannot prove provenance. This command is
an application combiner, not a hybrid KEM wire protocol, X-Wing or TLS key schedule.
ML-KEM implicit rejection can produce a different secret for altered ciphertext
without an error; successful decapsulation does not authenticate the sender.

All mutations above require `--confirm` and an RW session. USER authentication
uses `--pin-file` or `--protected-path` where supported. No secret values are read
or exported, and no software fallback or retry occurs. Provider/cleanup failure
can leave persistent effects; inspect and remove unwanted objects explicitly.
Output is released only after checked session and module cleanup.

## Verification and random bytes

```sh
pkcs11ctl verify --certificate-file certificate.der \
  --algorithm rsa-pkcs1 --digest sha256 --input message.bin \
  --signature signature.bin
pkcs11ctl --module /path/to/module.so random \
  --token 'pkcs11:serial=123' --length 32 --output random.bin
```

`verify` accepts either `--certificate-file PATH` (X.509 DER, no module or login)
or `--certificate URI` (loaded through the client, with optional USER authentication).
It uses the same algorithm and input arguments as signing, including classical
digest/PSS parameters or an ML-DSA context.
Verification always runs in software and accepts no `--hashing` policy.
RSA signatures are raw modulus-width bytes; ECDSA signatures are fixed-width
`r || s`. A success reports `verified: true` and `trust_validated: false`;
a mismatch returns exit code 4. This verifies the signature, not the certificate's
issuer, validity, usage or trust chain.

Verification limits message input to 64 MiB, signature input to 16 KiB and
certificate files to 1 MiB. Either `--input -` or `--signature -` can read stdin;
both cannot use it together. Certificate files require a path.

`random` requests 1 through 1048576 bytes in one token call. Authentication is
optional, subject to token policy. There is no software fallback, seeding or
automatic retry. Generated bytes stay in zeroizing storage until output completes
or fails. `--output PATH` and `--output -` have the same exclusive-file and binary
stdout behavior as signing, and output is released only after checked cleanup.

## Administration

Every mutation requires `--confirm` and executes once without automatic rollback
or retry. `init-token` can destroy all objects and takes an explicit current slot
ID and requires `--expected-token URI`. Copy the selected entry's complete URI
from `tokens`; it must include `token`, `manufacturer`, `model` and `serial`, with
explicit empty values where reported. Other attributes and queries are rejected.
The CLI compares these criteria against the selected slot, then the client
rechecks the captured token metadata immediately before initialization. This
requirement also applies to previously uninitialized tokens.

Metadata is not physical device identity: an identical replacement or a swap
after the check cannot be detected. Arrange exclusive physical access when erasing.
Runtime requires exclusive module ownership, so no borrowed token/session can
survive initialization. Token labels are at most 32 UTF-8 bytes.

`generate` supports `rsa`, `p256`, `p384`, `p521`, ML-DSA and ML-KEM kinds,
plus `ecdh-p256`, `ecdh-p384`, `ecdh-p521` and `aes128`, `aes192`, `aes256`.
RSA defaults to signing; `--purpose encryption` creates encryption/decryption-only
pairs, with signing disabled. RSA defaults to 2048 bits; `--bits` accepts multiples
of eight from 2048 to 16384, subject to provider bounds. Existing `p256`/`p384`/`p521` kinds create signing
pairs. ECDH private keys permit only derivation. AES requires
`--purpose encryption` (encryption/decryption), `--purpose wrapping`
(wrapping/unwrapping), or `--purpose authentication` (full-tag AES-CMAC only);
other permissions are disabled. `--always-authenticate`
applies to signing and RSA encryption keys. `--purpose` applies to AES and RSA,
and `--bits` only to RSA; invalid combinations fail before loading a provider.

```sh
pkcs11ctl --module /path/to/module.so generation-options --token 'pkcs11:serial=123'
pkcs11ctl --module /path/to/module.so generate --token 'pkcs11:serial=123' \
  --kind ecdh-p256 --id 31 --label agreement --pin-file user.pin --confirm
pkcs11ctl --module /path/to/module.so generate --token 'pkcs11:serial=123' \
  --kind aes256 --purpose wrapping --id 32 --label wrapper --pin-file user.pin --confirm
```

Choices describe generation only, not later operation support or template
acceptance. No private/secret values are returned. Generated objects persist;
private/secret keys are sensitive and nonextractable. RSA encryption, ECDH and AES require ID/label
fields of 1–128 bytes, rejecting existing public/private IDs for ECDH or secret
IDs for AES. Checks do not ensure uniqueness against concurrent writers. Existing
signing and PQC generation can create duplicate IDs/labels. Generation does not
overwrite existing objects and has no retry or rollback.

Certificate import accepts exact X.509 DER, including algorithms unsupported for
client signing. The client parses subject/issuer/serial metadata for the runtime
creation template; it does not validate certificate trust. Data bytes remain
uninterpreted. `--id` maps to CKA_ID for certificates/keys and CKA_OBJECT_ID for data;
select data objects by their label. Imported objects are persistent and public.

`import --kind public-key` accepts one RSA or named EC SPKI DER document up to
4096 bytes. It requires `--purpose verification|encryption`; encryption accepts
RSA only. RSA sizes are 2048–16384 bits; EC curves are P-256/P-384/P-521.
Restricted RSA-PSS keys and invalid components/points are rejected before module
loading. RSA NULL parameters and EC point representation are normalized. The
object is persistent and public, with wrapping, recovery and derivation disabled.
Existing public-key IDs are rejected. A matching private/certificate ID does not
establish association or trust, and those objects are not changed.

```sh
pkcs11ctl --module "$MODULE" import --token "$TOKEN_URI" --kind public-key \
  --purpose verification --input peer.der --id 0601 --label peer-key \
  --pin-file user.pin --confirm
```

`derive-ecdh` validates a P-256/P-384/P-521 peer SPKI DER public key and derives
one persistent sensitive, nonextractable key. Select `--kdf null` with
`--kind raw-secret` to preserve the complete raw secret (66 bytes on P-521).
Use `x963-sha256|384|512` or `sp800-sha256|384|512` with
`--kind aes128|aes192|aes256|derivation-secret` for an explicit SHA-2 KDF.
Generic KDF output requires `--length 1..4096`; AES length is fixed.
Optional `--shared-info-file` accepts up to 4096 public bytes for SHA-2 KDFs.
AES outputs permit only encryption/decryption; generic outputs permit only
further derivation. Peer authentication remains the caller's responsibility.
Individual KDF support is checked during derivation; rejection never changes
parameters or falls back to software.

```sh
pkcs11ctl --module "$MODULE" derive-ecdh --object "$PRIVATE_KEY_URI" \
  --input peer.der --kdf x963-sha512 --kind derivation-secret --length 64 \
  --shared-info-file context.bin --id 0501 --label agreement-material \
  --pin-file user.pin --confirm
```

`export --key-family x25519 --object "$PUBLIC_KEY_URI" --output peer.der`
exports an existing RFC 8410 X25519 public key. `derive-x25519` accepts a strict
peer SPKI DER, including stdin, and creates a complete 32-byte token-held secret
using CKD_NULL by default. Small-order public inputs are rejected before module loading.
The private base must be sensitive/nonextractable and permit derivation without
always-authenticate. The output permits further derivation only. Run
`derive-hkdf --digest sha256` separately, with public salt and a protocol context
that binds both authenticated peers. No private or secret values are exported.
`generate --kind x25519` creates a protected derivation-only pair;
`generation-options` reports advisory X25519 support. `import --kind x25519`
accepts strict public SPKI DER (file/stdin, at most 128 bytes) and disables public
operation permissions. It does not establish trust or associate a private key.
Generation/import require explicit ID/label and confirmation. Signing, AES-purpose,
RSA-size and context-authentication options do not apply to X25519 generation.
curveName parameters and desktop workflows remain outside this profile.

```sh
pkcs11ctl --module "$MODULE" generate --token "$TOKEN_URI" --kind x25519 \
  --id 0500 --label x25519-pair --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" import --token "$TOKEN_URI" --kind x25519 \
  --input peer.der --id 0501 --label x25519-peer --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" derive-x25519 --object "$PRIVATE_KEY_URI" \
  --input peer.der --id 0502 --label x25519-material --pin-file user.pin --confirm
```

For existing RFC 8410 X448 keys, `export --key-family x448` emits SPKI DER.
`derive-x448` accepts strict peer SPKI DER from a file or stdin, at most 128 bytes.
It requires explicit `--kdf` and `--kind`; SHA-2 choices are listed below.
The null KDF requires `raw-secret`, preserving all 56 bytes with derivation-only
permission and no shared info. SHA-512 KDFs accept a public `--shared-info-file`
(up to 4096 bytes, no stdin); their outputs are `aes128`/`aes192`/`aes256` or a
64-byte derivation-only `secret`. All outputs remain private, sensitive and
nonextractable. Raw 56-byte output cannot feed this app's hash-length PKCS #11
HKDF profile. Select SHA-512 and `secret` explicitly before `derive-hkdf --digest
sha512`; no automatic truncation or KDF substitution occurs.
`generate --kind x448` creates a protected derivation-only pair; `generation-options`
reports advisory support. `import --kind x448` accepts strict public SPKI DER from
a file or stdin (at most 128 bytes) and disables public operation permissions.
Both require nonempty IDs/labels of at most 128 bytes and explicit confirmation.
Generation rejects existing public/private IDs; import rejects public IDs and does
not establish trust or associate a private key. Signing, RSA-size, AES-purpose and
context-authentication options do not apply to X448 generation. This profile
requires OID parameters; desktop workflows remain deferred.

```sh
pkcs11ctl --module "$MODULE" generate --token "$TOKEN_URI" --kind x448 \
  --id 0601 --label x448-pair --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" import --token "$TOKEN_URI" --kind x448 \
  --input peer-x448.der --id 0602 --label x448-peer --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" derive-x448 --object "$PRIVATE_KEY_URI" \
  --input peer-x448.der --kdf nist-sha512 --kind secret \
  --shared-info-file context.bin --id 0600 --label x448-material \
  --pin-file user.pin --confirm
```

`generate --kind curve25519|curve448`, `import --kind curve25519|curve448` and
`export --key-family curve25519|curve448` select the separate RFC 7748 curveName
profiles. Public input/output consists of exactly 32/56 raw little-endian bytes;
SPKI DER is not accepted or produced. Generation and import require RW access,
explicit confirmation and bounded nonempty identity, with the same duplicate-ID
and protected-key policy as the OID profiles. `generation-options` lists advisory
choices in `montgomery_named`.

`derive-montgomery --curve curve25519|curve448` accepts a raw peer from a file or
stdin and requires a matching curveName private object. It creates a complete
32/56-byte sensitive, nonextractable derivation-only secret using CKD_NULL
by default.
Authenticate peers and apply a protocol KDF separately. `derive-kbkdf` accepts
either raw width; the 56-byte curve448 result cannot feed the hash-length
HKDF-SHA512 profile. No conversion between curveName and OID objects occurs.
Outputs are released only after checked session closure and module finalization.

```sh
pkcs11ctl --module "$MODULE" generate --token "$TOKEN_URI" --kind curve25519 \
  --id 0700 --label curve25519-pair --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" export --object "$PUBLIC_KEY_URI" \
  --key-family curve25519 --output local.raw
pkcs11ctl --module "$MODULE" import --token "$TOKEN_URI" --kind curve25519 \
  --input peer.raw --id 0701 --label curve25519-peer --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" derive-montgomery --object "$PRIVATE_KEY_URI" \
  --curve curve25519 --input peer.raw --id 0702 --label curve25519-secret \
  --pin-file user.pin --confirm
```

`derive-x25519`, `derive-x448` and `derive-montgomery` also accept
`--kdf x963-sha224|x963-sha256|x963-sha384|x963-sha512` or
`nist-sha224|nist-sha256|nist-sha384|nist-sha512`. Hashed output requires
`--kind aes128|aes192|aes256`, or `--kind derivation-secret --length N`
(1–4096 bytes). `--shared-info-file` supplies at most 4096 bytes of public binary
context and cannot read stdin. Peer input can still come from a file or stdin.
X25519 and curveName commands default to `--kdf null --kind raw-secret`;
X448 continues to require both options. Its existing `--kind secret` remains
64 bytes. `--length` applies only to `derivation-secret`. Null KDF rejects context
and all outputs except the complete raw secret; hashed KDFs reject raw output.
All new keys remain token-held, sensitive and nonextractable. Generic secrets
permit further derivation only; AES keys permit encryption/decryption only.
Provider rejection never changes the selected KDF or curve profile. Authenticate
peer ownership and bind shared info to the protocol. Further HKDF/SP 800-108
operations retain their existing input-length requirements.

```sh
pkcs11ctl --module "$MODULE" derive-x25519 --object "$PRIVATE_KEY_URI" \
  --input peer-x25519.der --kdf x963-sha256 --kind aes256 \
  --shared-info-file transcript.bin --id 0420 --label "Agreement AES" \
  --pin-file user.pin --confirm

pkcs11ctl --module "$MODULE" derive-montgomery --object "$PRIVATE_KEY_URI" \
  --curve curve448 --input peer-curve448.raw --kdf nist-sha512 \
  --kind derivation-secret --length 64 --shared-info-file transcript.bin \
  --id 0421 --label "Curve448 HKDF base" --pin-file user.pin --confirm
```

Raw certificate export and inspection work independently of client key support.
Arbitrary JSON templates, private/secret-key import/export, wrapping and
vendor-specific administration are not implemented.
Runtime exposes generic creation/update templates for library callers. Attribute
updates may partially succeed before a provider reports failure; runtime marks
that session unusable and does not attempt rollback.

## Token file digests

`digest-algorithms --token "$TOKEN_URI"` reports advertised multipart hash
algorithms. `digest` streams a file or stdin in bounded chunks and returns
`algorithm` and `digest_hex` after checked session/module closure. It does not
load the whole input, accept key material or fall back to software hashing.
Ordinary login is optional unless required by the provider.

```sh
pkcs11ctl --module "$MODULE" digest --token "$TOKEN_URI" \
  --algorithm sha3-256 --input document.bin
```

Choices are `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`, `sha512-256`,
`sha3-224`, `sha3-256`, `sha3-384` and `sha3-512`. Input `-` reads stdin;
empty files are supported. Read/native failures return no digest and discard
the session. SHA-512/224 and SHA-512/256 use their distinct standard algorithms.

## Output and exit codes

Structured JSON success has `schema_version: 1`, `command` and `result`. Errors
have `schema_version: 1` and `error: {kind, message}` on stderr. Parsing errors are
redacted rather than quoting raw arguments. Binary commands emit no success JSON;
`--format json` still controls their errors. Text output prints escaped field/value
records. User-controlled labels cannot inject terminal control sequences.

| Exit | Meaning |
| --- | --- |
| 0 | Success or requested help/version |
| 2 | Arguments, URI constraints or input parameters |
| 3 | Missing or ambiguous selection |
| 4 | Signing policy, unsupported client parsing/verification or binding mismatch |
| 5 | Runtime/provider/loading/cleanup failure |
| 6 | File or output I/O failure |

Provider mechanism names and session states are diagnostic strings. Structured
attributes use the explicit status/value contract above; no private object handle
is exposed. `diagnose` opens up to 64 simultaneous exclusive leases, verifies pool
exhaustion, releases them and verifies reuse. It is not a performance benchmark or
hardware fault-injection test.

## AES-GCM files

Use `encrypt-aes-gcm` or `decrypt-aes-gcm` with an AES `--object` URI containing
`type=secret-key`, exactly 24 hexadecimal nonce digits, `--input` and `--output`.
`--aad-file` is optional; omit it for empty AAD. The file cannot read stdin.
`--input -` reads stdin and `--output -` writes raw binary stdout, including with
`--format json`. File and provider errors use stderr without plaintext bytes.

```sh
# NONCE_HEX must be a nonce not previously used with this key.
pkcs11ctl --module /path/to/module.so encrypt-aes-gcm \
  --object 'pkcs11:serial=123;id=%31;type=secret-key' --nonce "$NONCE_HEX" \
  --aad-file context.bin --input message.bin --output ciphertext.bin --pin-file user.pin
pkcs11ctl --module /path/to/module.so decrypt-aes-gcm \
  --object 'pkcs11:serial=123;id=%31;type=secret-key' --nonce "$NONCE_HEX" \
  --aad-file context.bin --input ciphertext.bin --output recovered.bin --pin-file user.pin
```

The format is ciphertext followed by a full 16-byte tag, without a nonce, AAD or
header. Keep nonce and AAD for decryption. Plaintext is limited to 16 MiB; AAD to
1 MiB. Empty plaintext is supported; ciphertext must contain at least a full tag.
Generated encryption keys and HKDF AES outputs work; wrapping-only keys do not.
Use `aes-gcm-capabilities` for advisory size/permission checks without encryption.

Add `--multipart` to either command to read input through the client's zeroizing
64 KiB buffer and use native update/final calls. Files are opened and regular-file
lengths checked before loading the provider; input is consumed after initialization.
Stdin uses the same reader and is checked against the limit as it is read. The
16 MiB plaintext and 1 MiB AAD limits remain. Returned plaintext stays in zeroizing
quarantine until final authentication; binary results are emitted only after
checked session closure and module finalization. No plaintext staging file is used.

Single-part execution remains the default. Add `--multipart` to
`aes-gcm-capabilities` to check multipart entry points independently; the JSON
result's `multipart` field identifies the requested mode. Missing support or a
native error does not trigger a single-part or software retry. Read failures use
exit code 6 with redacted I/O diagnostics; authentication/provider/cleanup failures
use exit code 5. Input-limit violations use exit code 2. A cleanup failure takes
precedence over an earlier input or I/O error.

Callers ensure nonce uniqueness per key across applications, restarts and copies
of key material. No nonce is generated or tracked; an encryption error does not
authorize reusing it. There is no retry or software fallback. Authenticated
decryption and checked session/module closure precede plaintext output. Output
files are created with mode 0600 on Unix and never overwritten; incomplete files
are removed on failure. Input/plaintext buffers zeroize on drop. Multipart plaintext
output storage is zeroized on native failure; provider-internal memory remains
under provider control.

## Testing

```sh
cargo test -p pkcs11ctl --locked
./tools/test-softhsm.sh
```

Unit tests check argument validation, independent verification fixtures, redaction,
output preservation and exit codes. SoftHSM tests exercise inspection, signing,
verification, random generation and administration commands. The required PQC
provider lane also tests ML-DSA CLI workflows and OpenSSL interoperability.
`tools/test-kem-hkdf.sh` tests ML-KEM, HKDF and hybrid CLI workflows on a disposable
Kryoptic token; see the [test guide](../../tests/README.md#persistent-ml-kem-and-hkdf).

`--interface-version auto|2.40|3.0|3.1|3.2` selects module negotiation globally.
The default is `auto`; exact versions never downgrade. `info` reports the
selected interface separately from the provider's reported PKCS#11 version.

`verify-token --key <type=public URI> --algorithm rsa-pkcs1|rsa-pss|ecdsa
--digest sha256|sha384|sha512 --input <file> --signature <file>` performs native
verification. PSS requires `--mgf-digest` and `--salt-length`. `--hashing` and
`--input-kind` preserve the signing command's explicit message/digest boundaries.
The `verify` command continues to verify against certificates in software.

`encrypt-rsa-oaep` and `decrypt-rsa-oaep` take `--object`, `--digest`, `--input`
and `--output`. They use SHA-256/384/512; `--mgf-digest` defaults to `--digest`.
Optional `--label-hex` supplies up to 4096 bytes of binary context; the default
label is empty. Decryption requires the same digests and label. Ciphertext carries
no parameter metadata. Input is one RSA block; output files are never overwritten. Decryption
accepts `--context-pin-file` or `--context-protected-path`, separately from USER
login. Per-operation credentials are not cached or retried.

## AES-CMAC

```sh
pkcs11ctl --module /path/to/module.so generate --token 'pkcs11:serial=123' \
  --kind aes256 --purpose authentication --id 43 --label message-mac \
  --pin-file user.pin --confirm
pkcs11ctl --module /path/to/module.so mac-aes-cmac \
  --object 'pkcs11:serial=123;id=%43;type=secret-key' \
  --input message.bin --output tag.bin --pin-file user.pin
pkcs11ctl --module /path/to/module.so verify-aes-cmac \
  --object 'pkcs11:serial=123;id=%43;type=secret-key' \
  --input message.bin --tag-file tag.bin --pin-file user.pin
```

`aes-cmac-capabilities --object URI --operation generate|verify` reports native
support without producing a tag. The AES key must be sensitive and nonextractable,
with generation or verification permission respectively. Generation writes only
the raw 16-byte tag to a new file or binary stdout (`--output -`). Existing outputs
are preserved. Messages may be empty and are limited to 16 MiB; `--input -` reads
stdin. Tag input requires a file containing exactly 16 bytes, checked before module
loading. A verification mismatch returns exit code 4 with no success output.
Results are released after checked session closure. No software MAC or
fallback occurs. A shared-key MAC does not identify an individual signer.

All three CMAC commands accept optional `--tag-length 8..16` to select native
CKM_AES_CMAC_GENERAL. Omission preserves the full-tag mechanism and 16-byte
contract. Tag files must exactly match the selected length. A 16-byte general
tag still requires the general mechanism; rejection never falls back to full
CMAC or another length. Agree on the length before communication and keep it
fixed for that key's lifetime.

`mac-aes-cmac` and `verify-aes-cmac` accept `--multipart` for native
`C_SignUpdate`/`C_SignFinal` or `C_VerifyUpdate`/`C_VerifyFinal` execution.
File/stdin input uses the client's zeroizing 64 KiB buffer; the 16 MiB message
limit still applies, including files that grow after preflight. Full and general
tag profiles keep their exact lengths and permissions. Single-part remains the
default, and the capability command describes that mode. Missing multipart entry
points or native failures end the operation without fallback or retry. Tags and
verification success are released only after session closure and module finalization.
Read errors return exit code 6; oversized input returns 2, with no output.

Use `generate --kind aes256 --purpose authentication-general ...` for a separate
private, sensitive, nonextractable key restricted to the general mechanism and
MAC permissions. `generation-options` reports native compatible sizes in
`aes_cmac_general_bits`. The original `authentication` purpose remains full-tag
only. General tags use the token directly, without software truncation.

## HMAC

```sh
pkcs11ctl --module /path/to/module.so generate --token 'pkcs11:serial=123' \
  --kind hmac-sha384 --id 48 --label message-hmac --pin-file user.pin --confirm
pkcs11ctl --module /path/to/module.so mac-hmac \
  --object 'pkcs11:serial=123;id=%48;type=secret-key' --algorithm hmac-sha384 \
  --input message.bin --output tag.bin --pin-file user.pin
pkcs11ctl --module /path/to/module.so verify-hmac \
  --object 'pkcs11:serial=123;id=%48;type=secret-key' --algorithm hmac-sha384 \
  --input message.bin --tag-file tag.bin --pin-file user.pin
```

`hmac-capabilities --object URI --operation generate|verify` reports permitted
profiles without producing a tag. Algorithms are `hmac-sha224`, `hmac-sha256`,
`hmac-sha384`, `hmac-sha512`, `hmac-sha512-224`, `hmac-sha512-256` and
`hmac-sha3-224/256/384/512` (each suffix is a separate choice). Full tags are
28/32/48/64 bytes according to the selected hash. SHA-512/224 and SHA-512/256
use their distinct hash functions. The algorithm is explicit; no substitution occurs.
Generation kinds of the same names create hash-length generic secrets restricted
to the chosen HMAC. They take neither `--purpose` nor `--always-authenticate`.
`generation-options` includes advisory `hmac` and `hmac_general` lists.

Pass `--tag-length N` to `mac-hmac` or `verify-hmac` to select native general HMAC.
The application accepts half the hash output through its full length: 14–28,
16–32, 24–48 or 32–64 bytes. Omission keeps the existing full-tag mechanism;
even a full-length general tag requires the distinct general mechanism.
`hmac-capabilities --general-tag` inspects general mechanisms. For generation,
`generate --kind hmac-sha384 --general-tag ...` restricts the new key to its
general mechanism. Existing full-tag keys retain their restriction. Agree on
one algorithm and tag length per key before communicating; key attributes do
not encode this length. No software truncation or fallback occurs.

Existing generic and matching hash-specific HMAC keys must be sensitive,
nonextractable, 16–4096 bytes long and permit the requested direction. Provider
limits may reject a key. Message input may be empty and is bounded to 16 MiB;
`--input -` reads stdin. Tag generation writes a new raw file or binary stdout.
Verification requires an exact selected-length tag file, checked before module loading;
`--tag-file -` is rejected. Mismatch returns exit code 4 without success output.
Results follow checked session closure and module finalization; existing outputs
are preserved. No truncation, software fallback or retry occurs.

`mac-hmac` and `verify-hmac` also accept `--multipart` with the same input,
output and lifecycle rules as multipart AES-CMAC above. It applies to both full
and general HMAC profiles. The capability command continues to inspect single-part
support; multipart execution independently requires its native entry points.

## Pure EdDSA

Signature commands accept `--algorithm ed25519|ed448` with original message input.
They reject digest, hashing-policy, PSS, domain-context and hedging options.
`--context-pin-file` remains available for always-authenticate keys.

```sh
pkcs11ctl --module /path/to/module.so sign \
  --key 'pkcs11:token=example;id=%01;type=private' \
  --algorithm ed25519 --input message.bin --output signature.bin --pin-file user.pin
```

`generate --kind ed25519|ed448` creates sensitive, nonextractable signing pairs;
`--bits` is rejected. `generation-options` includes an `eddsa` array.
`capabilities`, `certificate`, `bind` and `export` select this family with
`--key-family eddsa`. Public export emits RFC 8410 SPKI DER;
`import --kind eddsa --purpose verification` imports that format with an explicit
ID/label. Mutations require `--confirm` and RW access.
`verify-token` uses the selected public key on the token; `verify` uses a token
certificate or an offline `--certificate-file`. Certificate binding and software
verification do not validate issuer trust. Signature files contain raw 64/114-byte
RFC 8032 signatures. Context/prehash schemes use the separate commands below;
X25519/X448 agreement uses the key-establishment commands.

## RFC 8032 curveName EdDSA

`generate --kind edwards25519|edwards448` creates a protected signing pair with
explicit curveName parameters. `import --kind edwards25519|edwards448` accepts
exactly 32/57 raw public bytes and enables verification only;
`export --key-family edwards25519|edwards448` emits checked raw public bytes.
These profiles reject OID keys and do not convert to/from SPKI. Generation/import
require RW mode, `--confirm`, bounded nonempty identity and unused IDs.
`generation-options` reports advisory choices in `eddsa_named`.

`sign-eddsa-named` and `verify-eddsa-named` require `--object` with private/public
class respectively and an explicit `--scheme ed25519|ed25519ctx|ed25519ph|ed448|ed448ph`.
`--input` supplies the original message from a file or stdin; ph hashing runs on
the token. Optional `--context-file` supplies at most 255 binary bytes from a
file. Ed25519 rejects nonempty context; Ed25519ctx with empty context remains a
distinct scheme. There is no digest, certificate-binding or software-verification
mode in these commands. `verify-eddsa-named --signature` accepts a raw signature
file or stdin; only one verification input may use stdin.

Signing supports `--context-pin-file`/`--context-protected-path` for
always-authenticate keys. Signatures and verification results are released only
after checked session closure and module finalization. Mismatches return exit 4;
provider failures are not retried.

```sh
pkcs11ctl --module "$MODULE" generate --token "$TOKEN_URI" --kind edwards25519 \
  --id 0800 --label edwards-signer --pin-file user.pin --confirm
pkcs11ctl --module "$MODULE" sign-eddsa-named --object "$PRIVATE_KEY_URI" \
  --scheme ed25519ph --input message.bin --context-file context.bin \
  --output signature.bin --pin-file user.pin
pkcs11ctl --module "$MODULE" verify-eddsa-named --object "$PUBLIC_KEY_URI" \
  --scheme ed25519ph --input message.bin --context-file context.bin \
  --signature signature.bin --pin-file user.pin
```
