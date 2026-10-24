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
| `objects --token URI` | Persistent object summaries; no secret values |
| `inspect --object URI` | Unique object's attributes, defaulting to class/label/ID |
| `export --object URI --output PATH` | Raw certificate/data CKA_VALUE or public-key SPKI DER |
| `certificate --object URI` | Supported certificate key summary and SPKI through client |
| `capabilities --key URI` | Signing capabilities and available public key metadata |
| `plan --key URI ...` | Selected signing plan, without signing |
| `bind --key URI --certificate URI` | One signature proving explicit key/certificate association |
| `sign --key URI [--certificate URI] ...` | Generic signing, or binding followed by verified signing |
| `verify --certificate-file PATH ...` or `verify --certificate URI ...` | Software verification against a certificate public key |
| `random --token URI --length N --output PATH` | Token-generated random bytes |
| `diagnose --token URI --pool-size N` | Bounded lease capacity/exhaustion/reuse and session role |
| `init-token --slot ID --expected-token URI --label LABEL --so-pin-file PATH --confirm` | Initialize or erase a token |
| `init-pin --token URI --role so --pin-file PATH --new-pin-file PATH --confirm` | Initialize/reset USER PIN |
| `set-pin --token URI --pin-file PATH --new-pin-file PATH --confirm` | Change the authenticated USER/SO PIN |
| `generate --token URI --kind KIND --id HEX --label LABEL --confirm` | Persistent sensitive, nonextractable signing key pair |
| `import --token URI --kind cert\|data --id HEX --label LABEL --input PATH --confirm` | Public certificate or data import |
| `set-label --object URI --label LABEL --confirm` | Relabel exactly one object |
| `delete --object URI --confirm` | Delete exactly one object |

Object summaries use the client's locator builder. Their `uri` is `null` when the
available metadata cannot form a supported selector; other summaries remain
available. Duplicate locators can still be ambiguous when passed to `inspect`.

`inspect --attributes` accepts a comma-separated list: `class`, `label`, `id`,
`object-id`, `private`, `sign`, `sensitive`, `extractable`, `always-authenticate`,
`key-type`, `modulus`, `exponent`, `ec-params`, `ec-point`, `subject`, `issuer`,
`serial`, `value`. Values are explicit; requesting `value` can reveal sensitive
application data if the token permits it. Attribute statuses distinguish
available, unsupported, sensitive and unavailable. Byte attributes are encoded
as hexadecimal; labels also have a UTF-8 text field when valid. Defaults never
request secret key material. `export` refuses private/secret-key classes. Public-key
export validates RSA or P-256/P-384/P-521 public attributes and encodes SPKI DER;
`--key-family ml-dsa` exports an ML-DSA public key instead;
certificate/data export retains its raw-value behavior.

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

`sign`, `plan` and `verify` accept `--algorithm ml-dsa-44|ml-dsa-65|ml-dsa-87`.
These are pure ML-DSA requests: digest input, `--digest`, PSS parameters and
`--hashing` are rejected. Messages are limited to 64 MiB; empty messages are valid.
`--context-file PATH` supplies up to 255 binary context bytes, defaulting to empty.
It requires a file path, while `--input -` can read the message from stdin.
Verification must use the same context as signing.

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

`generate` supports `rsa`, `p256`, `p384`, `p521` and the ML-DSA kinds above.
RSA defaults to 2048 bits;
`--bits` accepts multiples of eight from 2048 to 16384, subject to provider bounds.
`--always-authenticate` sets the private key's context-authentication requirement.
Both objects are persistent and share the explicit binary ID and label. The private
key is sensitive and nonextractable. Duplicate IDs/labels are possible and can make
later selectors ambiguous; the command does not overwrite an existing key.

Certificate import accepts exact X.509 DER, including algorithms unsupported for
client signing. The client parses subject/issuer/serial metadata for the runtime
creation template; it does not validate certificate trust. Data bytes remain
uninterpreted. `--id` maps to CKA_ID for certificates/keys and CKA_OBJECT_ID for data;
select data objects by their label. Imported objects are persistent and public.

Raw certificate export and inspection work independently of client key support.
Arbitrary JSON templates, private/secret-key import/export, wrapping, encryption,
decryption, derivation and vendor-specific administration are not implemented.
Runtime exposes generic creation/update templates for library callers. Attribute
updates may partially succeed before a provider reports failure; runtime marks
that session unusable and does not attempt rollback.

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

## Testing

```sh
cargo test -p pkcs11ctl --locked
./tools/test-softhsm.sh
```

Unit tests check argument validation, independent verification fixtures, redaction,
output preservation and exit codes. SoftHSM tests exercise inspection, signing,
verification, random generation and administration commands. The required PQC
provider lane also tests ML-DSA CLI workflows and OpenSSL interoperability.
