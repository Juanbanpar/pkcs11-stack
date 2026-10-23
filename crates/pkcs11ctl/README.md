# pkcs11ctl

PKCS#11 inspection, signing and administration. through `pkcs11-client`.

## Invocation

```sh
pkcs11ctl --module /absolute/path/to/trusted-pkcs11.so tokens
pkcs11ctl --module /absolute/path/to/trusted-pkcs11.so --format json info
pkcs11ctl sign --help
```

`--module` explicitly chooses trusted executable vendor code; a URI never loads a
library. `--module` and `--format text|json` may appear before or after a command.
Help/version need no module.

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
| `export --object URI --output PATH` | Raw certificate/data CKA_VALUE or RSA/EC public-key SPKI DER |
| `certificate --object URI` | Supported certificate key summary and SPKI through client |
| `capabilities --key URI` | Signing capabilities and available public key metadata |
| `plan --key URI ...` | Selected signing plan, without signing |
| `bind --key URI --certificate URI` | One signature proving explicit key/certificate association |
| `sign --key URI [--certificate URI] ...` | Generic signing, or binding followed by verified signing |
| `diagnose --token URI --pool-size N` | Bounded lease capacity/exhaustion/reuse and session role |
| `init-token --slot ID --label LABEL --so-pin-file PATH --confirm` | Initialize or erase a token |
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
client signing uses USER/RO sessions. One invocation owns one client Provider and finalizes
it after all clients/sessions are dropped.

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

`sign` and `plan` require `--algorithm rsa-pkcs1|rsa-pss|ecdsa`,
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

## Administration

Every mutation requires `--confirm` and executes once without automatic rollback
or retry. `init-token` can destroy all objects and takes an explicit current slot
ID. Runtime requires exclusive access to the module for initialization, so no
borrowed token/session can survive it. Token labels are at most 32 UTF-8 bytes.

`generate` supports `rsa`, `p256`, `p384` and `p521`. RSA defaults to 2048 bits;
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

Unit tests check argument validation, redaction, output preservation and exit
codes. SoftHSM tests exercise inspection, signing and administration commands.
