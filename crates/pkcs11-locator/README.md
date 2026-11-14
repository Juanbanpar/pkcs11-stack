# pkcs11-locator

RFC 7512 URI parsing, construction and selector matching without module loading
or hardware access.

```rust
use pkcs11_locator::{Pkcs11Uri, ResourceIdentity, ObjectType};

let uri: Pkcs11Uri =
    "pkcs11:token=production;object=server-key;type=private;id=%00%FF".parse()?;
let mut discovered = ResourceIdentity::default();
discovered.token.label = Some("production");
discovered.object.label = Some("server-key");
discovered.object.object_type = Some(ObjectType::Private);
discovered.object.id = Some(&[0, 255]);
assert!(uri.matches(&discovered));
# Ok::<(), pkcs11_locator::Error>(())
```

## Model and construction

`Pkcs11Uri` stores validated decoded attributes. Its builder accepts decoded path
bytes and owned `SecretString` query values, applying the same validation as parsing.
Attribute setters return typed errors rather than silently replacing values.

```rust
use pkcs11_locator::Pkcs11Uri;
use secrecy::{ExposeSecret, SecretString};

let uri = Pkcs11Uri::builder()
    .path_attribute("token", b"production")?
    .path_attribute("id", &[0, 255])?
    .query_attribute("pin-value", SecretString::from("example-only"))?
    .build()?;
assert!(!uri.to_string().contains("example-only"));
let serialized = uri.to_secret_uri(); // protected, zeroized storage
assert!(serialized.expose_secret().contains("example-only"));
# Ok::<(), pkcs11_locator::Error>(())
```

`ModuleSelector`, `SlotSelector`, `TokenSelector` and `ObjectSelector` borrow URI
criteria. Their `matches` methods check one level; `Pkcs11Uri::matches` checks the
complete `ResourceIdentity`. Discovered identities borrow metadata without handles
or session state. Initialize with `Default` and populate available fields; missing
fields mean unknown, not empty.

## Syntax and matching policy

| Area | Behavior |
| --- | --- |
| Scheme and names | ASCII case-insensitive, serialized lowercase. Vendor attribute names use the same rules. |
| Duplicates | Reject every duplicate path name and duplicate standard query name. Retain vendor query duplicates in insertion order. |
| Unknown attributes | Preserve valid vendor attributes. Any unknown path constraint prevents matching. Ignore unknown query attributes during built-in matching. |
| Empty values | Preserve empty text and binary values. Present empty criteria match empty metadata only; absent criteria are wildcards. Empty URI and empty query are accepted. |
| Object class | Support public, private, cert, secret-key and data. Case-insensitive literal values; unknown, empty or percent-encoded type names are rejected. |
| Percent encoding | Decode exactly once; reject incomplete/non-hex escapes. Reject raw characters outside the component grammar, including raw whitespace, non-ASCII and fragments. Plus is a literal plus. |
| UTF-8 and binary | Text values must decode to UTF-8. Only path `id` accepts arbitrary bytes. Text matches exactly, with no implicit Unicode normalization. |
| Metadata limits | Enforce PKCS#11 fixed-field byte widths (16/32/64 as applicable), ASCII serial numbers and no NUL in fixed text fields. Object labels and IDs are not width-limited. |
| Numeric fields | Decimal slot IDs fit u64; library major/minor each fit u8. Normalize leading zeros and an omitted minor version to zero. No signs or percent-encoded numeric syntax. Consumers must also enforce native CK_ULONG width when resolving a slot. |
| Padding | Strip trailing ASCII space padding only from discovered fixed-width fields, never from CKA_LABEL, CKA_ID or URI criteria. |
| Module selectors | Combine library path criteria and query module restrictions. Logical module names compare ASCII case-insensitively. Module paths must be absolute on the current platform and NUL-free. |
| Module paths | Compare decoded paths exactly. Discovery decides whether a path denotes a module or directory and supplies the corresponding identity; no symlink, directory or filesystem resolution occurs here. |
| Serialization | Sort path/query names, preserve same-name query order, uppercase hex, encode all ID bytes and encode textual bytes outside the unreserved set. Empty query markers are omitted. |

Construction uses decoded values, so a literal percent sign is encoded on output.
Known names in the wrong component are rejected. All matching constraints combine
with logical AND; the crate does not select the first candidate or guarantee that
metadata uniquely identifies an object. Cardinality/ambiguity belongs to discovery.
Full RFC section 2.6 URI equivalence (including nested PIN-source URI and filesystem
path normalization) is not an API here. Deterministic serialization is not a
resource-identity or full URI-equivalence guarantee.

## Secret handling

| Surface | Secret handling |
| --- | --- |
| `pin-value` / `pin-source` | Mutually exclusive; redacted in URI, builder and selector Display/Debug |
| Query storage | `SecretString`; access requires explicit `ExposeSecret` |
| URI Display | Diagnostic `[REDACTED]` markers; unsuitable for credential persistence |
| `to_secret_uri` | Full serialization in zeroizing, Debug-redacted storage |
| Unknown query attributes | Visible in Display; callers must supply their own redaction if storing secrets |

Decoding uses zeroizing scratch storage; full serialization reserves encoded size
before writing secrets. Errors omit input values and attacker-controlled names.
Original input and copies made after exposure remain the caller's responsibility.
PIN-source values are stored without interpretation or execution.

## Testing

```sh
cargo test -p pkcs11-locator --locked
cargo clippy -p pkcs11-locator --all-targets --locked -- -D warnings
```

Tests cover parsing, binary IDs, matching, serialization and secret redaction.
