# pkcs11-locator

Hardware-independent RFC 7512 URI parsing, construction and selector matching.
Stage 2 is implemented. This crate performs no module loading, discovery,
authentication, filesystem access, command execution or network I/O.

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

`Pkcs11Uri` stores validated decoded attributes. `Pkcs11UriBuilder` accepts decoded
bytes for path attributes and owned `secrecy::SecretString` values for query
attributes. The same validation applies to builder and parser. Attribute setters
return typed errors instead of silently replacing earlier values.

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

`ModuleSelector`, `SlotSelector`, `TokenSelector` and `ObjectSelector` are borrowed
views of a URI's criteria. Their `matches` methods check only the named level;
use `Pkcs11Uri::matches(ResourceIdentity)` to check the complete hierarchy.
Discovered identities are separate, borrowed metadata structs, with no handles or
session state. Missing identity fields are unknown, not empty. Initialize them
with `Default` and assign the available public fields.

## Syntax and matching policy

| Area | Behavior |
| --- | --- |
| Scheme and names | ASCII case-insensitive, serialized lowercase. Vendor attribute names follow the same explicit policy. |
| Duplicates | Reject every duplicate path name and duplicate standard query name. Retain vendor query duplicates in insertion order. |
| Unknown attributes | Preserve valid vendor attributes. Any unknown path constraint prevents matching. Ignore unknown query attributes during built-in matching. |
| Empty values | Preserve empty text and binary values. Present empty criteria match empty metadata only; absent criteria are wildcards. Empty URI and empty query are accepted. |
| Object class | Support public, private, cert, secret-key and data. Case-insensitive literal values; unknown, empty or percent-encoded type names are rejected. |
| Percent encoding | Decode exactly once; reject incomplete/non-hex escapes. Reject raw characters outside the component grammar, including raw whitespace, non-ASCII and fragments. Plus is a literal plus. |
| UTF-8 and binary | Text values must decode to UTF-8. Only path `id` accepts arbitrary bytes. Text matches exactly, with no implicit Unicode normalization. |
| Metadata limits | Enforce PKCS#11 fixed-field byte widths (16/32/64 as applicable), ASCII serial numbers and no NUL in fixed text fields. Object labels and IDs have no invented fixed width. |
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

`pin-value` and `pin-source` are mutually exclusive. Both are redacted in Display,
Debug, builder Debug and selector Debug. Display uses `[REDACTED]` markers; it is
for diagnostics, not persistence of credentials. Query values are stored in
`SecretString`, exposed only through an explicit `ExposeSecret` call. Unknown
query values remain visible in URI Display, so callers must not put secrets in
arbitrary vendor attributes unless they apply their own redaction policy.

`to_secret_uri` explicitly serializes the full URI into `SecretString`; its Debug
is also redacted. Decoding uses zeroizing scratch storage, and full serialization
reserves its encoded size before writing secrets. Errors contain neither input
values nor attacker-controlled names. This does not erase the caller's original
input or any copies made after secret exposure. PIN-source values are stored
without interpreting or executing them.

## Dependencies, tests and license

Only `secrecy`, `zeroize` and `thiserror` are dependencies. All sibling dependencies,
cryptoki, rustls and clap are forbidden. Runtime lifecycle, hardware discovery,
cryptography and protocol integration are non-goals.

Run `cargo test -p pkcs11-locator` and
`cargo clippy -p pkcs11-locator --all-targets -- -D warnings`.
Tests cover binary IDs, Unicode, delimiters, invalid syntax, metadata limits,
matching, construction, stable serialization and secret redaction without a token.

Original code and documentation are licensed under [MIT](../../LICENSE-MIT) OR
[Apache-2.0](../../LICENSE-APACHE), at your option. See
[ADR 0002](../../docs/adr/0002-object-identity.md) for the Stage 2 design decision.
