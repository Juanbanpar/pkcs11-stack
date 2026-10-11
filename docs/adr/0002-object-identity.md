# ADR 0002: persistent object identity

Status: accepted principles; locator API implemented in Stage 2. Date: 2026-09-05.

## Context and decision

Persistent references use RFC 7512 selectors from `pkcs11-locator`. A conceptual
`ObjectRef` combines token and object selectors; this is not yet a Rust type.
Token identity uses label, manufacturer, model and serial where possible. Object
selection includes class and binary CKA_ID as appropriate. Labels and IDs need
not be globally unique, so ambiguous discovery must fail explicitly.

A cryptoki `ObjectHandle` is an operational handle, not durable identity. The
runtime will resolve a selector in the leased session immediately before use.
Treat handles conservatively as session/context-local even when a module accepts
them across sessions. Never store an unscoped handle in a long-lived key object.
Caches, if justified, belong to session and runtime generations and are invalidated
on logout where relevant, session recreation, token removal and module restart.

Slot IDs remain available for explicit CLI selection and diagnostics. They are
not preferred persistent token identity. Token metadata and selectors remain
separate from mutable authentication/session state.

## Consequences

Do not promise uniqueness from one label or select the first match. No exact
public reference struct or handle-cache implementation is fixed in Stage 1.
Locator parsing and matching will be pure, independently testable operations.
Binary IDs must not be forced through UTF-8. PIN-bearing URI formatting requires
redaction by default and a separate explicit secret-inclusive operation.

Sources: [RFC 7512, sections 2.3–2.7](https://www.rfc-editor.org/rfc/rfc7512.html),
[cryptoki object API](https://docs.rs/cryptoki/0.12.0/cryptoki/object/index.html).


## Stage 2 decision: URI data, criteria and discovery metadata

Stage 2 introduces `Pkcs11Uri`, a validating builder, borrowed module/slot/token/
object selector views and separate discovered identity structs. `ResourceIdentity`
combines the discovery context, and `Pkcs11Uri::matches` checks every level.
Per-level matching is explicitly partial. Unknown path constraints fail closed;
unknown query attributes are preserved and ignored by built-in matching. A
runtime `ObjectRef`, uniqueness/ambiguity resolution and handle caches remain
unimplemented and are not fixed by the locator API.

Use generic named attribute insertion/access rather than a large speculative set
of builder setters. Retain decoded byte IDs. Standard numeric values normalize to
bounded integers; known fixed metadata widths are validated. Names and object
class spellings are ASCII case-insensitive; vendor names follow that documented
policy. Text matching is byte-exact, with only fixed-field padding removed from
actual metadata. No implicit Unicode normalization, filesystem resolution or full
RFC section 2.6 URI-equivalence API is introduced. Module paths use the current
platform's absolute-path rules and conservative exact matching.

Display/Debug redact both PIN values and PIN sources. All query values use
SecretString storage; explicit `to_secret_uri` returns a SecretString rather than
an ordinary String. Do not derive Clone or equality for the URI. Decode scratch
buffers zeroize; secret serialization preallocates its encoded size. Error variants
contain no input values or names. Full behavior and malformed-input policies are
in the locator README. These decisions refine the accepted architecture without
adding dependencies or crossing into runtime implementation.


## Stage 3 runtime references (2026-09-06)

Runtime ObjectRef now owns a validated locator rather than a handle. It requires
token/object criteria, rejects authentication queries and slot IDs, and permits
module-path only among query attributes. Unknown selectors and unsupported
module-name resolution fail at reference construction. Session::resolve checks
module, slot and token criteria, searches token objects afresh and checks object
metadata before requiring exactly one match. Generic template search can also
return session objects, but its operational Object values are session-borrowed
and are not persistent references. There is no handle cache or public raw handle.

Token resolution is explicit and rejects ambiguity; ObjectRef resolution is within
the already selected session/token. Criteria are not guaranteed globally unique.
Generic attribute values have redacted runtime Debug and an explicit raw-value
accessor; callers remain responsible for sensitive extractable attribute data.
