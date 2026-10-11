# ADR 0011: application API contracts

Status: accepted, 2026-09-27.

## Construction and ownership

Prefer `Provider::load` followed by `Provider::client` or `Provider::management`
for application workflows. Both consumers borrow the provider. Close management
sessions and drop signing clients before explicit provider finalization. Drop is
best-effort cleanup on early returns; callers needing cleanup errors must use the
explicit consuming methods.

Retain `Module`, `SessionPool`, `Client::connect`, `Client::new` and `Client::pool`
as documented advanced interfaces for applications coordinating runtime resources.
They share the existing runtime ownership model. Do not add another owner, pool or
opaque wrapper solely to hide those types. `Provider` does not expose a raw session
or object handle through its management API.

TLS applications use runtime's `Arc<Module>` and owned pools because rustls retains
signers with a `'static` lifetime. Stop connections and drop configs, resolvers and
credentials before `Arc::try_unwrap` and explicit module finalization. This is a
different ownership requirement from a borrowed signing client, not a second runtime.

## Public types and errors

The client's explicit runtime re-exports are intentional public dependencies:
selectors, authentication, policy, requests, capabilities, metadata and attribute
types retain their runtime identity. Some metadata and attribute types originate
in cryptoki. This facade does not promise insulation from changes to these exposed
types. Review their compatibility when updating runtime or upstream dependencies.
The adapter similarly exposes rustls types at its TLS boundary.

Keep exported management names explicit. New internals must not become public
merely because a module uses a wildcard re-export. Existing constructors and
re-exports remain available; no signature change is required by this review.

Errors retain typed sources for detailed diagnosis. Consumers wanting semantic
categories use `pkcs11_client::Error::kind`, with a fallback for non-exhaustive
variants. Display/Debug strings are diagnostics, not a parsing contract. Categories
do not define CLI exit codes or authorize retries. A provider omitting an attribute
status is `ErrorKind::Runtime`; requesting unsupported export is `ErrorKind::Input`.
The CLI owns its mapping from these categories to its documented exit codes.

Public request/policy structs remain explicit. Adding required fields or variants
to exhaustive public enums requires compatibility review. Before publication,
record API changes in release notes and choose a version appropriate to their
compatibility; the current `0.1.0` manifests are still unpublished scaffolding.

## Operation contracts

- URI selectors never load code, establish uniqueness, or prove a key/certificate
  association. Resolution rejects ambiguity and rediscovers handles at execution.
- `Authentication::None` leaves login state unchanged. USER/SO login is token-wide;
  an already established role can avoid PIN revalidation. Context authentication
  is explicit and per signing operation. Neither library silently prompts.
- Pool exhaustion is immediate. Planning is advisory. Signing, authentication and
  mutations are not retried after failure; mutation failure may have partial effects.
- Binding proves possession of the selected certificate's key, and bound signing
  verifies each result. Certificate trust remains the application's responsibility.
- `server_config_builder` aligns suites with selected protocol versions. Applications
  still choose the software provider, peer verification and credential order.
- Explicit attribute access may expose secret data. Redacted Debug output is not
  encryption and does not make returned attribute bytes safe to log.

## Consumer evidence

The [application examples](../examples.md) use the public APIs and ordinary process
I/O. Client examples depend on client, not runtime directly. TLS examples choose
ring as applications through a dev-dependency; production adapter dependencies
remain provider-free. Isolated acceptance executes signatures and loopback TLS,
including binding/trust failures. Independent crate CI checks avoid workspace-wide
feature unification hiding missing dependency declarations.
