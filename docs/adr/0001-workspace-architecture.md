# ADR 0001: workspace architecture

Status: accepted; CLI dependency rules amended by [ADR 0010](0010-cli-client-boundary.md)
on 2026-09-27. Original decision date: 2026-09-05.

## Decision

The repository/workspace is `pkcs11-stack`, an independent Rust implementation
above cryptoki. A shared runtime owns PKCS#11 state and token operations. Client
provides application and management workflows, which the CLI uses for all provider
operations.
This is neither a binding/port of libp11 or OpenSC nor an OpenSSL integration.

Dependency arrows below mean “depends on”. These are the actual initial sibling
and principal external edges:

```text
pkcs11-locator        -> secrecy, zeroize, thiserror
pkcs11-runtime        -> pkcs11-locator, cryptoki, secrecy, thiserror
pkcs11-client            -> pkcs11-runtime
pkcs11ctl             -> pkcs11-runtime, clap
pkcs11-rustls-adapter -> pkcs11-runtime, rustls, rustls-pki-types
```

| Crate | Responsibility | Allowed siblings | Forbidden siblings |
| --- | --- | --- | --- |
| pkcs11-locator | RFC 7512 syntax, binary IDs, selectors, matching, redaction | None | All |
| pkcs11-runtime | Module/token/session/authentication lifecycle, objects, capabilities, generic operations, recovery | locator | client, ctl, adapter |
| pkcs11-client | Ergonomic application workflows | runtime; locator when directly useful | ctl, adapter |
| pkcs11ctl | Administration, inspection, diagnostics, CLI presentation | client; locator when directly useful | runtime, adapter |
| pkcs11-rustls-adapter | External TLS signing and credentials | runtime; locator when directly useful | client, ctl |

The runtime is the only direct cryptoki consumer. No other workspace crate may
provide another FFI boundary. Only the adapter may depend on rustls or expose
rustls types. In particular, locator must not depend on cryptoki or the runtime.
Do not introduce micro-crates for types, errors, sessions, objects or mechanisms.
Shared lifecycle, authentication, recovery and token operations belong in runtime;
application workflows such as verified identity binding belong in client. CLI
must reuse those workflows instead of reimplementing them. Client must never
depend on CLI, directly or transitively. Another crate needs a coherent independent
domain and demonstrated consumers.

The graph above records the initial manifests. Stage 6 adds
`pkcs11ctl -> pkcs11-client` while retaining `pkcs11ctl -> pkcs11-runtime`.
The later [ADR 0010](0010-cli-client-boundary.md) removes direct CLI runtime access;
the current CLI manifest contains client and locator. See the
[Stage 6 specification](../stage-6-spec.md) for routing and acceptance requirements.

## Name preflight, before manifests

Direct GET requests to `https://crates.io/api/v1/crates/{name}` and GitHub's
repository search API (`q={name}+in:name&per_page=100`) were executed on
2026-09-05. GitHub matches were filtered by exact repository basename,
case-insensitively. All search responses were HTTP 200, not incomplete, and
contained fewer than 100 results. Snapshot: [preflight JSON](preflight-2026-09-05.json).
These checks concern public indexed repositories, not private repositories or
ownership guarantees. They do not reserve names.

| Proposed name | crates.io exact GET | GitHub search total | Exact GitHub basename matches |
| --- | --- | ---: | --- |
| pkcs11-locator | 404, absent | 0 | None |
| pkcs11-runtime | 404, absent | 0 | None |
| pkcs11-client | 404, absent | 6 | [mlecar/pkcs11-client](https://github.com/mlecar/pkcs11-client), [JoeyGii/pkcs11-client](https://github.com/JoeyGii/pkcs11-client) |
| pkcs11-rustls-adapter | 404, absent | 0 | None |
| pkcs11ctl | 404, absent | 0 | None |
| pkcs11-testkit | 404, absent | 0 | None |

Retain `pkcs11-client` as explicitly requested by the project owner. The initial
rename based on GitHub repository matches was incorrect; this decision supersedes
that interpretation. The exact crates.io check found no occupied crate name.
All six proposed names remain selected. The preflight JSON records the requested name checks and dependency metadata.
`pkcs11-testkit` is checked only; create it only when two consumers need substantial
shared software-token provisioning. Nothing is published or reserved.

## Dependency and toolchain selection

Stable crates.io metadata and downloaded release manifests agree on the versions,
MSRVs and licenses recorded in [ADR 0006](0006-licensing.md). Use edition 2024,
resolver 3, and Rust 1.85, the edition/resolver minimum and the highest declared
minimum among these selected direct dependencies (clap and zeroize). Do not base
the MSRV on the installed Rust 1.97. Commit Cargo.lock, use locked CI, and test
1.85.0 explicitly. Semver-compatible updates require rerunning that check.

Workspace dependency entries centralize versions. Initial skeletons intentionally
have no public domain types; dependencies establish compilation boundaries for
later milestones. Rustls disables default features and enables only `std`, so
the adapter does not choose a software provider. Applications must choose one
explicitly. Stage 7 adds optional TLS 1.2 and a ring dev-dependency for acceptance;
production still selects no provider.

## Original Stage 1 scope and continuing constraints

At the original decision, only Stage 0 research and Stage 1 scaffolding existed.
Stages 2–7 are now implemented, including the client-backed CLI and TLS adapter.
Keep synchronous calls explicitly synchronous, use typed
errors when operations are introduced, redact secrets, and forbid workspace
unsafe code. See the [Stage 7 specification](../stage-7-spec.md) for the
implemented TLS boundary. The client-only provider boundary for CLI is implemented in ADR 0010.

See [preflight research](../preflight.md) for upstream API findings and limitations.
