# ADR 0010: CLI consumes the client library

Status: accepted, 2026-09-27. Supersedes [ADR 0009](0009-cli-library-reuse.md).

`pkcs11ctl` depends on `pkcs11-client` for all provider workflows. It has no direct
runtime dependency or runtime calls hidden behind lifecycle-type reexports.
Locator remains a direct dependency for URI input and display. Client never depends
on CLI; runtime never depends on client. The TLS adapter boundary is unchanged.

Client adds a provider owner and scoped management sessions for discovery,
attribute inspection, certificate/data import/export, key generation, PIN/object
administration and pool diagnostics. These expose typed data and complete reusable
workflows, not command names, JSON or arbitrary access to raw sessions/objects.
Existing application signing and binding APIs remain compatible. Runtime still
owns initialization, sessions, authentication, operations, pooling and recovery.

One client provider wraps one runtime Module. Signing clients and management
sessions borrow it and must drop before explicit finalization. Management sessions
retain explicit close and authentication semantics; pooling does not silently
replace a one-session administration operation. PINs remain borrowed, mutations
and signatures are never retried, and token-wide login behavior is unchanged.

CLI owns arguments, input validation/policy choices, credential acquisition,
confirmation flags, file I/O, output schemas and exit codes. Client owns import
metadata/templates, export class restrictions, attribute status reads and the
pool diagnostic workflow. Generic inspection/export must not apply the supported
signing algorithms of `Certificate` to raw certificate values. Client errors expose
semantic categories; CLI maps these to the existing presentation/exit contracts.

Acceptance preserves all twenty command families, tests the client management API
directly, and rejects a CLI-to-runtime dependency in the Cargo graph. Run workspace
stable/MSRV checks and the existing software-token lanes. Historical stage reports
retain the architecture they validated; current guides/specifications follow this
ADR. See the [refactor report](../cli-client-refactor-report.md) for actual results.
