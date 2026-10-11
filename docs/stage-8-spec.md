# Stage 8: API contracts and application examples

Scope: review the public interfaces delivered by Stages 1–7 and demonstrate them
in runnable consumer applications. [ADR 0011](adr/0011-application-api-contracts.md)
records construction, public type exposure, errors, authentication and ownership.

Deliver four examples:

- Generic RSA PKCS#1 v1.5/SHA-256 signing through `pkcs11-client`.
- Explicit key/certificate binding followed by verified signing through client.
- A TLS 1.3 server using a token key and the adapter's server configuration builder.
- A verifying TLS client with optional token-backed authentication for mutual TLS.

Use explicit trusted module paths, stable selectors and PIN files. Never accept
PIN values as arguments. Read PIN buffers into zeroizing storage, bound their size,
and propagate failures without retries. The TLS callback reads its secret source
per operation. Examples deliberately use ordinary keys without context login;
existing always-authenticate acceptance remains separate.

Client signing examples write only raw signature bytes to stdout after successful
explicit finalization. TLS examples exchange application data over loopback with
normal server name, root and client certificate verification. Neither example
generates, imports or extracts private keys. Show successful explicit shutdown and
document best-effort Drop behavior on early errors.

Add the examples to the existing isolated software-token runner before tests mutate
their fixtures. Independently verify both signatures with OpenSSL. Require bound
signing with a mismatched certificate to fail without output, and require TLS to
reject unrelated trust roots and missing credentials when client authentication is
required. Bound server process lifetimes and clean temporary files/processes.

Compile and test each crate separately in CI as well as preserving workspace,
MSRV, architecture and provider-feature checks. Run all examples in both SoftHSM
CI lanes. Validate Rust 1.85 and stable locally. Record actual results and dependency
changes in the completion report.

This stage does not publish crates, introduce new cryptographic operations, change
hardware support claims or complete release packaging. Fuzzing, platform expansion
and distribution preparation remain subsequent work.
