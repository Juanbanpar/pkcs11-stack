# Stage 8 completion — 2026-09-27

Completed the [API contracts and application examples scope](stage-8-spec.md).

## API review

[ADR 0011](adr/0011-application-api-contracts.md) records preferred `Provider`
construction, borrowed client/management ownership, owned TLS pools, explicit
shutdown, token-wide authentication and no-retry behavior. Existing `Module`,
`SessionPool` and client pool access remain advanced public interfaces. Re-exported
runtime/upstream types are intentional compatibility obligations. No constructor
signature or public type was removed or replaced.

Changed the client management re-export to an explicit list, preserving all current
names. Corrected `Error::MissingAttributeStatus` from `ErrorKind::Input` to
`ErrorKind::Runtime`: a provider omission cannot be repaired by changing user input.
The CLI's existing category mapping now reports this as backend exit 5 instead of
input exit 2. A pure regression distinguishes it from unsupported export input.

## Runnable consumers

The [application guide](examples.md) documents four examples:

| Example | Public workflow |
| --- | --- |
| `pkcs11-client / sign` | Generic RSA PKCS#1 v1.5/SHA-256 signing through `Provider::client` |
| `pkcs11-client / bound_sign` | Explicit certificate binding and verified signing |
| `pkcs11-rustls-adapter / tls_server` | Token-backed TLS 1.3 server, optionally requiring client authentication |
| `pkcs11-rustls-adapter / tls_client` | Normal server verification, optionally with a token-backed client identity |

PIN files use bounded, zeroizing input buffers. TLS callbacks read their secret
source per operation. Signing examples emit raw bytes only after explicit module
finalization. TLS examples use separate processes and real loopback sockets, normal
trust verification and the adapter's protocol-aware server builder. They drop
connections/configs before explicit module finalization. Early errors propagate
with best-effort Drop cleanup. These demonstrations use ordinary RSA keys and the
existing application policies; they add no private-key export or provider fallback.

`tools/test-examples.sh` is integrated into the isolated SoftHSM runner before
existing tests mutate the fixture keys. It independently verifies both signatures
with OpenSSL, rejects mismatched binding without output, completes server and
mutual TLS, and rejects wrong server trust and missing required client credentials.
It bounds server process lifetimes and cleans temporary files/processes; a server
timeout is not accepted as a successful rejection.

CI adds one check/test job per crate to catch dependencies or features supplied
accidentally by unrelated workspace members. Both SoftHSM jobs now execute the
application examples as part of the existing runner. Equivalent commands were
validated locally.

## Validation

Validated in a disposable Fedora 44 container:

| Check | Result |
| --- | --- |
| Stable Rust 1.97.1: formatting, all-target workspace check, Clippy with warnings denied | Passed |
| Stable and Rust 1.85.0 workspace tests | 53 ordinary tests and 14 doctests each, including 7 compile-fail checks |
| Rust 1.85.0 all-target workspace check, including all four examples | Passed |
| Stable: each of five crates checked/tested independently | Passed |
| Dependency boundaries and provider-free adapter checks, with/without TLS 1.2 | Passed |
| Packaged SoftHSM `2.7.0-0.1.rc1.fc44.1`, stable and Rust 1.85.0 | All 6 integration tests plus application example acceptance passed |
| Upstream SoftHSM `884cb38f3d2012a0447bd5f50dbd29c429987c41`, stable | All integration tests and examples passed; all 3 combined ECDSA/context-authentication mechanisms verified |
| Shell syntax, CI YAML, local Markdown links and Rust SPDX headers | Passed |

Client and adapter add the existing zeroize 1.9.0 as a dev-dependency for their
examples. The lockfile adds those two edges; no dependency package versions changed.
Client examples use client without a direct runtime import. TLS examples use the
existing runtime/adapter boundary. Production adapter dependencies select no
software TLS provider.

## Subsequent work

Publication remains disabled. Fuzz/property testing, a supported-platform matrix,
crate packaging, release metadata and release procedures remain the next release
preparation work. The existing hardware/provider limitations remain as documented
in the [project review](project-review-2026-09-27.md).
