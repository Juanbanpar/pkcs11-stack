# CLI client refactor report

Completed locally on 2026-09-27. The CLI now uses `pkcs11-client` for every provider
workflow and has no direct `pkcs11-runtime` dependency, imports or calls through
runtime lifecycle reexports. Locator remains available for URI input/display.
[ADR 0010](adr/0010-cli-client-boundary.md) supersedes the earlier mixed dependency
model; the Stage 6 specification and current guides have been updated.

## Changes

Client adds `Provider`, which owns one runtime Module, and `ManagementSession`,
which borrows that provider and wraps one explicitly authenticated runtime session.
Provider supports library/slot/token/mechanism discovery, signing-client creation,
scoped management sessions, token initialization, pool diagnostics and explicit
finalization. Metadata snapshots contain no live object handles.

Management supplies attribute availability/value snapshots, raw certificate/data
export, parsed certificate and data import, sensitive nonextractable key generation,
PIN initialization/change, relabel and deletion. Export restrictions and import
templates now live in the library. Unsupported signing algorithms remain available
for raw certificate inspection/import/export; Ed25519 round trips are tested.

The client also supplies object/token URI validation/projection and semantic error
categories. CLI retains arguments, credential acquisition, confirmation flags,
file I/O, presentation, JSON schema and exit codes. It no longer creates sessions,
pools or import templates, resolves runtime objects or classifies runtime variants.
All twenty command families retain their existing input/output contracts.

Runtime remains responsible for lifecycle, authentication, pooling, mutation and
recovery. Management operations use explicit sessions, with explicit close and
no hidden authentication/signing/mutation retry. Signing and management share one
initialization owner. Existing `Client::connect`, Module/pool reexports and signing
APIs remain compatible; new consumers can use the provider API without importing
runtime. The runtime, locator and TLS adapter implementation files were unchanged.

The dependency checker now requires CLI-to-client and rejects CLI-to-runtime,
including test dependencies. Runtime mutation-guard coverage moved from CLI tests
to client integration, preserving the checks where runtime is an allowed dependency.
Client promotes the existing secrecy dependency from test-only to production.
Cargo.lock changes only the removed direct CLI/runtime edge; no package version
was added, removed or updated. No unsafe code, new crate or FFI layer was added.

## Validation

Passed on Fedora 44 with Rust 1.97.1 and Rust 1.85.0:

- Workspace check, 49 ordinary tests and fourteen doctests, including seven
  compile-fail ownership checks. New examples cover management and provider lifetime.
- All six ignored tests across five software-token suites on packaged SoftHSM 2.7.0
  with both toolchains, including all CLI command families and TLS handshakes.
- All six integration tests on stable with upstream SoftHSM commit
  `884cb38f3d2012a0447bd5f50dbd29c429987c41`, built with OpenSSL and without GOST.
  Strict multipart acceptance verified all three combined ECDSA context-login paths.
- Stable formatting, all-target Clippy with warnings denied, dependency boundaries,
  Markdown links, and unchanged locked package versions.

New direct client acceptance checks discovery, wrong-PIN recovery, pool capacity/
exhaustion/reuse, RO mutation rejection without session damage, binary data import/
export, attribute status and redaction, Ed25519 certificate round trips, sensitive
nonextractable generation, shared-owner signing lookup, relabel/delete and ambiguity
without mutation. Existing CLI tests continue to check PIN administration, signing,
certificate binding, raw/binary output, JSON/errors and file handling.

The existing CI jobs run the updated checker and suites. These are local validation
results; no remote CI run, commit or publication is claimed. Software-token results
do not establish hardware behavior. The test runner removes disposable token stores.
