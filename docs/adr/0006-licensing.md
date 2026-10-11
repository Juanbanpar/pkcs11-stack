# ADR 0006: licensing

Status: accepted for original project code. Date: 2026-09-05.

## Decision

All original project code and documentation are licensed under
`MIT OR Apache-2.0`, at the recipient's option, as explicitly requested by the
project owner. This supersedes the initial GPL licensing decision.
Every workspace crate inherits `license = "MIT OR Apache-2.0"`.
Root `LICENSE-MIT` and `LICENSE-APACHE` contain the respective license texts;
the former GPL `COPYING` file is removed. Original Rust sources start with
`// SPDX-License-Identifier: MIT OR Apache-2.0`. The MIT notice identifies the
project contributors collectively without inventing individual names or years.
Crate READMEs link to both licenses. Publication remains disabled in scaffolding.

## Dependency review

Versions below are current stable releases observed on crates.io on 2026-09-05.
Declared MSRV/license values were cross-checked with the published release
Cargo.toml files; these are upstream declarations, not claims about every feature
or platform. The snapshot in ADR 0001 records the API results.

| Dependency | Selected version | Declared Rust minimum | Declared SPDX license | Direct workspace consumers |
| --- | --- | --- | --- | --- |
| [cryptoki](https://docs.rs/crate/cryptoki/0.12.0/source/Cargo.toml) | 0.12.0 | 1.77 | Apache-2.0 | runtime |
| [rustls](https://docs.rs/crate/rustls/0.23.43/source/Cargo.toml) | 0.23.43 | 1.71 | Apache-2.0 OR ISC OR MIT | adapter |
| [rustls-pki-types](https://docs.rs/crate/rustls-pki-types/1.15.1/source/Cargo.toml) | 1.15.1 | 1.60 | MIT OR Apache-2.0 | adapter |
| [secrecy](https://docs.rs/crate/secrecy/0.10.3/source/Cargo.toml) | 0.10.3 | 1.60 | Apache-2.0 OR MIT | locator, runtime |
| [zeroize](https://docs.rs/crate/zeroize/1.9.0/source/Cargo.toml) | 1.9.0 | 1.85 | Apache-2.0 OR MIT | locator |
| [thiserror](https://docs.rs/crate/thiserror/2.0.20/source/Cargo.toml) | 2.0.20 | 1.71 | MIT OR Apache-2.0 | locator, runtime |
| [clap](https://docs.rs/crate/clap/4.6.6/source/Cargo.toml) | 4.6.6 | 1.85 | MIT OR Apache-2.0 | ctl |

The project license choice applies to original material. Dependencies retain the
license choices shown above: in particular, cryptoki remains Apache-2.0-only.
Selecting MIT for project code does not relicense cryptoki or remove Apache notice
requirements. Retain upstream license texts, copyright notices and any required
NOTICE material when distributing third-party components.

This review covers the listed dependencies, not a blanket license clearance for
future features, copied material, every transitive dependency or proprietary
vendor modules. Distribution with a vendor module requires reviewing its own
terms and the combined distribution. No vendor module is included here.

## Third-party material

Implement independently from specifications and documented behavior. No reference implementation was copied into the original workspace crates.
Stage 4 temporarily vendored a narrowly patched cryptoki dependency separately.
The September 25 review removed that source override in favor of cryptoki 0.12.1;
[provenance](../../vendor/README.md) remains available.
Upstream source was inspected outside the workspace to verify APIs and ownership.

Any future copied/adapted code, fixture or test vector must record its exact source,
version, license and modifications and retain required attribution/license text.
Do not relabel third-party material with the project's SPDX header. RFC 7512's
IETF Trust notice has special terms for extracted Code Components (Simplified
BSD); OASIS material has its own notices/IPR terms. Prefer original tests derived
from requirements instead of copying source examples or normative text.

Reference projects remain references, not dependencies: OpenSC documents LGPL
licensing and file-level exceptions; libp11 is LGPL-2.1-or-later; the inspected
OpenSSL PKCS#11 provider and OxiCrypto adapter declare Apache-2.0; p11-kit has
BSD-style file notices. Those project-level summaries are not permission to copy
an arbitrary file. Inspect each file's terms before any reuse. The project's
license texts do not grant additional rights over third-party material.

## Stage 4 dependency additions

Runtime now uses sha2 0.10.9 (MIT OR Apache-2.0), with Rust 1.85 checked locally.
This is a pinned compatible release line, not a claim that 0.10.9 is the latest.
The temporary cryptoki source override retains Apache-2.0 and is excluded from
workspace membership. Original local modifications are MIT OR Apache-2.0;
upstream material is not relicensed. See the vendor provenance for the exact source,
change and removal criteria. OpenSSL and SoftHSM are integration-test executables,
not bundled runtime backends. Their installed distributions retain their own terms.


## September 25 dependency cleanup

Cryptoki now resolves from crates.io at 0.12.1 (Apache-2.0, declared MSRV 1.77),
with the upstream bounded-decoding fix and no local source changes. The temporary
vendored crate, its workspace exclusion and its separate CI test were removed.
The dependency table above remains the Stage 1 historical snapshot. No other
locked package version changed. Stable and Rust 1.85 workspace tests and isolated
software-token acceptance passed with the released dependency.

The CI multipart ECDSA lane builds unmodified SoftHSM upstream commit
`884cb38f3d2012a0447bd5f50dbd29c429987c41` outside this workspace. It is a test tool,
not a bundled runtime dependency. Its source and installed license notices remain
with that isolated build.

## Stage 5 dependency additions

The client adds the following compatible release lines, checked from the resolved
package metadata on 2026-09-26. Each declares Rust 1.65 and MIT OR Apache-2.0:
`x509-cert` 0.2.5, `rsa` 0.9.10, `p256` 0.13.2, `p384` 0.13.1 and `p521` 0.13.3.
These are not claims of the latest releases. Client also uses the existing
`sha2` and `thiserror` dependencies. The locked workspace is tested on Rust 1.85.
OpenSC's `pkcs11-tool` is an external fixture provisioner, not a bundled library
or dependency of production code. Original verification fixtures were generated
with OpenSSL; their provenance and regeneration script are recorded in the
[fixture README](../../crates/pkcs11-client/tests/fixtures/README.md).


## Stage 6 dependency additions

CLI now consumes client, runtime and locator, plus the existing clap, secrecy and
zeroize release lines. JSON output adds serde_json 1.0.151 (MIT OR Apache-2.0,
declared MSRV 1.71); the locked transitive additions retain their published
licenses. Existing locked versions remain unchanged. No FFI or software crypto
backend is added to CLI. SoftHSM/OpenSC/OpenSSL remain external acceptance tools.

## Stage 7 dependency additions

The adapter directly uses the already locked rustls-webpki 0.103.15 (ISC, declared
MSRV 1.71) for leaf parsing and signature/name verification with the application's
provider algorithms. It also uses existing x509-cert 0.2.5, secrecy and thiserror.
Ring is enabled only by the adapter's rustls dev-dependency for TLS acceptance.
Production normal/build dependencies select neither ring nor aws-lc; CI checks
that boundary. No locked package versions were added, removed or changed in Stage 7.
The locked workspace and TLS acceptance are tested on Rust 1.85.0. License metadata
was checked from resolved Cargo packages; this does not replace their notices.

## CLI client refactor (2026-09-27)

Client now uses the existing secrecy 0.10.3 dependency in production for management
PIN inputs and URI projection, instead of only in tests. CLI removes its direct
runtime edge. No locked package versions changed and no dependency was added to
runtime or the TLS adapter. The dual-license and Rust 1.85 requirements are unchanged.

## Stage 8 application examples

Client and adapter add the already locked zeroize 1.9.0 as a dev-dependency for
example PIN-file buffers. No package versions changed; the lockfile adds only these
two dependency edges. TLS examples explicitly select ring through the existing
adapter dev-dependency. Production dependency boundaries and provider selection
remain unchanged. New examples and their fixture runner are original dual-licensed
project code.

## Generated regression coverage (2026-09-27)

Locator and adapter add proptest 1.11.0 as an exact dev-dependency, using only its
`std` feature. Its published manifest declares Rust 1.85 and MIT OR Apache-2.0;
the workspace and tests were checked on Rust 1.85. Adapter also declares the already
locked der 0.7.10 as a dev-dependency for independent DER decoding. Existing locked
package versions are retained. The new random-generation dependencies are confined
to tests; the architecture check rejects proptest/libfuzzer-sys in production graphs.

The separate, unpublished fuzz workspace locks libfuzzer-sys 0.4.13, whose manifest
declares `(MIT OR Apache-2.0) AND NCSA`. Cargo-fuzz 0.13.2 is an external test tool
licensed MIT OR Apache-2.0. Nightly-2026-09-25 is used only for instrumented fuzzing.
The original harnesses and synthetic seed files are dual-licensed project code;
upstream fuzzing runtime notices and licenses remain unchanged. No fuzzing runtime
or test corpus is bundled as a production dependency.
