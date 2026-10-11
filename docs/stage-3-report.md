# Stage 3: runtime foundation

Historical Stage 3 snapshot, superseded by [Stage 4](stage-4-report.md).

Completed 2026-09-06. Runtime now supports the Stage 3 foundation. Crate names,
MIT OR Apache-2.0 licensing, Rust 1.85 MSRV and dependency boundaries are preserved.
No pool, recovery engine, signing/capability planner, production mutation API,
rustls integration or testkit crate was introduced.

## Implementation

| File | Purpose |
| --- | --- |
| `crates/pkcs11-runtime/src/module.rs` | Owned module initialization/finalization, metadata, slots, stable token discovery/resolution and mechanism information |
| `crates/pkcs11-runtime/src/session.rs` | Borrowed RO/RW sessions, explicit authentication/logout/close, session-bound objects, fresh stable-reference resolution and attribute access |
| `crates/pkcs11-runtime/src/error.rs` | Typed errors with upstream operation/return-value context and explicit no-match/ambiguity |
| `crates/pkcs11-runtime/tests/softhsm.rs` | Ignored, isolated software-token acceptance |
| `tools/test-softhsm.sh` | Disposable SoftHSM configuration, token setup, invocation and cleanup |
| `.github/workflows/ci.yml` | Separate SoftHSM job alongside default stable/MSRV checks |

Module successfully initializes with OS locking before acquiring finalization
ownership. A rejected duplicate owner never finalizes the existing owner.
Metadata failure after initialization attempts cleanup; a secondary cleanup
failure is retained alongside the primary failure. Explicit finalization reports
errors, while Drop is best effort.

Sessions borrow their module. Their explicit Drop keeps that borrow active until
session destruction, preventing early module finalization even after the last
explicit session use. Objects borrow their originating session. No raw context,
session handle or object handle escapes, and there is no public handle cache.
Two compile-fail examples verify ownership boundaries.

Token-only selector resolution distinguishes zero, one and multiple matches.
ObjectRef contains only locator data and rejects credentials, slot IDs, unknown
constraints and unsupported query selectors. Resolution in the selected session
checks module/slot/token metadata, searches CKA_TOKEN=true objects afresh, checks
storage-object metadata and requires exactly one match. Generic template search
also supports session objects as operational, session-bound values.

PINs are borrowed SecretStrings, not cached. USER/SO policies and protected-path
capability checks are explicit. Authentication failures retain PKCS#11 errors.
Attribute containers and runtime errors have deliberately reviewed Debug output;
raw attribute values require explicit access. Attribute availability is separately
queryable because cryptoki may omit unavailable values from attribute reads.

## Validation

All passed locally:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
bash -n tools/test-softhsm.sh
```

Default workspace test counts: 26 ordinary tests (22 locator plus four runtime)
and five documentation tests (including two compile-fail ownership checks).
The SoftHSM test remains ignored in the default run; it was also explicitly
executed and passed through the isolated runner.

SoftHSM 2.6.1-3 Ubuntu packages were downloaded and extracted under
`/tmp/pkcs11-stage3-softhsm`, without installing packages system-wide. The actual
local acceptance invocation was:

```sh
PKCS11_TEST_MODULE=/tmp/pkcs11-stage3-softhsm/root/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
SOFTHSM2_UTIL=/tmp/pkcs11-stage3-softhsm/root/usr/bin/softhsm2-util \
./tools/test-softhsm.sh
```

Each invocation created a new private temporary configuration/token directory,
initialized two tokens with the same label and disposable public test PINs, and
removed the directory afterward. Fixture creation used cryptoki before runtime
ownership and created only data objects. No existing token directory or hardware
was used. The integration test exercised:

- Module load/metadata, duplicate-initialization rejection without disrupting the owner.
- Slot/token enumeration, no token match, ambiguous label and unique serial selection.
- Mechanism list and mechanism metadata.
- RO/RW session state, no-login policy, wrong PIN, USER and SO login/logout.
- Rejection of SO on RO and unavailable protected authentication paths.
- Private-object visibility, generic search, absent and ambiguous object resolution.
- Attribute values and invalid-attribute status, plus redacted result Debug.
- Closing one session without explicit token-wide logout, scoped concurrent sessions.
- Explicit and Drop cleanup, module reopening and fresh stable-reference resolution.
- Rejection of a reference for a different token.

Cargo metadata confirms runtime's direct dependencies remain cryptoki,
pkcs11-locator, secrecy and thiserror. Runtime has no direct or transitive rustls,
client or CLI dependency. All workspace crates still declare MIT OR Apache-2.0.
No Rust dependency or version changes were needed. The configured remote CI job
has not been executed from this workspace.

## Architectural decisions and limits

[ADR 0003](adr/0003-session-ownership.md) records borrowed ownership and initialization
policy. [ADR 0002](adr/0002-object-identity.md) records implemented stable references.
The [runtime README](../crates/pkcs11-runtime/README.md) documents the API and examples.

Lifecycle ownership assumes a conforming vendor module and cooperative callers;
it cannot prevent an unrelated raw context from finalizing the same vendor library.
Token metadata checks detect changes, not an attacker supplying identical metadata.
Token-wide logout/removal can invalidate other sessions' handles, and errors are
propagated without retry or recovery. Attribute values explicitly exposed by the
caller may include extractable secrets and are not zeroizing containers.

SoftHSM here has no protected authentication path; only the negative capability
case was executed. No hardware authentication, physical-removal recovery or
hardware interoperability is claimed. Context-specific login requires an active
operation and remains deferred with CKA_ALWAYS_AUTHENTICATE to Stage 4. The
known cryptoki one-shot signing limitation remains unresolved and documented.

## Upstream review

cryptoki 0.12.0 remains the current stable release according to crates.io checked
on 2026-09-06. Its published source was rechecked for explicit finalization,
Send/non-Sync sessions, close/drop behavior, USER/SO login, object search and
attribute omission/availability semantics. No upstream implementation code was
copied. Sources: [module API](https://docs.rs/cryptoki/0.12.0/cryptoki/context/struct.Pkcs11.html),
[session source](https://docs.rs/crate/cryptoki/0.12.0/source/src/session/session_management.rs),
[object source](https://docs.rs/crate/cryptoki/0.12.0/source/src/session/object_management.rs).

Next milestone: Stage 4, session pooling, recovery, capability planning and signing.
It has not started.
