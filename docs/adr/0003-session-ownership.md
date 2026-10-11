# ADR 0003: runtime ownership of modules and sessions

Status: implemented through Stage 7. Original decision: 2026-09-05.

## Decision

Only runtime owns module lifecycle, initialization/finalization coordination,
authentication, sessions, pooling, invalidation and recovery. All consumers share
that behavior. Do not place production pools in the application API, CLI or TLS
adapter. Do not introduce hidden workers, executors or fake async functions.

Establish explicit initialization ownership before finalizing a module. Already
initialized state is not proof that this runtime owns finalization. A coordinated
shutdown must stop new operations, drain active leases, close sessions, then
finalize only an owned initialization. Exact ownership/registry mechanics await
cryptoki and software-token experiments; do not introduce hidden global state.

A lease must give exclusive use of its session across an entire multipart
operation and any context-specific login. USER and SO authentication affect
shared token state; logout is not a harmless per-lease cleanup operation.
Protected authentication paths require capability checks and no host PIN.
CKA_ALWAYS_AUTHENTICATE needs an explicit per-operation authentication sequence.
Secrets require protected storage and intentionally reviewed Debug/error output.

Pool capacity, lease timeout, read-only/read-write separation and authentication
coordination will be designed when pooling is requested. Failed or uncertain
operation state must not return to the pool as healthy. Recreation replaces the
session generation and invalidates its handles. Token removal/module restart
invalidate affected state and require rediscovery from stable selectors. Do not
blindly retry signing or other operations whose completion is uncertain.

## Upstream findings and unresolved constraints

cryptoki 0.12.0 has a cloneable Arc-backed `Pkcs11`; `finalize(self)` explicitly
calls C_Finalize, with no automatic module-finalizing Drop. Its sessions retain a
context clone, are Send but not Sync, and normally close on Drop. Explicit close
can report errors; Drop only logs closure failures. Rust ownership alone does not
coordinate module initialization and shutdown for all clones/other users.

The one-shot `Session::sign` invokes C_SignInit internally. Its API has no callback
for a CKU_CONTEXT_SPECIFIC login between initialization and signing. Separate
`sign_init`, `sign_update`, `sign_final` exist, but do not assume raw single-part
mechanisms support multipart signing. Before promising always-authenticated raw
signatures, verify a supported safe upstream path, seek an upstream API addition,
or return a typed unsupported-capability error. No second FFI layer or workspace
unsafe workaround is authorized by this ADR.

These are research findings, not executed token acceptance. See [research sources](../preflight.md).


## Stage 3 ownership decision (2026-09-06)

Use a non-cloneable Module owning a successful cryptoki initialization. Sessions
borrow Module, and session-bound objects borrow their originating Session. No raw
context, session handle or object handle escapes the runtime. Module is shareable
by reference across scoped threads; each session is used exclusively. There is
no global registry, worker or pool. Existing already-initialized modules are
rejected without calling finalize. This assumes a conforming module and cooperative
callers using a single initialization owner; independent raw finalizers are not
made safe by Rust ownership inside this crate.

An explicit Session Drop implementation is essential: it retains the module
borrow through the destructor, not merely until the session's last explicit use.
Compile-fail examples verify that module finalization cannot precede session
cleanup, and objects cannot be used after session close. Borrowing implements the
previous shutdown principle without speculative lease-draining machinery.
Explicit close/finalize report errors; Drop is best effort. If initialization
succeeds but library metadata fails, cleanup is attempted; if it also fails, both errors
are preserved. cryptoki may retry/log session close failure in its own Drop.

Token metadata is revalidated before token/session operations and around opening.
It is a consistency check, not cryptographic proof against a replacement carrying
identical metadata. Removal and cross-session logout can still invalidate handles;
errors propagate, with no hidden replay or recovery. Context-specific login is
intentionally not callable without an active operation; its implementation and
CKA_ALWAYS_AUTHENTICATE remain Stage 4 work. None/USER/SO/protected-path policies
are explicit and never cache PINs. Drop never explicitly issues token-wide logout.

SoftHSM acceptance verifies ownership rejection, cleanup, RO/RW and USER/SO state,
private visibility, independent sessions and fresh reference resolution. SoftHSM
has no protected authentication path here, so that path has a negative capability
test only. These tests do not constitute hardware or production-pool assurance.

## Stage 4 implementation

Pooling, recovery and context-specific RSA signing are now implemented as described
in [ADR 0007](0007-signing-and-pooling.md). Earlier stage observations above remain
historical; the raw single-part context-login limitation is still explicit.

## Stage 7 owned consumers (2026-09-26)

`SessionPool::new_owned` accepts an existing `Arc<Module>` and resolves a full token
URI. An internal borrowed/shared owner representation preserves all borrowed APIs
and compile-fail guarantees while supporting rustls's static signing traits. Each
owned session retains the same module owner; its raw session closes before that
reference drops. No second initialization, independent finalizer or global registry
is introduced. Pool accounting, authentication and recovery are unchanged.

Applications stop operations and drop TLS connections, configs, credentials,
signers and pools before unwrapping their final module Arc for explicit finalization.
Dropping the last owner instead performs existing best-effort cleanup. Owned-pool
acceptance verifies that dropping the external Arc keeps sessions usable, and that
final pool destruction permits fresh module initialization. The earlier borrowed
ownership examples remain checked.
