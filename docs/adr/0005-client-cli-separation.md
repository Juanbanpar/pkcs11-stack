# ADR 0005: application API and CLI remain independent

Status: superseded by [ADR 0009](0009-cli-library-reuse.md) on 2026-09-26.
Original decision date: 2026-09-05.

The decision below is historical. The current rule allows `pkcs11ctl` to consume
both client and runtime; client must not depend on the CLI. Presentation remains
CLI-owned and token operations remain runtime-owned.

## Original decision

`pkcs11-client` provides ergonomic application
workflows: token/key/certificate lookup, identity association and common key and
object operations. `pkcs11ctl` provides comprehensive administration, inspection
and diagnostics, including low-level templates, slot IDs, attributes, mechanisms,
PIN/token management and concurrency diagnostics in later stages.

Neither depends on the other, directly or transitively. Both use runtime, and
may use locator directly when useful. Shared substantial PKCS#11 behavior belongs
in runtime. Terminal formatting, clap argument definitions, JSON output choices
and command workflows belong in the CLI. Do not expand the application API solely
to satisfy an administration command.

## Consequences

Some small presentation/workflow duplication is acceptable; duplicated lifecycle
or cryptographic behavior is not. Only help/version parsing is implemented now.
Future PIN input must prefer non-echoing prompts, protected authentication paths,
stdin/file descriptors or explicit secret sources over observable command-line
PIN arguments. Do not add PIN options to this skeleton.

See [ADR 0001](0001-workspace-architecture.md) for the selected names and actual graph.
