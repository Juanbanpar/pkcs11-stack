# ADR 0009: CLI reuse of client and runtime

Status: superseded by [ADR 0010](0010-cli-client-boundary.md). Original date: 2026-09-26.
Supersedes [ADR 0005](0005-client-cli-separation.md) and amends the CLI dependency
rules in [ADR 0001](0001-workspace-architecture.md).

## Decision

`pkcs11ctl` consumes `pkcs11-client` for existing application workflows and
`pkcs11-runtime` directly for inspection and administration. Client must never
depend on CLI, directly or transitively. Locator remains available to the CLI
when URI parsing or construction is directly useful.

| Layer | Responsibility |
| --- | --- |
| CLI | Arguments, PIN acquisition, command orchestration, terminal/JSON output, file I/O and exit codes |
| Client | Application lookup, signing policy workflows, certificate parsing, explicit identity binding and verified signing |
| Runtime | Module/session ownership, token authentication, discovery, attributes, mechanism planning, token operations and recovery |

The CLI uses the existing client API for matching workflows. It must not implement
another certificate-to-key proof, certificate verifier, signing planner or pool.
Direct runtime calls are appropriate for module/slot enumeration, raw object
inspection, mechanism diagnostics and administration operations. These paths must
not impose client certificate/algorithm restrictions on general inspection.

When a command reveals a reusable application workflow missing from client, add
that workflow to client. When it needs a token operation missing from runtime,
implement the operation in runtime. Keep prompts, output schemas, exit codes and
command-specific sequencing in the CLI. Do not add forwarding-only client methods
just to hide legitimate runtime access.

One invocation uses one module owner and coordinates authentication/session use
through runtime. Client and direct runtime paths must not create competing
initialization owners or assume isolated login state on the same token. Shared
operations retain the existing no-automatic-signing/PIN-retry rules.

## Rationale and consequences

The former symmetric dependency ban already avoided duplication of token
operations through runtime, but would require CLI duplication of the application
workflows added in Stage 5. The CLI should exercise the public library API and
benefit from its fixes. Direct runtime access preserves administration coverage
without broadening client solely for a terminal command.

CLI consequently accepts the client's parsing and verification dependencies.
It remains separate from TLS: only the adapter consumes rustls, and only runtime
directly consumes cryptoki. Licensing, MSRV, secret redaction, explicit policy and
stable object identity requirements are unchanged.

This decision originally changed architecture/specifications only. Stage 6 now
implements the dependency edges and command consumers; see its
[completion report](../stage-6-report.md). Historical completion reports retain
the dependency graphs that were actually validated at the time.

Implementation and acceptance requirements are in the
[Stage 6 specification](../stage-6-spec.md).
