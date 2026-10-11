# Stage 6: pkcs11ctl specification

Status: implemented, 2026-09-26. The command inventory below defines the delivered
scope; see the [completion report](stage-6-report.md) for validation.
The dependency model was revised on 2026-09-27 by
[ADR 0010](adr/0010-cli-client-boundary.md); command contracts are unchanged.

## Dependency and ownership model

Arrows mean depends on:

```text
pkcs11ctl -> pkcs11-client -> pkcs11-runtime -> pkcs11-locator
                            -> cryptoki
          -> pkcs11-locator (when directly useful)
```

The CLI manifest depends on client and locator. All provider workflows use client. Client must not depend on CLI; runtime
must not depend on client or CLI. CLI must not directly depend on cryptoki, the
rustls adapter or rustls. No additional pool, FFI layer or generic utility crate
is needed for this dependency change.

The CLI explicitly loads one trusted client Provider per selected library. Signing
clients own runtime pools and management sessions wrap runtime sessions; both borrow
that provider.
Drop sessions/clients before finalization. Use coordinated session lifetimes and
roles when combining paths; login/logout is token-wide. Ordinary client commands
use read-only sessions; administration requests read-write sessions when required.

## Command routing

| Command capability | Implementation route |
| --- | --- |
| Unique private/public key lookup, supported certificate parsing, public metadata | Client |
| Signing policy, capabilities and plan for a selected key | Client over runtime planning |
| Sign without a certificate | Client `sign` |
| Explicit key/certificate association and certificate-bound signing | Client `bind_identity` and `sign_identity` |
| Enumerate modules, slots, tokens, mechanisms and general objects | Client discovery/management; locator for URI display |
| Raw certificate export or object/attribute inspection | Client management snapshots/export; certificate parsing only when requested |
| Session, authentication and concurrency diagnostics | Client diagnostics over runtime pools |
| Token/PIN/object administration | Client management workflows over runtime operations |

This table assigns ownership. The implementation contract below lists available
commands; the CLI guide documents arguments, outputs and mutation semantics. For
additional capabilities, identify the runtime operation or reusable client workflow
before writing command code. Do not silently omit an administration capability
because client does not expose it.

Reuse library errors and behavior. Convert errors to CLI output and exit codes at
the boundary. Terminal commands must not independently parse supported certificates,
prove bindings, verify bound signatures, plan mechanisms or recover sessions.
Low-level inspection must remain possible for certificates/objects outside the
client's supported signing set.

## User-visible semantics

- Accept an explicitly configured trusted module path. URI selection never loads
  a module implicitly. Respect all supported URI constraints and reject unsupported
  constraints; never select an arbitrary match when results are ambiguous.
- Distinguish discovery slot IDs from stable object selectors. Prefer token serials
  and binary object IDs for persistent references. Preserve available empty labels
  and IDs in listed URIs as exact empty criteria.
- Validate private-key and certificate selector types before loading the module.
  Invalid selector types must produce exit 2 without provider access or reserving output.
- Keep message and digest input distinct. Expose explicit digest, RSA-PSS parameters,
  hashing policy and signature encoding; reuse the runtime's validation. Do not
  guess whether ECDSA output is raw or DER. Check prehash length against the selected
  digest before output reservation, module loading or token authentication.
- Make certificate binding explicit: it performs a token signature, and subsequent
  bound signing verifies against the certificate. General inspection does not
  trigger binding. Matching IDs/labels do not prove association, and a successful
  binding does not establish certificate trust.
- Preserve client verifier restrictions for bound operations. An unsupported bound
  request must fail rather than silently fall back to unbound signing.
- Acquire PINs through non-echoing prompts, explicit secret sources or protected
  authentication paths. Do not introduce ordinary command-line PIN values. Borrow
  credentials only for the required calls and never print them in output/errors.
- Respect runtime's token-wide login semantics and explicit context authentication.
  Do not automatically retry failed PIN entry, signing or mutations.
- Keep stdout suitable for the selected data/output format; prompts and diagnostics
  use stderr. Define typed error-to-exit-code mapping and JSON output contracts
  alongside each command. Secret attributes require explicit access, not default dumps.

## Acceptance

Keep existing library unit and software-token suites. Add CLI-specific tests for
argument validation, output/exit-code contracts, secret redaction and forwarding
of explicit policy/authentication choices. Exercise the executable against isolated
SoftHSM fixtures for every implemented command family, including failure cases.

For shared workflows, compare CLI behavior with client behavior: ambiguous lookup,
unsupported signing policy, certificate mismatch, explicit binding, context PIN
requirements and failed operations must preserve the same semantics. Add raw
inspection/export coverage for a certificate outside client's supported key set.
Administration tests operate only on disposable fixtures and verify resulting state.

Check the dependency graph in both directions: CLI consumes client, never runtime directly;
client must not transitively consume CLI. Runtime remains the only direct cryptoki
consumer, and rustls remains confined to the adapter. Replace the historical
CLI-must-not-depend-on-client check wherever it is used for future validation.

Run formatting, workspace check, Clippy, ordinary/doctests and isolated acceptance,
including the existing provider lanes. Keep Rust 1.85 checks and MIT OR Apache-2.0
licensing. Record implemented command scope and actual validation in a Stage 6
completion report; do not describe planned commands as available.

## Stage 6 command inventory

All invocations take an explicit `--module PATH`. Structured commands support
`--format text|json`; JSON success is `{schema_version: 1, command, result}` and
errors use `{schema_version: 1, error: {kind, message}}` on stderr. Exit codes:
0 success, 2 usage/input, 3 selection, 4 policy/unsupported/binding, 5 backend,
6 filesystem/output. Binary export/signature commands require `--output PATH`
(`-` means stdout) and never mix a status document into binary stdout. New output
files use exclusive creation; existing files are never overwritten.

| Command | Contract |
| --- | --- |
| `info`, `slots`, `tokens` | Library and discovery metadata |
| `mechanisms --token URI` | Advertised mechanism flags and size bounds |
| `objects --token URI` | Persistent object summaries, with no secret values |
| `inspect --object URI` | Unique object attributes; explicit `--attributes` allowlist |
| `export --object URI --output PATH` | Raw certificate/data CKA_VALUE, without certificate parsing; private/secret-key export forbidden |
| `certificate --object URI` | Client-supported certificate public-key summary |
| `capabilities --key URI`, `plan --key URI ...` | Client capabilities or policy plan |
| `bind --key URI --certificate URI` | Explicit client association probe |
| `sign --key URI [--certificate URI] --input PATH --output PATH ...` | Generic or explicitly bound client signing; raw RSA/ECDSA output |
| `diagnose --token URI --pool-size N` | Session role and bounded pool exhaustion/reuse diagnostics |
| `init-token --slot ID --label LABEL --so-pin-file PATH --confirm` | Destructive initialization through an exclusive module owner |
| `init-pin --token URI --role so --pin-file PATH --new-pin-file PATH --confirm` | Initialize/reset USER PIN in an RW SO session |
| `set-pin --token URI --pin-file PATH --new-pin-file PATH --confirm` | Change the authenticated USER/SO PIN once |
| `generate --token URI --kind rsa|p256|p384|p521 --id HEX --label LABEL --confirm` | Persistent sensitive, nonextractable signing key pair; RSA defaults to 2048 bits |
| `import --token URI --kind cert|data --id HEX --label LABEL --input PATH --confirm` | Persistent public certificate/data object; exact X.509 DER and metadata are parsed by client without a signing-algorithm restriction |
| `set-label --object URI --label LABEL --confirm`, `delete --object URI --confirm` | Mutate exactly one freshly resolved object |

Authentication is opt-in via mutually exclusive `--pin-file` or `--protected-path`;
`--role user|so` defaults to USER. PIN files contain UTF-8 bytes with one optional
terminal LF/CRLF removed; file descriptors can be supplied as filesystem paths.
Always-authenticate signing accepts a separate `--context-pin-file` or
`--context-protected-path`. Token/PIN initialization APIs require host PIN files
because the upstream safe mutation APIs do not expose null-PIN inputs.
Signing/plan requires `--algorithm` and `--digest`; PSS additionally requires
`--mgf-digest` and `--salt-length`. `--input-kind message|digest` is explicit in
help (default message); `--hashing token|allow-software|software` defaults to token.
Signatures retain the library's raw encoding; DER/PEM transformations are deferred.

Generic runtime object creation/update supports explicit templates. CLI templates
are typed by the commands above. Arbitrary JSON templates, private/secret-key import
or export, wrapping, encryption/decryption, derivation and hardware-specific
administration are deferred; these are additional runtime/CLI capabilities, not
blocked by the client's supported signing algorithms. No command claims them.
