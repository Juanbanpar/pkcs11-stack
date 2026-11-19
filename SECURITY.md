# Security policy

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Juanbanpar/pkcs11-stack/security/advisories/new).
Include the affected version or commit, OS, PKCS#11 provider and mechanism, and
the observed impact. Use a disposable token or software store to reproduce the
issue. Redact PINs, keys, and production token identifiers from logs and samples.
Maintainers coordinate disclosure with reporters and affected upstream projects.

See the [security model](docs/security-model.md) for what the stack, the provider,
and the application each protect.

## Dependency advisories

CI audits the workspace, fuzz and pinned provider lockfiles. The
[workspace audit configuration](.cargo/audit.toml) keeps unmaintained-package
notices visible and treats unsoundness and yanked packages as failures.
Changes to advisory exclusions require explicit review and a written
justification for each new exception.
