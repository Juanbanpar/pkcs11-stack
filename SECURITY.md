# Security policy

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Juanbanpar/pkcs11-stack/security/advisories/new).
Include the affected version or commit, OS, PKCS#11 provider and mechanism, and
the observed impact. Use a disposable token or software store to reproduce the
issue. Redact PINs, keys, and production token identifiers from logs and samples.
Maintainers coordinate disclosure with reporters and affected upstream projects.

See the [security model](docs/security-model.md) for what the stack, the provider,
and the application each protect.

## Dependency advisories

| Advisory | How the dependency is used |
| --- | --- |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (`rsa`) | Public-key parsing, export, and software verification. The provider performs private RSA operations. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) (`crypto-bigint`) | Public EC point validation and signature verification. The provider performs secret-key operations. |
| [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) (`ctutils`) | Public ML-DSA key decoding and verification. The workspace uses 0.4.2 for Rust 1.85. The fuzz workspace uses patched 0.4.8. |

These uses account for the exceptions in the [workspace audit configuration](.cargo/audit.toml).
Changes to advisory exclusions require explicit review and a written justification
for each new exception.
