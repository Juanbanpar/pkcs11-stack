# Changelog

## Unreleased

- PKCS#11 URI `Display` and `Debug` redact all query values. Use
  `to_secret_uri()` for full serialization.
- Public APIs use `SecretText` and `SecretBytes` with redacted debug output,
  zeroization on drop, and direct `expose_secret()` methods.
