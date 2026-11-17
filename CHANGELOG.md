# Changelog

## Unreleased

- PKCS#11 URI `Display` and `Debug` redact all query values. Use
  `to_secret_uri()` for full serialization.
- AES-GCM in the CLI and desktop defaults to [versioned envelopes](docs/aes-gcm-envelope.md).
  CLI encryption uses `--nonce-state`. Supply `--nonce` to read or write the raw
  ciphertext and tag format.
