# Public verification fixtures

Generated locally by `tools/generate-client-fixtures.sh` using OpenSSL 3.5.8.
These are original project fixtures, licensed MIT OR Apache-2.0. Regeneration
creates new random keys and signatures; temporary private keys are deleted.
Certificates and signatures contain no private keys. Certificate dates and issuer
signatures are intentionally outside the client trust boundary.

`rsa-*.sig` use PKCS#1 v1.5 unless named `rsa-pss-*` (20-byte salt, matching MGF1).
EC signatures use ASN.1 DER; unit tests convert to the runtime's fixed-width format.
Every signature covers the exact bytes of `message.txt`, including its newline.
Ed25519 supplies an unsupported-key certificate case.

`.gitattributes` disables text conversion for fixture data, so Windows checkouts
preserve the signed message, certificates and signatures byte for byte.
