# ADR 0008: application client and certificate association

Status: implemented. Date: 2026-09-26.

## Decision

`pkcs11-client` owns a runtime `SessionPool` and application `SigningPolicy`.
It borrows its Module and accepts borrowed authentication per operation. Runtime
continues to own lifecycle, token-wide authentication, recovery, object resolution,
mechanism planning and token signing. Client exposes no durable handles or hidden
retries. Full token URI resolution was added to runtime so module/slot constraints
cannot be silently discarded by application lookup.

Certificates are immutable DER snapshots with parsed RSA or named NIST EC public
keys. Association is explicit: select one private key and certificate, then perform
one policy-permitted signature over a fixed domain-separated message and verify it.
Labels, IDs and certificate order are not evidence of association. The probe also
supports tokens that do not expose the private EC object's public point. The
cost is a signing operation, including context authentication where required;
applications must account for token audit and usage policies.

An `Identity` retains the selector and certificate. Each bound signature is
verified before output is released, so replacing the key behind an unchanged
selector fails closed. A mismatch discards the runtime lease. Generic signing
remains available without certificate association. The client does not establish
certificate trust, construct a chain or implement TLS credential selection.

Under [ADR 0009](0009-cli-library-reuse.md), the CLI consumes these public workflows
for binding and signing. It accesses runtime directly for administration and raw
inspection, without imposing this certificate parser's supported-key restrictions
on those commands. Client retains no terminal or argument-parsing responsibilities.

## Verification dependencies

`x509-cert` 0.2.5 parses exact DER. RustCrypto `rsa` 0.9.10, `p256` 0.13.2,
`p384` 0.13.1 and `p521` 0.13.3 perform public-key verification; `sha2` 0.10.9
hashes messages for that verification. These compatible release lines support
our Rust 1.85 minimum. No token private key is extracted or loaded into the
software verifier. The client has no direct cryptoki, rustls or OpenSSL dependency.
OpenSSL-generated fixtures independently check message/prehash verification,
including P-521 with a 32-byte SHA-256 digest.

The initial verifier accepts rsaEncryption RSA keys up to 16384 bits and named
P-256/P-384/P-521. RSA-PSS-restricted SPKI is rejected because its restrictions
are not modeled. Bound PSS requires matching message/MGF1 digests and an explicit
salt length. Requests outside that verifier boundary fail before checkout;
generic runtime signing retains independently chosen MGF1 digests.

## Alternatives

Matching CKA_ID or labels alone can bind unrelated keys. Comparing public metadata
alone does not work across providers that hide the private EC public point.
A proof only at construction would miss later object replacement. Per-signature
verification adds CPU work but retains the certificate association throughout use.
Certificate trust remains a separate application decision.
