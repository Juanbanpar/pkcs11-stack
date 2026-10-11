# ADR 0007: signing, capability planning and pooled sessions

Status: accepted and implemented for Stage 4. Date: 2026-09-06.
Updated after the [September 25 review](../implemented-stage-review.md).

A `SessionPool` owns a bounded set of sessions for one discovered token and one
access mode. A short mutex protects accounting and idle storage; PKCS#11 calls
and crypto operations occur outside it. Each RAII lease exclusively owns one
session. Exhaustion is an immediate typed error, with no hidden blocking queue,
executor or worker. Applications choose their own scheduling/backpressure.

Checkout validates an idle session and can replace it once. Reservations remain
counted during open and close, and failed opens/logins return capacity. Healthy
sessions are returned; failed signing/search calls, explicit discard and unwinding
cause closure. Return also checks module, token and mode binding. Session generations
are diagnostic only. The runtime caches no handles: every signing call resolves
its PrivateKeyRef in the current session and rediscovers capability metadata.
No signature, PIN, failed crypto operation or module initialization is retried.
Token identity changes fail closed; slot migration/module reconnection is explicit.

Checkout authentication ensures USER/SO state rather than asserting ownership of
a particular prior login. A concurrent CKR_USER_ALREADY_LOGGED_IN is accepted only
when the actual role matches. PINs are borrowed, not stored or retried. Use one pool
per token/role and coordinate token-wide logout with all consumers. No-auth checkout
means no state change, not proof of public-only visibility. Login state can still
change concurrently after the check; the resulting operation error is propagated.

`KeyCapabilities::plan` is pure and produces an inspectable result. It intersects
key type, RSA modulus size or recognized EC curve, CKA_SIGN, CKA_ALLOWED_MECHANISMS,
mechanism CKF_SIGN and size bounds, request parameters and application policy.
Required metadata that is missing or sensitive fails closed. An unsupported optional
CKA_ALLOWED_MECHANISMS attribute is distinguished from a populated restriction;
an empty supported list is unrestricted under PKCS#11 semantics. Snapshots are not
authorization: signing obtains new metadata. Module-side policy/parameter validation
remains authoritative; advertisements cannot guarantee every parameter combination.

Messages and supplied digests have distinct variants. TokenOnly requires combined
hash/sign for messages; AllowSoftware permits raw signing after runtime SHA-2;
SoftwareOnly explicitly selects that boundary. A caller digest is already hashed
outside the token, regardless of message policy. No implicit software fallback
occurs after a failed token operation. SHA-256/384/512 use RustCrypto sha2 0.10.9,
selected for the existing Rust 1.85 baseline. Runtime never implements a private-key
primitive in software.

RSA PKCS#1 v1.5 raw signing receives SHA-2 DigestInfo, not naked digest bytes.
PSS requires an exact salt length and explicit MGF1 digest, including modulus-fit
checks. ECDSA supports named P-256/P-384/P-521 parameters. Unknown or explicit
curve encodings are rejected. RSA results are modulus-width bytes; ECDSA results
are fixed-width `r || s`, checked against the selected curve. DER/protocol conversion
belongs to adapters. No TLS algorithm names or rustls types enter runtime.

CKA_ALWAYS_AUTHENTICATE uses init, context-specific login, update, final for combined
RSA and ECDSA hashing mechanisms. Missing credentials fail before init. Cryptoki
0.12.1's single-part `sign` performs init internally, so raw/prehashed
always-authenticate requests are rejected before the operation. No login is
skipped. Failed context login invalidates the entire session, including subsequent
discovery and authentication. Protected-path capability is read afresh using the
same identity validation as ordinary login. Provider advertisements do not ensure
implementation: SoftHSM 2.7 rejects multipart ECDSA despite advertising combined
mechanisms. Such failures are propagated and the session is discarded.

Public metadata reads only public attributes of a private/public key. Consumers can
request token-provided SPKI, RSA modulus/exponent or EC parameters/point. A separately
selected CertificateRef exposes certificate DER. Runtime does not infer key/certificate
association from labels or IDs, extract SPKI from certificates, construct missing SPKI,
or validate certificate trust. Applications must bind and validate independently
selected material before use. This accommodates tokens with different object layouts.

The nonempty allowed-mechanisms test exposed a byte-count/element-count defect in
cryptoki 0.12.0. The temporary override was removed in favor of released cryptoki
0.12.1, which implements equivalent bounded decoding; see
[dependency provenance](../../vendor/README.md). Cryptoki remains Apache-2.0. Original workspace code remains unsafe-free and
MIT OR Apache-2.0.

Validation combines pure planner and lifetime tests, real empty/single/multiple
allowed-mechanisms attribute reads, and isolated SoftHSM operations verified independently with the OpenSSL executable.
OpenSSL is test-only, not a Rust dependency or runtime backend. Software tokens do
not establish hardware behavior, protected-path UX or device hot-unplug recovery.

References: [OASIS PKCS#11 3.1, private-key authentication and attributes](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html),
[OASIS current mechanisms, RSA/PSS/ECDSA](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html),
[cryptoki 0.12 signing API](https://docs.rs/cryptoki/0.12.0/cryptoki/session/struct.Session.html),
[sha2 0.10.9](https://docs.rs/sha2/0.10.9/sha2/).
