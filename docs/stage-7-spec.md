# Stage 7: rustls adapter specification

Implemented scope, accepted 2026-09-26 and validated 2026-09-27.
See the [completion report](stage-7-report.md). The CLI dependency model was unchanged during Stage 7. The subsequently completed
client-only CLI refactor is specified by [ADR 0010](adr/0010-cli-client-boundary.md).

Adapter implements rustls 0.23 SigningKey/Signer and server/client certificate
resolvers over runtime. Production builds select no software crypto provider.
Applications pass an explicit CryptoProvider and configure rustls trust/protocols.
TLS 1.3 is the default; TLS 1.2 is an optional feature. TLS-specific schemes and
signature encodings remain confined to adapter. No private token key becomes a
PrivateKeyDer, no global provider is installed, and no second pool/FFI is added.

Runtime adds SessionPool::new_owned(Arc<Module>, ...), sharing one initialization
owner while preserving borrowed pool APIs. Every owned session retains that owner
until its raw session closes. Applications stop connections, drop configs/signers
and pools, then use Arc::try_unwrap for explicit finalization. No leaked references,
unsafe self-reference or background worker solves the rustls 'static requirement.

Credentials take an explicit private selector, leaf-first DER certificate chain,
runtime pool, signing policy, application credential callback and crypto provider.
Loading performs one domain-separated binding signature verified with the leaf
and provider. Every TLS signature is also verified, detecting replacement behind
the selector. Authentication is acquired once per operation in zeroizing storage;
no stored PIN or implicit prompt/retry. Context authentication is explicit.

Scheme selection intersects peer offers, key type/curve, runtime capability/policy
planning and software-provider verification support. Cached capabilities are only
advisory; runtime rediscovers at execution. RSA supports SHA-2 PKCS#1 v1.5 and
PSS with matching MGF1 hash and digest-sized salt; rustls filters TLS-version
compatibility. ECDSA maps P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512 only.
Unsupported SPKI algorithms (including restricted RSA-PSS) and schemes fail closed.
Provider support may narrow this list. Fixed-width token ECDSA becomes canonical
DER r/s; no encoding guessing or application-message logging.

Server resolution uses explicitly registered DNS names validated against leaf SANs,
with application ordering among multiple credentials for a name. Routing is exact,
case-insensitive; an optional default applies only when SNI is absent. Unknown SNI
fails. Client resolution intersects offered schemes and DER issuer-name hints
from the configured chain; empty hints allow any compatible configured identity.
Chain ordering/content and trust policy are application-owned, verified by peers
in real handshakes; local binding alone makes no trust decision.

The adapter's `server_config_builder` restricts a clone of the supplied provider's
cipher suites to the configured protocol versions before calling rustls's builder.
It preserves suite order and application ownership of provider and trust policy.
This prevents rustls 0.23.43 from considering disabled TLS 1.3 suites when selecting
a credential for a TLS 1.2-only server. Direct rustls builder users must apply the
same restriction. Acceptance includes a dual-version client with ECDSA-only TLS 1.2
suites and a TLS 1.2-only server whose resolver lists RSA before ECDSA.

Acceptance includes pure scheme/encoding/redaction tests and full server/mTLS
handshakes using nonextractable SoftHSM RSA/EC keys and an explicitly selected
software provider. Check normal peer verification, SNI and issuer-hint selection,
wrong trust, incompatible schemes, PIN failures/context authentication, concurrent
use, exhaustion/discard recovery, replacement detection and module lifetime.
Run stable/MSRV workspace and both software-token provider lanes. Report unsupported
hardware/provider behavior accurately. No hardware assurance or full CryptoProvider
implementation is implied.
