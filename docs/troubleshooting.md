# Troubleshooting

Start with the first failing operation and preserve its error and exit code.
Use [the disposable SoftHSM quickstart](quickstart.md) to separate application
setup from device-specific behavior. For CLI commands, `--format json` emits
structured errors to stderr. See the [exit-code table](../crates/pkcs11ctl/README.md#output-and-exit-codes).

## A module fails to load or initialize

| Symptom | Check |
| --- | --- |
| Module path error | Pass the actual library path explicitly. Paths vary by OS, architecture, and vendor package. Use the vendor documentation or package file list. |
| The file exists but loading fails | Check architecture and shared-library dependencies. On Linux, use `ldd` on the trusted installed library to find missing dependencies. |
| The provider says it is already initialized | Share one lifecycle owner within the process. The stack rejects an existing initialization rather than taking ownership of it. |
| Provider initialization fails | Confirm the provider's runtime prerequisites, such as configuration, drivers or services, and use its diagnostics. For SoftHSM, verify `SOFTHSM2_CONF` and token-store permissions. |
| The source of a module is unclear | Stop before loading. A module executes native code in your process. Obtain it from a trusted vendor or distribution. |

Try `pkcs11ctl --module /path/to/trusted-pkcs11.so info` before opening sessions.
See the [security model](security-model.md) for the loading boundary.

## A token or object is missing or ambiguous

- Use `tokens` to check what the configured module sees. For the desktop app,
  refresh the module and token inventory. Recheck the device, serial, and object
  metadata after reconnection or replacement.
- Use `objects --token URI` with USER authentication when looking for a private
  object. A visible public object does not establish that a private key is
  visible or permitted for the operation.
- Prefer a stable token serial and object ID. Slot IDs are for current discovery
  and token initialization. Raw ID bytes `00 FF` appear as `id=%00%FF` in a URI.
  For data objects, use a unique label because `id` selects `CKA_ID`, not
  `CKA_OBJECT_ID`.
- Selection fails when zero or several objects match. Add criteria supported by
  the operation and check for duplicate IDs or labels. A previous match does not
  establish that the selected key is still the same key.

See the [locator syntax and matching policy](../crates/pkcs11-locator/README.md#syntax-and-matching-policy).

## Authentication fails or a PIN is locked

| Symptom | Safe next step |
| --- | --- |
| Wrong PIN or locked role | Stop repeated attempts. Check the token and intended role, then follow the vendor's recovery process if the PIN is locked. |
| A key or mutation is unavailable | Confirm USER access for private-key operations and SO access for PIN initialization. Check whether the operation requires a read-write session. |
| Protected path is unavailable | Use protected-path authentication only when advertised by the token. Use the approved host PIN source if the device policy permits it. |
| A key requires context-specific authentication | Supply the separate per-operation credential for a supported profile. Certificate-bound signing can require it for both the binding probe and the message signature. |
| An unexpected login state persists | Login and logout are token-wide. Coordinate with other sessions and applications. A pool already in the requested role may reuse a session without checking a fresh PIN. |

See the [CLI authentication options](../crates/pkcs11ctl/README.md#authentication-and-output)
and [client lifecycle guidance](../crates/pkcs11-client/README.md#ownership-authentication-and-failure-handling).

## The token advertises a mechanism but rejects the operation

- Compare `mechanisms` and `function-support` with the
  [compatibility matrix](oasis-compatibility.md). An advertised mechanism is one
  input to capability checks. Provider version, runtime support, key type,
  usage attributes, allowed mechanisms, and parameters all matter.
- For classical signing, use `capabilities` and `plan` with the desired
  algorithm, digest, and hashing policy. Fix the mismatch rather than retrying
  the same call with relaxed parameters.
- Verify input and signature encodings. Raw RSA signatures have the modulus
  width. Raw ECDSA signatures are fixed-width `r || s`, while TLS uses DER.
  Match the original message or digest, PSS parameters, and any context.
- If a mutation reports an error, inspect resulting objects and attributes
  before trying again. A provider may have applied some or all of the change.

## Sessions are exhausted or cleanup fails

| Symptom | Safe next step |
| --- | --- |
| `PoolExhausted` | Release outstanding leases or bound application concurrency. Checkout returns immediately. Size a pool against the provider's session limit. |
| An operation invalidates a session | Discard uncertain sessions. The pool does this for sessions marked unhealthy. Investigate the error before issuing another operation. |
| Pool closure reports a failure | Pause new work using that pool. Close or discard it, investigate the provider cleanup error, and create a new pool only when the module and token are usable. |
| Finalization fails or ownership remains | Finish work, release leases and sessions, and drop consumers that retain the module. For owned pools, release their `Arc` owners before unwrapping the module for explicit finalization. |
| A device or key was replaced | Rediscover the token and resolve selectors again. Bind a certificate identity when the application must detect a replacement signing key. |

Keep output private until any checked cleanup required by the workflow succeeds.
See [runtime ownership and shutdown](../crates/pkcs11-runtime/README.md#ownership-and-shutdown).

## A TLS handshake fails

- **Certificate and key mismatch.** Use a leaf-first DER chain and a selector
  for the key corresponding to the leaf. Credential loading proves the
  association with a token signature.
- **No compatible signature scheme.** Check the listener's TLS versions,
  peer offers, key type, token mechanisms, and application crypto provider.
  TLS 1.2 requires the adapter feature. ML-DSA authentication uses TLS 1.3
  and a provider that verifies the matching parameter set.
- **No client credential.** Check the server's requested schemes and issuer
  hints against the configured client chain. Configure the server's client
  certificate verifier and the client resolver.
- **Trust failure.** Check the peer's trust roots, issuer chain, DNS name,
  validity, and usage. Credential binding and TLS peer verification are
  separate checks.

See the [adapter guide](../crates/pkcs11-rustls-adapter/README.md) and the
[loopback TLS and mutual TLS examples](examples.md#tls-and-mutual-tls).

## Can I export a private key?

Typed public export rejects private and secret keys. Raw attribute reads can
expose provider-permitted values. The provider enforces sensitivity and
extractability. See the [security model](security-model.md).
