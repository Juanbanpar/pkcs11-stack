# Security model

Load PKCS#11 modules from a trusted source. A module runs native code inside your
process and has access to its memory. A PKCS#11 URI selects objects in the module
you loaded.

| Area | What to account for |
| --- | --- |
| Key material | Typed private-key and secret-key operations run in the provider. Generated private and secret keys are marked sensitive and nonextractable. The provider enforces those attributes. Raw attribute reads can expose extractable objects. |
| Object selection | Persistent selectors must resolve to one object. Use a token serial and object ID where possible. Identical metadata can still describe a replacement token or key. |
| Authentication | Login and logout affect other sessions on the same token. A pooled session already logged into the requested role may be reused without checking the PIN again. Closing the last session can reset token login. |
| Failures | The stack invalidates sessions after uncertain provider failures and never retries crypto operations or mutations. A failed mutation can leave a persistent change. Inspect the token before trying again. |
| Sensitive buffers | PINs and plaintext held by the stack use zeroizing buffers. Copies made by the caller, GUI text widgets, or the PKCS#11 binding may survive. |

Certificate binding verifies that the selected key can sign for the certificate.
Applications still validate trust chains, names, expiry, usage, and revocation.
The rustls adapter signs with the token. The application selects the rustls
crypto provider and trust configuration.

For file encryption, use AES-GCM and follow the [nonce state rules](aes-gcm-envelope.md).
ECB exposes repeated blocks. CBC and CBC-PAD provide no integrity protection.
SHA-1 and SHA-224 signatures require explicit opt-in.
