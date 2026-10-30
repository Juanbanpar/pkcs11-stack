// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{EcdhKdf, Error, SecretKeyIdentity};
pub use pkcs11_runtime::MontgomeryOutput;

/// Explicit native Montgomery KDF/output parameters. Pair with a checked peer
/// of the exact RFC 8410 OID or RFC 7748 curveName profile. Outputs are persistent,
/// private, sensitive and nonextractable; no private/shared-secret bytes leave
/// the token. Authenticate peer ownership and bind shared info to the protocol.
pub struct MontgomeryKdfRequest<'a> {
    /// Null, X9.63 or NIST SP 800-56A with SHA-224/256/384/512.
    pub kdf: EcdhKdf,
    /// Public protocol context, at most 4096 bytes; empty for the null KDF.
    pub shared_info: &'a [u8],
    /// Protected output purpose and length.
    pub output: MontgomeryOutput,
    /// New token secret identity, with nonempty ID/label of at most 128 bytes.
    pub identity: SecretKeyIdentity<'a>,
}
impl MontgomeryKdfRequest<'_> {
    pub(crate) fn runtime_request(&self) -> pkcs11_runtime::MontgomeryKdfRequest<'_> {
        pkcs11_runtime::MontgomeryKdfRequest {
            kdf: self.kdf,
            shared_info: self.shared_info,
            output: self.output,
            id: self.identity.id,
            label: self.identity.label,
        }
    }
    /// Check identity, context bounds and KDF/output compatibility without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(self.runtime_request().validate()?)
    }
}
impl std::fmt::Debug for MontgomeryKdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MontgomeryKdfRequest")
            .field("kdf", &self.kdf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
