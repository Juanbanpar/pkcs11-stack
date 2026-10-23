// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::*;
use secrecy::SecretBox;

/// SHA-2 OAEP choice with matching MGF1 digest and empty label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OaepChoice {
    /// Digest for OAEP and MGF1.
    pub digest: DigestAlgorithm,
    /// Maximum plaintext bytes for the current modulus.
    pub maximum_plaintext: usize,
    /// Exact ciphertext length in bytes.
    pub ciphertext_length: usize,
}
/// Borrowed plaintext request; Debug omits input bytes.
pub struct EncryptRequest<'a> {
    /// SHA-2 digest for both OAEP and MGF1; label is empty.
    pub digest: DigestAlgorithm,
    /// One plaintext block, bounded by key size and selected digest.
    pub plaintext: &'a [u8],
}
/// Borrowed ciphertext request; Debug omits input bytes.
pub struct DecryptRequest<'a> {
    /// SHA-2 digest for both OAEP and MGF1; label is empty.
    pub digest: DigestAlgorithm,
    /// One modulus-width ciphertext block.
    pub ciphertext: &'a [u8],
}
impl std::fmt::Debug for EncryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptRequest([REDACTED])")
    }
}
impl std::fmt::Debug for DecryptRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptRequest([REDACTED])")
    }
}
/// Owned plaintext; Debug is redacted and storage zeroizes on drop.
pub type Plaintext = SecretBox<Vec<u8>>;
impl ManagementSession<'_> {
    /// Advisory SHA-2 choices after current key permissions and mechanism checks.
    /// Never probes a provider by performing an encryption/decryption operation.
    pub fn oaep_options(
        &mut self,
        key: &ObjectRef,
        operation: RsaCipherOperation,
    ) -> Result<Vec<OaepChoice>, Error> {
        let caps = self.session.rsa_oaep_capabilities(key, operation)?;
        Ok([
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ]
        .into_iter()
        .map(|digest| OaepChoice {
            digest,
            maximum_plaintext: caps.maximum_plaintext(digest),
            ciphertext_length: caps.ciphertext_length(),
        })
        .collect())
    }
    /// Encrypt once on the token, resolving current permissions and size bounds.
    pub fn encrypt(
        &mut self,
        key: &PublicKeyRef,
        request: &EncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .encrypt_rsa_oaep(key, request.digest, request.plaintext)?)
    }
    /// Decrypt once on the token; no bytes are returned on failure.
    /// Per-operation authentication and failed cryptoki-buffer zeroization are unsupported.
    pub fn decrypt(
        &mut self,
        key: &PrivateKeyRef,
        request: &DecryptRequest<'_>,
    ) -> Result<Plaintext, Error> {
        Ok(self
            .session
            .decrypt_rsa_oaep(key, request.digest, request.ciphertext)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_and_plaintext_never_format_payloads() {
        let canary = b"plaintext-redaction-canary";
        let encrypt = EncryptRequest {
            digest: DigestAlgorithm::Sha256,
            plaintext: canary,
        };
        let decrypt = DecryptRequest {
            digest: DigestAlgorithm::Sha256,
            ciphertext: canary,
        };
        let plaintext = SecretBox::new(Box::new(canary.to_vec()));
        assert!(!format!("{encrypt:?} {decrypt:?} {plaintext:?}").contains("canary"));
    }
}
