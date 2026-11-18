// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH,
    AesGcmDecryptRequest, AesGcmEncryptRequest, Error, ManagementSession, NonceSequence, ObjectRef,
    Plaintext,
};

const MAGIC: &[u8; 7] = b"P11GCM\x01";
/// Version-1 envelope header length: magic/version followed by a 12-byte nonce.
pub const AES_GCM_ENVELOPE_HEADER: usize = MAGIC.len() + AES_GCM_NONCE_LENGTH;
/// Maximum encoded envelope length, including nonce and authentication tag.
pub const AES_GCM_MAXIMUM_ENVELOPE: usize =
    AES_GCM_ENVELOPE_HEADER + AES_GCM_MAXIMUM_PLAINTEXT + AES_GCM_TAG_LENGTH;

/// Validated borrowed AES-GCM envelope. Parsing authenticates no data.
/// Debug omits the nonce and ciphertext. See the
/// [wire format](https://github.com/Juanbanpar/pkcs11-stack/blob/main/docs/aes-gcm-envelope.md).
pub struct AesGcmEnvelope<'a> {
    nonce: &'a [u8; AES_GCM_NONCE_LENGTH],
    ciphertext: &'a [u8],
}
impl std::fmt::Debug for AesGcmEnvelope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmEnvelope").finish_non_exhaustive()
    }
}
impl<'a> AesGcmEnvelope<'a> {
    /// Validate the exact version-1 header and bounded ciphertext/tag length.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if !(AES_GCM_ENVELOPE_HEADER + AES_GCM_TAG_LENGTH..=AES_GCM_MAXIMUM_ENVELOPE)
            .contains(&bytes.len())
        {
            return Err(Error::InvalidEnvelope);
        }
        let payload = bytes.strip_prefix(MAGIC).ok_or(Error::InvalidEnvelope)?;
        let (nonce, ciphertext) = payload.split_first_chunk().ok_or(Error::InvalidEnvelope)?;
        Ok(Self { nonce, ciphertext })
    }
    /// Borrow the nonce; it is not secret and is authenticated by GCM at decryption.
    pub fn nonce(&self) -> &[u8; AES_GCM_NONCE_LENGTH] {
        self.nonce
    }
    /// Borrow the ciphertext and full authentication tag.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
}
impl ManagementSession<'_> {
    /// Reserve a durable nonce, encrypt once and encode a version-1 envelope.
    /// All writers of a new key must share one intact `NonceSequence`; copied keys,
    /// state rollback and uncoordinated hosts are unsupported. A failed operation
    /// consumes its reservation and is never retried. Check session closure before output.
    pub fn encrypt_aes_gcm_envelope(
        &mut self,
        key: &ObjectRef,
        sequence: &mut NonceSequence,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if aad.len() > AES_GCM_MAXIMUM_AAD || plaintext.len() > AES_GCM_MAXIMUM_PLAINTEXT {
            return Err(Error::InvalidEnvelope);
        }
        let nonce = sequence.reserve(key)?;
        let ciphertext = self.encrypt_aes_gcm(
            key,
            &AesGcmEncryptRequest {
                nonce: &nonce,
                aad,
                plaintext,
            },
        )?;
        let mut output = Vec::with_capacity(AES_GCM_ENVELOPE_HEADER + ciphertext.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }
    /// Authenticate a version-1 envelope before returning zeroizing plaintext.
    /// Unsupported headers, bounds or authentication failures return no plaintext.
    pub fn decrypt_aes_gcm_envelope(
        &mut self,
        key: &ObjectRef,
        aad: &[u8],
        bytes: &[u8],
    ) -> Result<Plaintext, Error> {
        let envelope = AesGcmEnvelope::parse(bytes)?;
        self.decrypt_aes_gcm(
            key,
            &AesGcmDecryptRequest {
                nonce: envelope.nonce,
                aad,
                ciphertext: envelope.ciphertext,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_boundaries_and_headers_are_strict() {
        for length in [0, 6, 18, 19, 34, AES_GCM_MAXIMUM_ENVELOPE + 1] {
            assert!(AesGcmEnvelope::parse(&vec![0; length]).is_err());
        }
        for length in [35, AES_GCM_MAXIMUM_ENVELOPE] {
            let mut bytes = vec![0; length];
            bytes[..7].copy_from_slice(MAGIC);
            assert_eq!(
                AesGcmEnvelope::parse(&bytes).unwrap().ciphertext().len(),
                length - 19
            );
            bytes[6] = 2;
            assert!(AesGcmEnvelope::parse(&bytes).is_err());
        }
    }
}
