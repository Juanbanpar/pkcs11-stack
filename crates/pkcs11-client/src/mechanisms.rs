// SPDX-License-Identifier: MIT OR Apache-2.0
//! Application wrappers for the mechanism families exposed by the runtime.
//!
//! Each operation reuses one runtime implementation; the client never
//! reimplements PKCS#11 calls or capability checks.

use crate::{Authentication, Client, Error, ManagementSession, ObjectRef, Pkcs11Uri, Provider};
use pkcs11_runtime::{
    AES_BLOCK_SIZE, AesDecryptRequest, AesDirection, AesEncryptRequest, AesMode,
    FunctionAvailability, HashAlgorithm, KbkdfCapabilities, KbkdfMode, KbkdfPrf, KbkdfRequest,
    MacAlgorithm, MacKeyRequest, MechanismCapability, SlhDsaCapabilities, SlhDsaKeyPairRequest,
    SlhDsaRequest, SlhDsaSigningPolicy, VerifyRequest,
};
use secrecy::SecretBox;
use x509_cert::{
    der::{
        Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

fn slh_parameter_set_oid(parameter: pkcs11_runtime::SlhDsaParameterSet) -> ObjectIdentifier {
    use pkcs11_runtime::SlhDsaParameterSet as P;
    ObjectIdentifier::new_unwrap(match parameter {
        P::Sha2_128S => "2.16.840.1.101.3.4.3.20",
        P::Sha2_128F => "2.16.840.1.101.3.4.3.21",
        P::Sha2_192S => "2.16.840.1.101.3.4.3.22",
        P::Sha2_192F => "2.16.840.1.101.3.4.3.23",
        P::Sha2_256S => "2.16.840.1.101.3.4.3.24",
        P::Sha2_256F => "2.16.840.1.101.3.4.3.25",
        P::Shake128S => "2.16.840.1.101.3.4.3.26",
        P::Shake128F => "2.16.840.1.101.3.4.3.27",
        P::Shake192S => "2.16.840.1.101.3.4.3.28",
        P::Shake192F => "2.16.840.1.101.3.4.3.29",
        P::Shake256S => "2.16.840.1.101.3.4.3.30",
        P::Shake256F => "2.16.840.1.101.3.4.3.31",
    })
}

fn slh_public_key_der(key: &pkcs11_runtime::SlhDsaPublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: slh_parameter_set_oid(key.parameter_set()),
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(key.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?,
    }
    .to_der()
    .map_err(|_| Error::InvalidPublicKey)
}

impl Provider {
    /// Snapshot token mechanisms with family, operations, bounds and whether a
    /// typed execution path exists.
    pub fn mechanism_capabilities(
        &self,
        uri: &Pkcs11Uri,
    ) -> Result<Vec<MechanismCapability>, Error> {
        Ok(self
            .module
            .resolve_token_uri(uri)?
            .mechanism_capabilities()?)
    }

    /// Report which standard functions the selected upstream interface provides.
    pub fn function_availability(&self) -> Result<Vec<FunctionAvailability>, Error> {
        Ok(self.module.function_availability()?)
    }
}

impl Client<'_> {
    /// Resolve exactly one secret key; retain its selector, never its handle.
    pub fn secret_key(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<ObjectRef, Error> {
        let key = ObjectRef::new(uri)?;
        self.pool()
            .try_acquire(authentication)?
            .session()
            .resolve(&key)?;
        Ok(key)
    }

    /// Digest one bounded buffer on the token.
    pub fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .digest(algorithm, input)?)
    }

    /// Stream chunks through a multipart token digest.
    pub fn digest_chunks<'a>(
        &self,
        algorithm: HashAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .digest_chunks(algorithm, chunks)?)
    }

    /// Compute one full-tag MAC with a selected secret key.
    pub fn mac(
        &self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .mac(key, algorithm, input)?)
    }

    /// Verify one full-tag MAC with a selected secret key.
    pub fn verify_mac(
        &self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        tag: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_mac(key, algorithm, input, tag)?)
    }

    /// Encrypt one bounded buffer with an AES key.
    pub fn encrypt_aes(
        &self,
        key: &ObjectRef,
        request: &AesEncryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .encrypt_aes(key, request)?)
    }

    /// Decrypt one bounded buffer with an AES key, returning redacted plaintext.
    pub fn decrypt_aes(
        &self,
        key: &ObjectRef,
        request: &AesDecryptRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .decrypt_aes(key, request)?)
    }

    /// Inspect AES mode support for a selected key.
    pub fn aes_capabilities(
        &self,
        key: &ObjectRef,
        mode: AesMode,
        direction: AesDirection,
        authentication: Authentication<'_>,
    ) -> Result<pkcs11_runtime::AesCipherCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .aes_cipher_capabilities(key, mode, direction)?)
    }

    /// Verify a token signature with a public key and explicit hashing policy.
    pub fn verify(
        &self,
        key: &crate::PublicKeyRef,
        request: &VerifyRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self.pool().try_acquire(authentication)?.session().verify(
            key,
            request,
            self.policy(),
        )?)
    }

    /// Verify a signature over a precomputed digest using the signature-first API.
    pub fn verify_signature(
        &self,
        key: &crate::PublicKeyRef,
        request: &pkcs11_runtime::SignRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_signature(key, request, signature)?)
    }

    /// Discover SLH-DSA signing capabilities for a selected private key.
    pub fn slh_dsa_capabilities(
        &self,
        key: &crate::PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<SlhDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .slh_dsa_capabilities(key)?)
    }

    /// Sign one original message with SLH-DSA.
    pub fn sign_slh_dsa(
        &self,
        key: &crate::PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_slh_dsa(key, request, policy, context_pin)?)
    }

    /// Verify one SLH-DSA signature on the token.
    pub fn verify_slh_dsa(
        &self,
        key: &crate::PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_slh_dsa(key, request, signature)?)
    }

    /// Export a public, non-private SLH-DSA object as SPKI DER.
    pub fn export_slh_dsa_public_key(
        &self,
        key: &crate::PublicKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        slh_public_key_der(
            &self
                .pool()
                .try_acquire(authentication)?
                .session()
                .slh_dsa_public_key(key)?,
        )
    }
}

impl ManagementSession<'_> {
    /// Digest one bounded buffer on this session's token.
    pub fn digest(&mut self, algorithm: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.session.digest(algorithm, input)?)
    }

    /// Stream chunks through a multipart token digest.
    pub fn digest_chunks<'a>(
        &mut self,
        algorithm: HashAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.digest_chunks(algorithm, chunks)?)
    }

    /// Compute one full-tag MAC with a selected secret key.
    pub fn mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.mac(key, algorithm, input)?)
    }

    /// Stream a MAC over chunks.
    pub fn mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.mac_chunks(key, algorithm, chunks)?)
    }

    /// Verify one full-tag MAC with a selected secret key.
    pub fn verify_mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.verify_mac(key, algorithm, input, tag)?)
    }

    /// Verify a MAC over chunks.
    pub fn verify_mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
        tag: &[u8],
    ) -> Result<(), Error> {
        Ok(self
            .session
            .verify_mac_chunks(key, algorithm, chunks, tag)?)
    }

    /// Encrypt one bounded buffer with an AES key.
    pub fn encrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesEncryptRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes(key, request)?)
    }

    /// Stream AES encryption over chunks.
    pub fn encrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encrypt_aes_chunks(key, mode, iv, chunks)?)
    }

    /// Decrypt one bounded buffer with an AES key, returning redacted plaintext.
    pub fn decrypt_aes(
        &mut self,
        key: &ObjectRef,
        request: &AesDecryptRequest<'_>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        Ok(self.session.decrypt_aes(key, request)?)
    }

    /// Stream AES decryption over chunks.
    pub fn decrypt_aes_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        iv: Option<&[u8; AES_BLOCK_SIZE]>,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        Ok(self.session.decrypt_aes_chunks(key, mode, iv, chunks)?)
    }

    /// Inspect AES mode support for a selected key on this session.
    pub fn aes_capabilities(
        &mut self,
        key: &ObjectRef,
        mode: AesMode,
        direction: AesDirection,
    ) -> Result<pkcs11_runtime::AesCipherCapabilities, Error> {
        Ok(self.session.aes_cipher_capabilities(key, mode, direction)?)
    }

    /// Export a public, non-private SLH-DSA object as SPKI DER.
    pub fn export_slh_dsa_public_key(
        &mut self,
        key: &crate::PublicKeyRef,
    ) -> Result<Vec<u8>, Error> {
        slh_public_key_der(&self.session.slh_dsa_public_key(key)?)
    }

    /// Inspect supported SP 800-108 PRF/mode combinations for a base key.
    pub fn kbkdf_options(&mut self, base: &ObjectRef) -> Result<Vec<KbkdfCapabilities>, Error> {
        Ok(self.session.kbkdf_options(base)?)
    }

    /// Derive one persistent key with SP 800-108.
    pub fn derive_kbkdf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.derive_kbkdf(base, request, mode, iv)?)
    }

    /// Inspect one explicit SP 800-108 PRF and mode.
    pub fn kbkdf_capabilities(
        &mut self,
        base: &ObjectRef,
        prf: KbkdfPrf,
        mode: KbkdfMode,
    ) -> Result<KbkdfCapabilities, Error> {
        Ok(self.session.kbkdf_capabilities(base, prf, mode)?)
    }

    /// Generate a persistent HMAC or AES-CMAC key.
    pub fn generate_mac_key(&mut self, request: &MacKeyRequest<'_>) -> Result<(), Error> {
        self.session.generate_mac_key(request)?;
        Ok(())
    }

    /// Generate a persistent SLH-DSA signing pair.
    pub fn generate_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_slh_dsa_key_pair(request)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_runtime::{SlhDsaParameterSet, SlhDsaPublicKey};
    use x509_cert::der::Decode;

    #[test]
    fn slh_dsa_spki_uses_the_standard_parameter_set_oids() {
        for (parameter, oid) in [
            (SlhDsaParameterSet::Sha2_128S, "2.16.840.1.101.3.4.3.20"),
            (SlhDsaParameterSet::Sha2_128F, "2.16.840.1.101.3.4.3.21"),
            (SlhDsaParameterSet::Sha2_192S, "2.16.840.1.101.3.4.3.22"),
            (SlhDsaParameterSet::Sha2_192F, "2.16.840.1.101.3.4.3.23"),
            (SlhDsaParameterSet::Sha2_256S, "2.16.840.1.101.3.4.3.24"),
            (SlhDsaParameterSet::Sha2_256F, "2.16.840.1.101.3.4.3.25"),
            (SlhDsaParameterSet::Shake128S, "2.16.840.1.101.3.4.3.26"),
            (SlhDsaParameterSet::Shake128F, "2.16.840.1.101.3.4.3.27"),
            (SlhDsaParameterSet::Shake192S, "2.16.840.1.101.3.4.3.28"),
            (SlhDsaParameterSet::Shake192F, "2.16.840.1.101.3.4.3.29"),
            (SlhDsaParameterSet::Shake256S, "2.16.840.1.101.3.4.3.30"),
            (SlhDsaParameterSet::Shake256F, "2.16.840.1.101.3.4.3.31"),
        ] {
            let key =
                SlhDsaPublicKey::from_bytes(parameter, vec![0; parameter.public_key_length()])
                    .unwrap();
            let der = slh_public_key_der(&key).unwrap();
            let spki = SubjectPublicKeyInfoOwned::from_der(&der).unwrap();
            assert_eq!(spki.algorithm.oid, ObjectIdentifier::new_unwrap(oid));
            assert!(spki.algorithm.parameters.is_none());
        }
    }
}
