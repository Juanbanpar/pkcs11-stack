// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, HashSlhDsaCapabilities, HashSlhDsaRequest,
    HashSlhDsaSigningPolicy, ManagementSession, SlhDsaCapabilities, SlhDsaKeyPairRequest,
    SlhDsaRequest, SlhDsaSigningPolicy, public_key::encode_raw_spki,
};
use x509_cert::der::asn1::ObjectIdentifier;

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
    encode_raw_spki(slh_parameter_set_oid(key.parameter_set()), key.as_bytes())
}

impl Client<'_> {
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

    /// Inspect HashSLH-DSA signing support for one hash/mode.
    pub fn hash_slh_dsa_capabilities(
        &self,
        key: &crate::PrivateKeyRef,
        hash: pkcs11_runtime::PrehashAlgorithm,
        prehashed: bool,
        authentication: Authentication<'_>,
    ) -> Result<HashSlhDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .hash_slh_dsa_capabilities(key, hash, prehashed)?)
    }

    /// Sign one HashSLH-DSA message or digest.
    pub fn sign_hash_slh_dsa(
        &self,
        key: &crate::PrivateKeyRef,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_hash_slh_dsa(key, request, policy, context_pin)?)
    }

    /// Verify one HashSLH-DSA signature on the token.
    pub fn verify_hash_slh_dsa(
        &self,
        key: &crate::PublicKeyRef,
        request: &HashSlhDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_hash_slh_dsa(key, request, signature)?)
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
    /// Read the public key's SLH-DSA parameter set without reading key bytes.
    pub fn slh_dsa_public_parameter_set(
        &mut self,
        key: &crate::PublicKeyRef,
    ) -> Result<pkcs11_runtime::SlhDsaParameterSet, Error> {
        Ok(self.session.slh_dsa_public_parameter_set(key)?)
    }

    /// Verify one SLH-DSA signature on the token.
    pub fn verify_slh_dsa(
        &mut self,
        key: &crate::PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session.verify_slh_dsa(key, request, signature)?;
        Ok(())
    }

    /// Verify one HashSLH-DSA signature on the token.
    pub fn verify_hash_slh_dsa(
        &mut self,
        key: &crate::PublicKeyRef,
        request: &HashSlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session.verify_hash_slh_dsa(key, request, signature)?;
        Ok(())
    }

    /// Export a public, non-private SLH-DSA object as SPKI DER.
    pub fn export_slh_dsa_public_key(
        &mut self,
        key: &crate::PublicKeyRef,
    ) -> Result<Vec<u8>, Error> {
        slh_public_key_der(&self.session.slh_dsa_public_key(key)?)
    }

    /// Generate a persistent SLH-DSA signing pair.
    pub fn generate_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_slh_dsa_key_pair(request)?;
        Ok(())
    }

    /// Generate a protected HashSLH-DSA-only pair in an RW session.
    /// Pure SLH-DSA remains excluded from the allowed-mechanism list.
    pub fn generate_hash_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_hash_slh_dsa_key_pair(request)?;
        Ok(())
    }

    /// Discover SLH-DSA signing capabilities for a selected private key.
    pub fn slh_dsa_capabilities(
        &mut self,
        key: &crate::PrivateKeyRef,
    ) -> Result<SlhDsaCapabilities, Error> {
        Ok(self.session.slh_dsa_capabilities(key)?)
    }

    /// Sign one original message with SLH-DSA.
    pub fn sign_slh_dsa(
        &mut self,
        key: &crate::PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_slh_dsa(key, request, policy, context_pin)?)
    }

    /// Inspect HashSLH-DSA signing support for one hash/mode.
    pub fn hash_slh_dsa_capabilities(
        &mut self,
        key: &crate::PrivateKeyRef,
        hash: pkcs11_runtime::PrehashAlgorithm,
        prehashed: bool,
    ) -> Result<HashSlhDsaCapabilities, Error> {
        Ok(self
            .session
            .hash_slh_dsa_capabilities(key, hash, prehashed)?)
    }

    /// Sign one HashSLH-DSA message or digest.
    pub fn sign_hash_slh_dsa(
        &mut self,
        key: &crate::PrivateKeyRef,
        request: &HashSlhDsaRequest<'_>,
        policy: &HashSlhDsaSigningPolicy,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_hash_slh_dsa(key, request, policy, context_pin)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_runtime::{SlhDsaParameterSet, SlhDsaPublicKey};
    use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

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
