// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, ManagementSession, Pin, Pkcs11Uri, PrivateKeyRef, Provider,
    PublicKeyRef, SlhDsaCapabilities, SlhDsaKeyPairRequest, SlhDsaParameterSet, SlhDsaPublicKey,
    SlhDsaRequest, SlhDsaSigningPolicy,
};
use x509_cert::{
    der::{
        Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

fn parameter_set_oid(parameter: SlhDsaParameterSet) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match parameter {
        SlhDsaParameterSet::Sha2_128S => "2.16.840.1.101.3.4.3.20",
        SlhDsaParameterSet::Sha2_128F => "2.16.840.1.101.3.4.3.21",
        SlhDsaParameterSet::Sha2_192S => "2.16.840.1.101.3.4.3.22",
        SlhDsaParameterSet::Sha2_192F => "2.16.840.1.101.3.4.3.23",
        SlhDsaParameterSet::Sha2_256S => "2.16.840.1.101.3.4.3.24",
        SlhDsaParameterSet::Sha2_256F => "2.16.840.1.101.3.4.3.25",
        SlhDsaParameterSet::Shake128S => "2.16.840.1.101.3.4.3.26",
        SlhDsaParameterSet::Shake128F => "2.16.840.1.101.3.4.3.27",
        SlhDsaParameterSet::Shake192S => "2.16.840.1.101.3.4.3.28",
        SlhDsaParameterSet::Shake192F => "2.16.840.1.101.3.4.3.29",
        SlhDsaParameterSet::Shake256S => "2.16.840.1.101.3.4.3.30",
        SlhDsaParameterSet::Shake256F => "2.16.840.1.101.3.4.3.31",
    })
}
fn public_key_der(key: &SlhDsaPublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: parameter_set_oid(key.parameter_set()),
            // RFC 9909 requires absent parameters and a raw public-key BIT STRING.
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(key.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?,
    }
    .to_der()
    .map_err(|_| Error::InvalidPublicKey)
}

fn verification_error(error: pkcs11_runtime::Error) -> Error {
    match error {
        pkcs11_runtime::Error::SignatureMismatch => Error::SignatureMismatch,
        other => other.into(),
    }
}

impl Provider {
    /// Advertised SLH-DSA generation choices. Does not generate keys or prove template support.
    pub fn slh_dsa_generation_options(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<Vec<SlhDsaParameterSet>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .slh_dsa_generation_options()?)
    }
}
impl ManagementSession<'_> {
    /// Generate one persistent signing/verification-only pair in an RW session.
    /// Existing public/private IDs are rejected; failures may leave partial objects.
    pub fn generate_slh_dsa_key_pair(
        &mut self,
        request: &SlhDsaKeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_slh_dsa_key_pair(request)?;
        Ok(())
    }
    /// Rediscover private-key permissions and parameter set without signing.
    pub fn slh_dsa_capabilities(
        &mut self,
        key: &PrivateKeyRef,
    ) -> Result<SlhDsaCapabilities, Error> {
        Ok(self.session.slh_dsa_capabilities(key)?)
    }
    /// Sign once under an explicit SLH-DSA policy. Classical signing policy does not apply.
    /// Close the session before releasing output when checked cleanup is required.
    pub fn sign_slh_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_slh_dsa(key, request, policy, context_pin)?)
    }
    /// Verify on the token; does not establish certificate trust or key association.
    pub fn verify_slh_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_slh_dsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a public, non-private SLH-DSA object as RFC 9909 SPKI DER.
    pub fn export_slh_dsa_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        public_key_der(&self.session.slh_dsa_public_key(key)?)
    }
}
impl Client<'_> {
    /// Discover the selected private key's current SLH-DSA capabilities.
    pub fn slh_dsa_capabilities(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<SlhDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .slh_dsa_capabilities(key)?)
    }
    /// Sign once under a separate explicit SLH-DSA policy; never hashes externally or retries.
    /// No key handle, input, PIN or SLH-DSA policy is cached in the client.
    pub fn sign_slh_dsa(
        &self,
        key: &PrivateKeyRef,
        request: &SlhDsaRequest<'_>,
        policy: &SlhDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_slh_dsa(key, request, policy, context_pin)?)
    }
    /// Verify using a public key on the token; mismatches do not invalidate its session.
    pub fn verify_slh_dsa(
        &self,
        key: &PublicKeyRef,
        request: &SlhDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.parameter_set.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        self.pool()
            .try_acquire(authentication)?
            .session()
            .verify_slh_dsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a uniquely selected public, non-private SLH-DSA key as RFC 9909 SPKI DER.
    pub fn export_slh_dsa_public_key(
        &self,
        key: &PublicKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        public_key_der(
            &self
                .pool()
                .try_acquire(authentication)?
                .session()
                .slh_dsa_public_key(key)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    #[test]
    fn spki_has_standard_oid_raw_key_and_absent_parameters() {
        for (index, parameter) in SlhDsaParameterSet::ALL.into_iter().enumerate() {
            let oid = format!("2.16.840.1.101.3.4.3.{}", index + 20);
            let key =
                SlhDsaPublicKey::from_bytes(parameter, vec![0xA5; parameter.public_key_length()])
                    .unwrap();
            let encoded = public_key_der(&key).unwrap();
            let decoded = SubjectPublicKeyInfoOwned::from_der(&encoded).unwrap();
            assert_eq!(decoded.algorithm.oid.to_string(), oid);
            assert!(decoded.algorithm.parameters.is_none());
            assert_eq!(
                decoded.subject_public_key.as_bytes().unwrap(),
                key.as_bytes()
            );
        }
    }
}
