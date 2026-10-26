// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, ManagementSession, MlDsaCapabilities, MlDsaParameterSet,
    MlDsaPublicKey, MlDsaRequest, MlDsaSigningPolicy, Pin, Pkcs11Uri, PrivateKeyRef, Provider,
    PublicKeyRef,
};
use x509_cert::{
    der::{
        Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

pub(crate) fn parameter_set_oid(parameter: MlDsaParameterSet) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match parameter {
        MlDsaParameterSet::MlDsa44 => "2.16.840.1.101.3.4.3.17",
        MlDsaParameterSet::MlDsa65 => "2.16.840.1.101.3.4.3.18",
        MlDsaParameterSet::MlDsa87 => "2.16.840.1.101.3.4.3.19",
    })
}
pub(crate) fn public_key_der(key: &MlDsaPublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: parameter_set_oid(key.parameter_set()),
            // RFC 9881 requires absent parameters and a raw public-key BIT STRING.
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
    /// Advertised ML-DSA generation choices. Does not generate keys or prove template support.
    pub fn ml_dsa_generation_options(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<Vec<MlDsaParameterSet>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .ml_dsa_generation_options()?)
    }
}
impl ManagementSession<'_> {
    /// Generate one persistent sensitive, nonextractable ML-DSA pair in an RW session.
    /// Identity is explicit; duplicate IDs remain possible and are not overwritten.
    pub fn generate_ml_dsa_key_pair(
        &mut self,
        parameter: MlDsaParameterSet,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(), Error> {
        self.session
            .generate_ml_dsa_key_pair(parameter, id, label, always_authenticate)?;
        Ok(())
    }
    /// Rediscover private-key permissions and parameter set without signing.
    pub fn ml_dsa_capabilities(&mut self, key: &PrivateKeyRef) -> Result<MlDsaCapabilities, Error> {
        Ok(self.session.ml_dsa_capabilities(key)?)
    }
    /// Sign once under an explicit ML-DSA policy. Classical signing policy does not apply.
    /// Close the session before releasing output when checked cleanup is required.
    pub fn sign_ml_dsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_ml_dsa(key, request, policy, context_pin)?)
    }
    /// Verify on the token; does not establish certificate trust or key association.
    pub fn verify_ml_dsa(
        &mut self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_ml_dsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a public, non-private ML-DSA object as RFC 9881 SPKI DER.
    pub fn export_ml_dsa_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        public_key_der(&self.session.ml_dsa_public_key(key)?)
    }
}
impl Client<'_> {
    /// Discover the selected private key's current ML-DSA capabilities.
    pub fn ml_dsa_capabilities(
        &self,
        key: &PrivateKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<MlDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .ml_dsa_capabilities(key)?)
    }
    /// Sign once under a separate explicit ML-DSA policy; never hashes externally or retries.
    /// No key handle, input, PIN or ML-DSA policy is cached in the client.
    pub fn sign_ml_dsa(
        &self,
        key: &PrivateKeyRef,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_ml_dsa(key, request, policy, context_pin)?)
    }
    /// Verify using a public key on the token; mismatches do not invalidate its session.
    pub fn verify_ml_dsa(
        &self,
        key: &PublicKeyRef,
        request: &MlDsaRequest<'_>,
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
            .verify_ml_dsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a uniquely selected public, non-private ML-DSA key as RFC 9881 SPKI DER.
    pub fn export_ml_dsa_public_key(
        &self,
        key: &PublicKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        public_key_der(
            &self
                .pool()
                .try_acquire(authentication)?
                .session()
                .ml_dsa_public_key(key)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    #[test]
    fn spki_has_standard_oid_raw_key_and_absent_parameters() {
        for (parameter, oid) in [
            (MlDsaParameterSet::MlDsa44, "2.16.840.1.101.3.4.3.17"),
            (MlDsaParameterSet::MlDsa65, "2.16.840.1.101.3.4.3.18"),
            (MlDsaParameterSet::MlDsa87, "2.16.840.1.101.3.4.3.19"),
        ] {
            let key =
                MlDsaPublicKey::from_bytes(parameter, vec![0xA5; parameter.public_key_length()])
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
