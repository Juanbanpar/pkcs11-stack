// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::public_key::{encode_raw_spki, raw_key_bytes};
use crate::{
    Authentication, Client, Error, ManagementSession, MlDsaCapabilities, MlDsaParameterSet,
    MlDsaPublicKey, MlDsaRequest, MlDsaSigningPolicy, Pin, Pkcs11Uri, PrivateKeyRef, Provider,
    PublicKeyRef,
};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};
use pkcs11_runtime::{HashMlDsaCapabilities, HashMlDsaRequest, HashMlDsaSigningPolicy};
use x509_cert::{
    der::{Decode, asn1::ObjectIdentifier},
    spki::SubjectPublicKeyInfoOwned,
};

fn parameter_set_oid(parameter: MlDsaParameterSet) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match parameter {
        MlDsaParameterSet::MlDsa44 => "2.16.840.1.101.3.4.3.17",
        MlDsaParameterSet::MlDsa65 => "2.16.840.1.101.3.4.3.18",
        MlDsaParameterSet::MlDsa87 => "2.16.840.1.101.3.4.3.19",
    })
}
fn public_key_der(key: &MlDsaPublicKey) -> Result<Vec<u8>, Error> {
    encode_raw_spki(parameter_set_oid(key.parameter_set()), key.as_bytes())
}

enum VerificationKey {
    MlDsa44(Box<VerifyingKey<MlDsa44>>),
    MlDsa65(Box<VerifyingKey<MlDsa65>>),
    MlDsa87(Box<VerifyingKey<MlDsa87>>),
}

/// Software ML-DSA public key. Holds no token handle or private material.
/// Verification uses the pure FIPS 204 message/context mode only.
pub struct MlDsaVerifyingKey(VerificationKey);
impl std::fmt::Debug for MlDsaVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaVerifyingKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}
impl MlDsaVerifyingKey {
    /// Decode raw public-key bytes of exactly the selected parameter set's length.
    /// Does not prove ownership or establish certificate trust.
    pub fn from_bytes(parameter: MlDsaParameterSet, bytes: &[u8]) -> Result<Self, Error> {
        let invalid = |_| Error::InvalidPublicKey;
        let key = match parameter {
            MlDsaParameterSet::MlDsa44 => VerificationKey::MlDsa44(Box::new(VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa44>::try_from(bytes).map_err(invalid)?,
            ))),
            MlDsaParameterSet::MlDsa65 => VerificationKey::MlDsa65(Box::new(VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(invalid)?,
            ))),
            MlDsaParameterSet::MlDsa87 => VerificationKey::MlDsa87(Box::new(VerifyingKey::decode(
                &EncodedVerifyingKey::<MlDsa87>::try_from(bytes).map_err(invalid)?,
            ))),
        };
        Ok(Self(key))
    }
    /// Decode exactly one RFC 9881 SPKI DER key. Parameters must be absent and
    /// the BIT STRING must contain the raw, byte-aligned public-key encoding.
    /// Unknown algorithms, including HashML-DSA, are unsupported.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| Error::InvalidPublicKey)?;
        let parameter = [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ]
        .into_iter()
        .find(|&parameter| parameter_set_oid(parameter) == spki.algorithm.oid)
        .ok_or(Error::UnsupportedCertificateKey)?;
        Self::from_bytes(parameter, raw_key_bytes(&spki)?)
    }
    /// Parameter set encoded by this public key.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        match &self.0 {
            VerificationKey::MlDsa44(_) => MlDsaParameterSet::MlDsa44,
            VerificationKey::MlDsa65(_) => MlDsaParameterSet::MlDsa65,
            VerificationKey::MlDsa87(_) => MlDsaParameterSet::MlDsa87,
        }
    }
    /// Validate context length and parameter compatibility without token access.
    /// The request's hedging choice has no effect on verification.
    pub fn validate_request(&self, request: &MlDsaRequest<'_>) -> Result<(), Error> {
        request.validate()?;
        if request.parameter_set != self.parameter_set() {
            return Err(Error::UnsupportedVerification);
        }
        Ok(())
    }
    /// Verify a pure ML-DSA signature in software, including its context and
    /// canonical encoding. Malformed/nonmatching signatures return `SignatureMismatch`.
    /// No module or authentication is needed; this makes no trust decision.
    pub fn verify_signature(
        &self,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.validate_request(request)?;
        if signature.len() != self.parameter_set().signature_length() {
            return Err(Error::SignatureMismatch);
        }
        let mismatch = |_| Error::SignatureMismatch;
        let valid = match &self.0 {
            VerificationKey::MlDsa44(key) => key.verify_with_context(
                request.message,
                request.context,
                &Signature::<MlDsa44>::try_from(signature).map_err(mismatch)?,
            ),
            VerificationKey::MlDsa65(key) => key.verify_with_context(
                request.message,
                request.context,
                &Signature::<MlDsa65>::try_from(signature).map_err(mismatch)?,
            ),
            VerificationKey::MlDsa87(key) => key.verify_with_context(
                request.message,
                request.context,
                &Signature::<MlDsa87>::try_from(signature).map_err(mismatch)?,
            ),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::SignatureMismatch)
        }
    }
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

impl Client<'_> {
    /// Inspect HashML-DSA signing support for one hash/mode.
    pub fn hash_ml_dsa_capabilities(
        &self,
        key: &crate::PrivateKeyRef,
        hash: pkcs11_runtime::PrehashAlgorithm,
        prehashed: bool,
        authentication: Authentication<'_>,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .hash_ml_dsa_capabilities(key, hash, prehashed)?)
    }

    /// Sign one HashML-DSA message or digest.
    pub fn sign_hash_ml_dsa(
        &self,
        key: &crate::PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &HashMlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_hash_ml_dsa(key, request, policy, context_pin)?)
    }

    /// Verify one HashML-DSA signature on the token.
    pub fn verify_hash_ml_dsa(
        &self,
        key: &crate::PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_hash_ml_dsa(key, request, signature)?)
    }
}

impl ManagementSession<'_> {
    /// Read the public key's ML-DSA parameter set without reading key bytes.
    pub fn ml_dsa_public_parameter_set(
        &mut self,
        key: &crate::PublicKeyRef,
    ) -> Result<MlDsaParameterSet, Error> {
        Ok(self.session.ml_dsa_public_parameter_set(key)?)
    }

    /// Verify one HashML-DSA signature on the token.
    pub fn verify_hash_ml_dsa(
        &mut self,
        key: &crate::PublicKeyRef,
        request: &HashMlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session.verify_hash_ml_dsa(key, request, signature)?;
        Ok(())
    }

    /// Inspect HashML-DSA signing support for one hash/mode.
    pub fn hash_ml_dsa_capabilities(
        &mut self,
        key: &crate::PrivateKeyRef,
        hash: pkcs11_runtime::PrehashAlgorithm,
        prehashed: bool,
    ) -> Result<HashMlDsaCapabilities, Error> {
        Ok(self
            .session
            .hash_ml_dsa_capabilities(key, hash, prehashed)?)
    }

    /// Sign one HashML-DSA message or digest.
    pub fn sign_hash_ml_dsa(
        &mut self,
        key: &crate::PrivateKeyRef,
        request: &HashMlDsaRequest<'_>,
        policy: &HashMlDsaSigningPolicy,
        context_pin: Option<crate::Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .sign_hash_ml_dsa(key, request, policy, context_pin)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
