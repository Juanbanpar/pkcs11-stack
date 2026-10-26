// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, CertificateDocument, CertificateRef, Client, Error, MlDsaHedging,
    MlDsaParameterSet, MlDsaRequest, MlDsaSigningPolicy, Pin, Pkcs11Uri, PrivateKeyRef,
    ml_dsa::parameter_set_oid,
};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};

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
        if spki.algorithm.parameters.is_some() {
            return Err(Error::InvalidPublicKey);
        }
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidPublicKey)?;
        Self::from_bytes(parameter, bytes)
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

/// Exact X.509 certificate and software ML-DSA verifier. Parsing does not check
/// issuer signatures, chains, validity, usage, revocation or hostnames.
pub struct MlDsaCertificate {
    document: CertificateDocument,
    key: MlDsaVerifyingKey,
}
impl std::fmt::Debug for MlDsaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaCertificate")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}
impl MlDsaCertificate {
    /// Parse exactly one DER X.509 certificate with an RFC 9881 ML-DSA public key.
    /// Rejects algorithm parameters, wrong key sizes, trailing bytes and other algorithms.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let document = CertificateDocument::from_der(der)?;
        let key =
            MlDsaVerifyingKey::from_spki_der(document.spki_der()).map_err(|error| match error {
                Error::InvalidPublicKey => Error::InvalidCertificate,
                other => other,
            })?;
        Ok(Self { document, key })
    }
    /// Original certificate document, with no trust assertion.
    pub fn document(&self) -> &CertificateDocument {
        &self.document
    }
    /// Exact certificate DER.
    pub fn der(&self) -> &[u8] {
        self.document.der()
    }
    /// Certificate SubjectPublicKeyInfo DER.
    pub fn spki_der(&self) -> &[u8] {
        self.document.spki_der()
    }
    /// Public-key parameter set.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.key.parameter_set()
    }
    /// Retained software verifier, independent of token state.
    pub fn verifying_key(&self) -> &MlDsaVerifyingKey {
        &self.key
    }
    /// Check context/parameter compatibility before signing or binding.
    pub fn validate_signing_request(&self, request: &MlDsaRequest<'_>) -> Result<(), Error> {
        self.key.validate_request(request)
    }
    /// Verify a message signature against this certificate key in software.
    /// Does not validate the certificate or assert private-key ownership.
    pub fn verify_signature(
        &self,
        request: &MlDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.key.verify_signature(request, signature)
    }
    fn verify_binding(&self, request: &MlDsaRequest<'_>, signature: &[u8]) -> Result<(), Error> {
        self.verify_signature(request, signature)
            .map_err(|error| match error {
                Error::SignatureMismatch => Error::KeyCertificateMismatch,
                other => other,
            })
    }
}

/// Proven ML-DSA key selector and immutable certificate snapshot.
/// No PIN or handle is retained. Construction requires a verified binding probe;
/// use `Client::sign_ml_dsa_identity` to verify each subsequent signature.
#[derive(Debug)]
pub struct MlDsaIdentity {
    key: PrivateKeyRef,
    certificate: MlDsaCertificate,
}
impl MlDsaIdentity {
    /// Stable private-key selector. Direct signing skips the association check.
    pub fn key(&self) -> &PrivateKeyRef {
        &self.key
    }
    /// Certificate snapshot used for binding and later verification; no trust assertion.
    pub fn certificate(&self) -> &MlDsaCertificate {
        &self.certificate
    }
}

impl Client<'_> {
    /// Read one uniquely selected token certificate and construct a software verifier.
    /// The certificate need not share an ID/label with the private key.
    pub fn ml_dsa_certificate(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<MlDsaCertificate, Error> {
        let reference = CertificateRef::new(uri)?;
        let der = reference.der(self.pool().try_acquire(authentication)?.session())?;
        MlDsaCertificate::from_der(der)
    }
    /// Prove a key/certificate association with one domain-separated, hedged
    /// signature and software verification. Required hedging has no fallback.
    /// Policy/context compatibility is checked before authentication. Mismatches
    /// discard the lease; no signature, binding or login is automatically retried.
    pub fn bind_ml_dsa_identity(
        &self,
        key: PrivateKeyRef,
        certificate: MlDsaCertificate,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<MlDsaIdentity, Error> {
        let request = MlDsaRequest {
            parameter_set: certificate.parameter_set(),
            message: b"pkcs11-client ML-DSA identity binding v1\0",
            context: b"pkcs11-client identity binding v1",
            hedging: MlDsaHedging::Required,
        };
        policy.validate(&request)?;
        let mut lease = self.pool().try_acquire(authentication)?;
        if lease.session().ml_dsa_capabilities(&key)?.parameter_set != certificate.parameter_set() {
            return Err(Error::KeyCertificateMismatch);
        }
        let signature = lease
            .session()
            .sign_ml_dsa(&key, &request, policy, context_pin)?;
        if let Err(error) = certificate.verify_binding(&request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(MlDsaIdentity { key, certificate })
    }
    /// Sign once and verify in software against the retained certificate before
    /// releasing output. Detects replacement keys even with identical selectors
    /// and parameters. Unsupported requests fail before checkout/authentication;
    /// verification failures discard the lease. No automatic retry occurs.
    pub fn sign_ml_dsa_identity(
        &self,
        identity: &MlDsaIdentity,
        request: &MlDsaRequest<'_>,
        policy: &MlDsaSigningPolicy,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        policy.validate(request)?;
        identity.certificate.validate_signing_request(request)?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let signature = lease
            .session()
            .sign_ml_dsa(&identity.key, request, policy, context_pin)?;
        if let Err(error) = identity.certificate.verify_binding(request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}
