// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, CertificateDocument, CertificateRef, Client, EdDsaCurve, EdDsaRequest,
    EdDsaVerifyingKey, Error, Pin, Pkcs11Uri, PrivateKeyRef,
};
/// Exact X.509 certificate and software EdDSA verifier. Parsing does not check
/// issuer signatures, chains, validity, usage, revocation or hostnames.
pub struct EdDsaCertificate {
    document: CertificateDocument,
    key: EdDsaVerifyingKey,
}
impl std::fmt::Debug for EdDsaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDsaCertificate")
            .field("curve", &self.curve())
            .finish_non_exhaustive()
    }
}
impl EdDsaCertificate {
    /// Parse exactly one DER X.509 certificate with an RFC 8410 EdDSA public key.
    /// Rejects algorithm parameters, wrong key sizes, trailing bytes and other algorithms.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let document = CertificateDocument::from_der(der)?;
        let key =
            EdDsaVerifyingKey::from_spki_der(document.spki_der()).map_err(|error| match error {
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
    /// Public-key curve.
    pub fn curve(&self) -> EdDsaCurve {
        self.key.curve()
    }
    /// Retained software verifier, independent of token state.
    pub fn verifying_key(&self) -> &EdDsaVerifyingKey {
        &self.key
    }
    /// Check curve compatibility before signing or binding.
    pub fn validate_signing_request(&self, request: &EdDsaRequest<'_>) -> Result<(), Error> {
        self.key.validate_request(request)
    }
    /// Verify a message signature against this certificate key in software.
    /// Does not validate the certificate or assert private-key ownership.
    pub fn verify_signature(
        &self,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.key.verify_signature(request, signature)
    }
    fn verify_binding(&self, request: &EdDsaRequest<'_>, signature: &[u8]) -> Result<(), Error> {
        self.verify_signature(request, signature)
            .map_err(|error| match error {
                Error::SignatureMismatch => Error::KeyCertificateMismatch,
                other => other,
            })
    }
}

/// Proven EdDSA key selector and immutable certificate snapshot.
/// No PIN or handle is retained. Construction requires a verified binding probe;
/// use `Client::sign_eddsa_identity` to verify each subsequent signature.
#[derive(Debug)]
pub struct EdDsaIdentity {
    key: PrivateKeyRef,
    certificate: EdDsaCertificate,
}
impl EdDsaIdentity {
    /// Stable private-key selector. Direct signing skips the association check.
    pub fn key(&self) -> &PrivateKeyRef {
        &self.key
    }
    /// Certificate snapshot used for binding and later verification; no trust assertion.
    pub fn certificate(&self) -> &EdDsaCertificate {
        &self.certificate
    }
}

impl Client<'_> {
    /// Read one uniquely selected token certificate and construct a software verifier.
    /// The certificate need not share an ID/label with the private key.
    pub fn eddsa_certificate(
        &self,
        uri: Pkcs11Uri,
        authentication: Authentication<'_>,
    ) -> Result<EdDsaCertificate, Error> {
        let reference = CertificateRef::new(uri)?;
        let der = reference.der(self.pool().try_acquire(authentication)?.session())?;
        EdDsaCertificate::from_der(der)
    }
    /// Prove a key/certificate association with one domain-separated
    /// original-message signature and software verification. Mismatches
    /// discard the lease; no signature, binding or login is automatically retried.
    pub fn bind_eddsa_identity(
        &self,
        key: PrivateKeyRef,
        certificate: EdDsaCertificate,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<EdDsaIdentity, Error> {
        let request = EdDsaRequest {
            curve: certificate.curve(),
            message: b"pkcs11-client EdDSA identity binding v1\0",
        };
        let mut lease = self.pool().try_acquire(authentication)?;
        if lease.session().eddsa_capabilities(&key)?.curve != certificate.curve() {
            return Err(Error::KeyCertificateMismatch);
        }
        let signature = lease.session().sign_eddsa(&key, &request, context_pin)?;
        if let Err(error) = certificate.verify_binding(&request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(EdDsaIdentity { key, certificate })
    }
    /// Sign once and verify in software against the retained certificate before
    /// releasing output. Detects replacement keys even with identical selectors
    /// and curve. Unsupported requests fail before checkout/authentication;
    /// verification failures discard the lease. No automatic retry occurs.
    pub fn sign_eddsa_identity(
        &self,
        identity: &EdDsaIdentity,
        request: &EdDsaRequest<'_>,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        identity.certificate.validate_signing_request(request)?;
        let mut lease = self.pool().try_acquire(authentication)?;
        let signature = lease
            .session()
            .sign_eddsa(&identity.key, request, context_pin)?;
        if let Err(error) = identity.certificate.verify_binding(request, &signature) {
            lease.discard();
            return Err(error);
        }
        Ok(signature)
    }
}
