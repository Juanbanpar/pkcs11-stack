// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use x509_cert::der::{Decode, Encode};

/// Exact X.509 DER and public metadata, independent of supported signing algorithms.
/// Parsing alone does not validate certificate trust or the subject public key.
/// Useful for importing certificates whose key algorithm cannot be used by this client.
pub struct CertificateDocument {
    der: Vec<u8>,
    spki: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}
impl std::fmt::Debug for CertificateDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertificateDocument { contents: [REDACTED] }")
    }
}
impl CertificateDocument {
    pub(super) fn parse(der: Vec<u8>) -> Result<(Self, x509_cert::Certificate), Error> {
        let parsed =
            x509_cert::Certificate::from_der(&der).map_err(|_| Error::InvalidCertificate)?;
        let tbs = parsed.tbs_certificate();
        let document = Self {
            spki: tbs
                .subject_public_key_info()
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            subject: tbs
                .subject()
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            issuer: tbs
                .issuer()
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            serial: tbs
                .serial_number()
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            der,
        };
        Ok((document, parsed))
    }
    /// Parse one exact DER X.509 certificate, including unsupported key algorithms.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        Ok(Self::parse(der)?.0)
    }
    /// Original certificate DER.
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    /// SubjectPublicKeyInfo DER; no public-key validity or support check is implied.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }
    /// Subject Name DER, suitable for CKA_SUBJECT.
    pub fn subject_der(&self) -> &[u8] {
        &self.subject
    }
    /// Issuer Name DER, suitable for CKA_ISSUER.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer
    }
    /// Serial number DER INTEGER, suitable for CKA_SERIAL_NUMBER.
    pub fn serial_der(&self) -> &[u8] {
        &self.serial
    }
}

pub(super) fn parse_with_verifier<T>(
    der: Vec<u8>,
    parse_key: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> Result<(CertificateDocument, T), Error> {
    let document = CertificateDocument::from_der(der)?;
    let key = parse_key(document.spki_der()).map_err(|error| match error {
        Error::InvalidPublicKey => Error::InvalidCertificate,
        other => other,
    })?;
    Ok((document, key))
}
