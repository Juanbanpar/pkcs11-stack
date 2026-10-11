// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    DigestAlgorithm, Error, KeyKind, NamedCurve, SignInput, SignRequest, SignatureAlgorithm,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::der::{
    Decode, Encode,
    asn1::{Null, ObjectIdentifier},
};

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
    fn parse(der: Vec<u8>) -> Result<(Self, x509_cert::Certificate), Error> {
        let parsed =
            x509_cert::Certificate::from_der(&der).map_err(|_| Error::InvalidCertificate)?;
        let tbs = &parsed.tbs_certificate;
        let document = Self {
            spki: tbs
                .subject_public_key_info
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            subject: tbs
                .subject
                .to_der()
                .map_err(|_| Error::InvalidCertificate)?,
            issuer: tbs.issuer.to_der().map_err(|_| Error::InvalidCertificate)?,
            serial: tbs
                .serial_number
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

enum VerificationKey {
    Rsa(Box<RsaPublicKey>),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

/// Parsed X.509 certificate and validated public key, without a trust decision.
///
/// Parsing does not verify the issuer signature, chain, validity dates, key usage,
/// revocation or hostname. Applications must apply their own certificate policy.
pub struct Certificate {
    document: CertificateDocument,
    key: VerificationKey,
}
impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("key", &self.key_kind())
            .finish_non_exhaustive()
    }
}
impl Certificate {
    /// Parse exactly one DER certificate; reject trailing bytes and unsupported keys.
    ///
    /// Supports rsaEncryption keys up to 16384 bits and named P-256/P-384/P-521.
    /// RSASSA-PSS-restricted certificate keys are rejected rather than losing their
    /// algorithm restrictions. PEM and certificate bundles are not accepted.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let (document, certificate) = CertificateDocument::parse(der)?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidCertificate)?;
        let algorithm = &spki.algorithm;
        let key = match algorithm.oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => {
                if algorithm
                    .parameters
                    .as_ref()
                    .is_some_and(|p| p.decode_as::<Null>().is_err())
                {
                    return Err(Error::InvalidCertificate);
                }
                let public = rsa::pkcs1::RsaPublicKey::from_der(bytes)
                    .map_err(|_| Error::InvalidCertificate)?;
                let key = RsaPublicKey::new_with_max_size(
                    BigUint::from_bytes_be(public.modulus.as_bytes()),
                    BigUint::from_bytes_be(public.public_exponent.as_bytes()),
                    16384,
                )
                .map_err(|_| Error::InvalidCertificate)?;
                VerificationKey::Rsa(Box::new(key))
            }
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
                let curve = algorithm
                    .parameters
                    .as_ref()
                    .ok_or(Error::UnsupportedCertificateKey)?
                    .decode_as::<ObjectIdentifier>()
                    .map_err(|_| Error::UnsupportedCertificateKey)?;
                match curve {
                    oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7") => {
                        VerificationKey::P256(
                            p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                                .map_err(|_| Error::InvalidCertificate)?,
                        )
                    }
                    oid if oid == ObjectIdentifier::new_unwrap("1.3.132.0.34") => {
                        VerificationKey::P384(
                            p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                                .map_err(|_| Error::InvalidCertificate)?,
                        )
                    }
                    oid if oid == ObjectIdentifier::new_unwrap("1.3.132.0.35") => {
                        VerificationKey::P521(
                            p521::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                                .map_err(|_| Error::InvalidCertificate)?,
                        )
                    }
                    _ => return Err(Error::UnsupportedCertificateKey),
                }
            }
            _ => return Err(Error::UnsupportedCertificateKey),
        };
        Ok(Self { document, key })
    }
    /// Public DER metadata, without an issuer/chain trust decision.
    pub fn document(&self) -> &CertificateDocument {
        &self.document
    }
    /// Original DER certificate bytes. No certificate trust is implied.
    pub fn der(&self) -> &[u8] {
        self.document.der()
    }
    /// DER SubjectPublicKeyInfo extracted from this certificate.
    pub fn spki_der(&self) -> &[u8] {
        self.document.spki_der()
    }
    /// Public-key type and size/curve from the actual certificate key.
    pub fn key_kind(&self) -> KeyKind {
        match &self.key {
            VerificationKey::Rsa(key) => KeyKind::Rsa {
                bits: key.n().bits(),
            },
            VerificationKey::P256(_) => KeyKind::Ec(NamedCurve::P256),
            VerificationKey::P384(_) => KeyKind::Ec(NamedCurve::P384),
            VerificationKey::P521(_) => KeyKind::Ec(NamedCurve::P521),
        }
    }
    /// Check whether this certificate can verify the request before performing a binding probe.
    /// This checks algorithm/parameter compatibility and digest length, not token
    /// capability, signing policy, certificate trust or a signature itself.
    pub fn validate_signing_request(&self, request: &SignRequest<'_>) -> Result<(), Error> {
        match (self.key_kind(), request.algorithm, request.pss) {
            (KeyKind::Rsa { .. }, SignatureAlgorithm::RsaPkcs1, None)
            | (KeyKind::Ec(_), SignatureAlgorithm::Ecdsa, None) => {}
            (KeyKind::Rsa { .. }, SignatureAlgorithm::RsaPss, Some(pss))
                if pss.mgf_digest == request.digest => {}
            _ => return Err(Error::UnsupportedVerification),
        }
        if let SignInput::Digest(bytes) = request.input {
            if bytes.len() != request.digest.output_len() {
                return Err(Error::UnsupportedVerification);
            }
        }
        Ok(())
    }
    pub(crate) fn verify(&self, request: &SignRequest<'_>, signature: &[u8]) -> Result<(), Error> {
        self.validate_signing_request(request)?;
        let hash = match request.input {
            SignInput::Message(bytes) => match request.digest {
                DigestAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
                DigestAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
                DigestAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
            },
            SignInput::Digest(bytes) => bytes.to_vec(),
        };
        let mismatch = |_| Error::KeyCertificateMismatch;
        match &self.key {
            VerificationKey::Rsa(key) => {
                if let Some(pss) = request.pss {
                    let scheme = match request.digest {
                        DigestAlgorithm::Sha256 => Pss::new_with_salt::<Sha256>(pss.salt_len),
                        DigestAlgorithm::Sha384 => Pss::new_with_salt::<Sha384>(pss.salt_len),
                        DigestAlgorithm::Sha512 => Pss::new_with_salt::<Sha512>(pss.salt_len),
                    };
                    key.verify(scheme, &hash, signature).map_err(mismatch)
                } else {
                    let scheme = match request.digest {
                        DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                        DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                        DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                    };
                    key.verify(scheme, &hash, signature).map_err(mismatch)
                }
            }
            VerificationKey::P256(key) => key
                .verify_prehash(
                    &hash,
                    &p256::ecdsa::Signature::from_slice(signature)
                        .map_err(|_| Error::KeyCertificateMismatch)?,
                )
                .map_err(|_| Error::KeyCertificateMismatch),
            VerificationKey::P384(key) => key
                .verify_prehash(
                    &hash,
                    &p384::ecdsa::Signature::from_slice(signature)
                        .map_err(|_| Error::KeyCertificateMismatch)?,
                )
                .map_err(|_| Error::KeyCertificateMismatch),
            VerificationKey::P521(key) => {
                // ECDSA interprets a shorter digest as an unsigned integer. Pad
                // on the left to satisfy RustCrypto's half-field input minimum,
                // including SHA-256 with P-521, without changing that integer.
                let mut padded = [0; 66];
                padded[66 - hash.len()..].copy_from_slice(&hash);
                key.verify_prehash(
                    &padded,
                    &p521::ecdsa::Signature::from_slice(signature)
                        .map_err(|_| Error::KeyCertificateMismatch)?,
                )
                .map_err(|_| Error::KeyCertificateMismatch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PssParameters;

    const MESSAGE: &[u8] = include_bytes!("../tests/fixtures/message.txt");
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn independent_openssl_signatures() {
        for key in ["rsa", "p256", "p384", "p521"] {
            let certificate = Certificate::from_der(fixture(&format!("{key}.der"))).unwrap();
            assert!(!certificate.spki_der().is_empty());
            for (name, digest) in [
                ("sha256", DigestAlgorithm::Sha256),
                ("sha384", DigestAlgorithm::Sha384),
                ("sha512", DigestAlgorithm::Sha512),
            ] {
                let hash = match digest {
                    DigestAlgorithm::Sha256 => Sha256::digest(MESSAGE).to_vec(),
                    DigestAlgorithm::Sha384 => Sha384::digest(MESSAGE).to_vec(),
                    DigestAlgorithm::Sha512 => Sha512::digest(MESSAGE).to_vec(),
                };
                let encoded = fixture(&format!("{key}-{name}.sig"));
                let signature = match key {
                    "p256" => p256::ecdsa::Signature::from_der(&encoded)
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                    "p384" => p384::ecdsa::Signature::from_der(&encoded)
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                    "p521" => p521::ecdsa::Signature::from_der(&encoded)
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                    _ => encoded,
                };
                for input in [SignInput::Message(MESSAGE), SignInput::Digest(&hash)] {
                    let request = SignRequest {
                        algorithm: if key == "rsa" {
                            SignatureAlgorithm::RsaPkcs1
                        } else {
                            SignatureAlgorithm::Ecdsa
                        },
                        digest,
                        input,
                        pss: None,
                    };
                    certificate.verify(&request, &signature).unwrap();
                    let mut bad = signature.clone();
                    bad[0] ^= 1;
                    assert!(matches!(
                        certificate.verify(&request, &bad),
                        Err(Error::KeyCertificateMismatch)
                    ));
                    assert!(certificate.verify(&request, &[]).is_err());
                    let changed = SignRequest {
                        input: SignInput::Message(b"changed message"),
                        ..request
                    };
                    assert!(certificate.verify(&changed, &signature).is_err());
                    if key == "rsa" {
                        let request = SignRequest {
                            algorithm: SignatureAlgorithm::RsaPss,
                            pss: Some(PssParameters {
                                mgf_digest: digest,
                                salt_len: 20,
                            }),
                            ..request
                        };
                        let signature = fixture(&format!("rsa-pss-{name}.sig"));
                        certificate.verify(&request, &signature).unwrap();
                        let bad_salt = SignRequest {
                            pss: Some(PssParameters {
                                mgf_digest: digest,
                                salt_len: 21,
                            }),
                            ..request
                        };
                        assert!(certificate.verify(&bad_salt, &signature).is_err());
                    }
                }
            }
        }
    }
    #[test]
    fn certificate_documents_preserve_metadata_for_unsupported_keys() {
        let der = fixture("ed25519.der");
        let parsed = x509_cert::Certificate::from_der(&der).unwrap();
        let document = CertificateDocument::from_der(der.clone()).unwrap();
        assert_eq!(document.der(), der);
        assert_eq!(
            document.subject_der(),
            parsed.tbs_certificate.subject.to_der().unwrap()
        );
        assert_eq!(
            document.issuer_der(),
            parsed.tbs_certificate.issuer.to_der().unwrap()
        );
        assert_eq!(
            document.serial_der(),
            parsed.tbs_certificate.serial_number.to_der().unwrap()
        );
        assert_eq!(
            document.spki_der(),
            parsed
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap()
        );
        assert!(matches!(
            Certificate::from_der(der.clone()),
            Err(Error::UnsupportedCertificateKey)
        ));
        let mut trailing = der;
        trailing.push(0);
        assert!(CertificateDocument::from_der(trailing).is_err());
        assert!(!format!("{document:?}").contains("ed25519"));
    }
    #[test]
    fn strict_certificate_parsing() {
        assert!(matches!(
            Certificate::from_der(vec![1, 2, 3]),
            Err(Error::InvalidCertificate)
        ));
        let mut trailing = fixture("rsa.der");
        trailing.push(0);
        assert!(matches!(
            Certificate::from_der(trailing),
            Err(Error::InvalidCertificate)
        ));
        assert!(matches!(
            Certificate::from_der(fixture("ed25519.der")),
            Err(Error::UnsupportedCertificateKey)
        ));
        let mut cert = x509_cert::Certificate::from_der(&fixture("rsa.der")).unwrap();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        assert!(matches!(
            Certificate::from_der(cert.to_der().unwrap()),
            Err(Error::UnsupportedCertificateKey)
        ));
        let mut cert = x509_cert::Certificate::from_der(&fixture("p256.der")).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key = x509_cert::der::asn1::BitString::from_bytes(&[4; 65]).unwrap();
        assert!(matches!(
            Certificate::from_der(cert.to_der().unwrap()),
            Err(Error::InvalidCertificate)
        ));
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = None;
        assert!(matches!(
            Certificate::from_der(cert.to_der().unwrap()),
            Err(Error::UnsupportedCertificateKey)
        ));
    }
    #[test]
    fn verification_rejects_unsupported_requests() {
        let certificate = Certificate::from_der(fixture("rsa.der")).unwrap();
        let request = SignRequest {
            algorithm: SignatureAlgorithm::RsaPss,
            digest: DigestAlgorithm::Sha256,
            input: SignInput::Message(MESSAGE),
            pss: Some(PssParameters {
                mgf_digest: DigestAlgorithm::Sha384,
                salt_len: 20,
            }),
        };
        assert!(matches!(
            certificate.validate_signing_request(&request),
            Err(Error::UnsupportedVerification)
        ));
        let request = SignRequest {
            algorithm: SignatureAlgorithm::RsaPkcs1,
            pss: None,
            input: SignInput::Digest(&[0; 31]),
            ..request
        };
        assert!(matches!(
            certificate.validate_signing_request(&request),
            Err(Error::UnsupportedVerification)
        ));
        let request = SignRequest {
            algorithm: SignatureAlgorithm::Ecdsa,
            input: SignInput::Message(MESSAGE),
            ..request
        };
        assert!(matches!(
            certificate.validate_signing_request(&request),
            Err(Error::UnsupportedVerification)
        ));
        assert!(!format!("{certificate:?}").contains("pkcs11-client-rsa-fixture"));
    }
}
