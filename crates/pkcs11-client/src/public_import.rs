// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Validated import of RSA and named-curve EC public keys.

use crate::{
    Attribute, EcdhPeer, Error, KeyKind, KeyType, ManagementSession, ObjectClass, PublicKeyMetadata,
};
use rsa::BigUint;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{Null, ObjectIdentifier, OctetString},
    },
    spki::SubjectPublicKeyInfoOwned,
};

/// Mutually exclusive permissions for a newly imported public key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClassicalPublicKeyPurpose {
    /// RSA or EC signature verification only.
    #[default]
    Verification,
    /// RSA encryption only; EC keys are rejected before creation.
    Encryption,
}

/// Validated `rsaEncryption` or named-curve EC SubjectPublicKeyInfo.
///
/// Parsing validates encoding and key components, not identity, provenance,
/// private-key possession or association with objects sharing an ID.
#[derive(Clone)]
pub struct ClassicalPublicKey {
    metadata: PublicKeyMetadata,
    spki: Vec<u8>,
}

impl std::fmt::Debug for ClassicalPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassicalPublicKey")
            .field("key", &self.key_kind())
            .finish_non_exhaustive()
    }
}

impl ClassicalPublicKey {
    /// Parse one canonical SPKI DER document, at most 4096 bytes.
    ///
    /// Supports RSA 2048..=16384 bits and P-256/384/521. Restricted RSA-PSS
    /// keys, unsupported curves, invalid components/points and trailing bytes
    /// are rejected. Missing rsaEncryption NULL parameters are accepted and
    /// normalized to NULL; EC points are normalized to uncompressed SEC1.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::InvalidPublicKey);
        }
        let spki =
            SubjectPublicKeyInfoOwned::from_der(bytes).map_err(|_| Error::InvalidPublicKey)?;
        if spki.to_der().map_err(|_| Error::InvalidPublicKey)? != bytes {
            return Err(Error::InvalidPublicKey);
        }
        let encoded = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidPublicKey)?;
        let mut metadata = PublicKeyMetadata {
            key: KeyKind::Rsa { bits: 0 },
            spki: None,
            modulus: None,
            public_exponent: None,
            ec_params: None,
            ec_point: None,
        };
        match spki.algorithm.oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => {
                if spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .is_some_and(|p| p.decode_as::<Null>().is_err())
                {
                    return Err(Error::InvalidPublicKey);
                }
                let public = rsa::pkcs1::RsaPublicKey::from_der(encoded)
                    .map_err(|_| Error::InvalidPublicKey)?;
                let bits = BigUint::from_bytes_be(public.modulus.as_bytes()).bits();
                if !(2048..=16384).contains(&bits) {
                    return Err(Error::InvalidPublicKey);
                }
                metadata.key = KeyKind::Rsa { bits };
                metadata.modulus = Some(public.modulus.as_bytes().to_vec());
                metadata.public_exponent = Some(public.public_exponent.as_bytes().to_vec());
            }
            oid if oid == ObjectIdentifier::new_unwrap("1.3.101.112")
                || oid == ObjectIdentifier::new_unwrap("1.3.101.113") =>
            {
                let key = crate::EdDsaVerifyingKey::from_spki_der(bytes)?;
                metadata.key = KeyKind::Edwards(key.curve());
                metadata.ec_params = Some(key.curve().ec_params().to_vec());
                metadata.ec_point = Some(
                    OctetString::new(key.as_bytes().to_vec())
                        .map_err(|_| Error::InvalidPublicKey)?
                        .to_der()
                        .map_err(|_| Error::InvalidPublicKey)?,
                );
            }
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
                let peer = EcdhPeer::from_spki_der(bytes)?;
                metadata.key = KeyKind::Ec(peer.curve());
                metadata.ec_params = Some(
                    spki.algorithm
                        .parameters
                        .ok_or(Error::InvalidPublicKey)?
                        .to_der()
                        .map_err(|_| Error::InvalidPublicKey)?,
                );
                metadata.ec_point = Some(
                    OctetString::new(peer.point().to_vec())
                        .map_err(|_| Error::InvalidPublicKey)?
                        .to_der()
                        .map_err(|_| Error::InvalidPublicKey)?,
                );
            }
            _ => return Err(Error::InvalidPublicKey),
        }
        let spki = crate::public_export::encode_public_key(metadata.clone())?;
        Ok(Self { metadata, spki })
    }

    /// Actual modulus size or named curve after validation.
    pub fn key_kind(&self) -> KeyKind {
        self.metadata.key
    }

    /// Canonical public SPKI with normalized parameters/point representation.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }
}

/// Bounded identity and explicit purpose for one public-key import.
pub struct PublicKeyImportRequest<'a> {
    /// Validated RSA or named EC public key; no private components are accepted.
    pub key: &'a ClassicalPublicKey,
    /// Verification, or RSA encryption. No wrapping, recovery or derivation.
    pub purpose: ClassicalPublicKeyPurpose,
    /// New nonempty public-key CKA_ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}

impl std::fmt::Debug for PublicKeyImportRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyImportRequest")
            .field("key", &self.key.key_kind())
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

impl PublicKeyImportRequest<'_> {
    /// Check identity and purpose before accessing a provider.
    pub fn validate(&self) -> Result<(), Error> {
        if self.id.is_empty()
            || self.id.len() > 128
            || self.label.is_empty()
            || self.label.len() > 128
        {
            return Err(pkcs11_runtime::Error::InvalidParameters("public key identity").into());
        }
        if self.purpose == ClassicalPublicKeyPurpose::Encryption
            && !matches!(self.key.key_kind(), KeyKind::Rsa { .. })
        {
            return Err(pkcs11_runtime::Error::InvalidParameters(
                "encryption purpose requires RSA",
            )
            .into());
        }
        Ok(())
    }

    fn template(&self) -> Result<Vec<Attribute>, Error> {
        self.validate()?;
        let mut template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(self.id.to_vec()),
            Attribute::Label(self.label.to_vec()),
            Attribute::Verify(self.purpose == ClassicalPublicKeyPurpose::Verification),
            Attribute::Encrypt(self.purpose == ClassicalPublicKeyPurpose::Encryption),
            Attribute::VerifyRecover(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::Trusted(false),
        ];
        let metadata = &self.key.metadata;
        match metadata.key {
            KeyKind::Rsa { .. } => template.extend([
                Attribute::KeyType(KeyType::RSA),
                Attribute::Modulus(metadata.modulus.clone().ok_or(Error::InvalidPublicKey)?),
                Attribute::PublicExponent(
                    metadata
                        .public_exponent
                        .clone()
                        .ok_or(Error::InvalidPublicKey)?,
                ),
            ]),
            KeyKind::Ec(_) => template.extend([
                Attribute::KeyType(KeyType::EC),
                Attribute::EcParams(metadata.ec_params.clone().ok_or(Error::InvalidPublicKey)?),
                Attribute::EcPoint(metadata.ec_point.clone().ok_or(Error::InvalidPublicKey)?),
            ]),
            KeyKind::Edwards(_) => template.extend([
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::EcParams(metadata.ec_params.clone().ok_or(Error::InvalidPublicKey)?),
                Attribute::EcPoint(metadata.ec_point.clone().ok_or(Error::InvalidPublicKey)?),
                Attribute::AllowedMechanisms(vec![crate::MechanismType::EDDSA]),
            ]),
        }
        Ok(template)
    }
}

impl ManagementSession<'_> {
    /// Create one persistent public RSA/EC object with explicit purpose.
    ///
    /// Requires RW access. Public-key ID collisions are rejected before
    /// creation; an existing private key/certificate with this ID is neither
    /// changed nor bound. Concurrent writers can still race. No private or
    /// secret material is accepted. No retry or rollback occurs.
    pub fn import_public_key(&mut self, request: &PublicKeyImportRequest<'_>) -> Result<(), Error> {
        let template = request.template()?;
        if !self
            .session
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Id(request.id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(
                pkcs11_runtime::Error::InvalidParameters("public key ID already exists").into(),
            );
        }
        self.session.create_object(&template)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::Certificate;

    fn spki(fixture: &[u8]) -> Vec<u8> {
        Certificate::from_der(fixture)
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap()
    }

    #[test]
    fn rsa_and_named_ec_spki_roundtrip_and_reject_invalid_purposes() {
        for (fixture, expected) in [
            (include_bytes!("../tests/fixtures/rsa.der").as_slice(), None),
            (
                include_bytes!("../tests/fixtures/p256.der").as_slice(),
                Some(crate::NamedCurve::P256),
            ),
            (
                include_bytes!("../tests/fixtures/p384.der").as_slice(),
                Some(crate::NamedCurve::P384),
            ),
            (
                include_bytes!("../tests/fixtures/p521.der").as_slice(),
                Some(crate::NamedCurve::P521),
            ),
        ] {
            let der = spki(fixture);
            let key = ClassicalPublicKey::from_spki_der(&der).unwrap();
            assert_eq!(key.spki_der(), der);
            match expected {
                Some(curve) => assert_eq!(key.key_kind(), KeyKind::Ec(curve)),
                None => assert!(matches!(key.key_kind(), KeyKind::Rsa { bits } if bits >= 2048)),
            }
            let request = PublicKeyImportRequest {
                key: &key,
                purpose: ClassicalPublicKeyPurpose::Encryption,
                id: b"id",
                label: b"label",
            };
            if expected.is_some() {
                assert!(request.validate().is_err());
            } else {
                request.validate().unwrap();
            }
        }
        let der = spki(include_bytes!("../tests/fixtures/rsa.der"));
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(ClassicalPublicKey::from_spki_der(&trailing).is_err());
        assert!(ClassicalPublicKey::from_spki_der(&[]).is_err());
    }
}
