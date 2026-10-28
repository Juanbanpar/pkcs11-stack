// SPDX-License-Identifier: MIT OR Apache-2.0
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
/// Validated rsaEncryption or named-curve EC SubjectPublicKeyInfo.
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
    /// Parse one canonical SPKI DER document, at most 4096 bytes. Supports RSA
    /// 2048..=16384 bits and P-256/384/521. Rejects restricted RSA-PSS keys,
    /// unsupported curves, invalid components/points and trailing bytes.
    /// Missing rsaEncryption NULL parameters are accepted and normalized to NULL;
    /// EC points are normalized to uncompressed SEC1 before storage/export.
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
        // The export encoder also validates RSA modulus/exponent constraints and
        // named-curve point/parameter consistency using the established libraries.
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
        }
        Ok(template)
    }
}
impl ManagementSession<'_> {
    /// Create one persistent public RSA/EC object with explicit purpose. Requires
    /// RW access. Public-key ID collisions are rejected before creation; an
    /// existing private key/certificate with this ID is neither changed nor bound.
    /// Concurrent writers can still race. Uses 2.40 component attributes, without
    /// CKA_PUBLIC_KEY_INFO or private/secret import. No retry/rollback occurs;
    /// provider errors may leave an object. Check session closure after the call.
    pub fn import_classical_public_key(
        &mut self,
        request: &PublicKeyImportRequest<'_>,
    ) -> Result<(), Error> {
        let template = request.template()?;
        if !self.session.info()?.read_write() {
            return Err(pkcs11_runtime::Error::ReadWriteRequired.into());
        }
        if !self
            .session
            .find_objects(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Token(true),
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
    use x509_cert::der::asn1::{Any, BitString, UintRef};
    fn spki(name: &str) -> Vec<u8> {
        crate::Certificate::from_der(
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("tests/fixtures/{name}.der")),
            )
            .unwrap(),
        )
        .unwrap()
        .spki_der()
        .to_vec()
    }
    #[test]
    fn valid_keys_and_purpose_templates_use_only_public_component_attributes() {
        for name in ["rsa", "p256", "p384", "p521"] {
            let bytes = spki(name);
            let key = ClassicalPublicKey::from_spki_der(&bytes).unwrap();
            assert_eq!(key.spki_der(), bytes);
            let request = PublicKeyImportRequest {
                key: &key,
                purpose: ClassicalPublicKeyPurpose::Verification,
                id: b"id-canary",
                label: b"label-canary",
            };
            let template = request.template().unwrap();
            for attr in [
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Verify(true),
                Attribute::Encrypt(false),
                Attribute::VerifyRecover(false),
                Attribute::Wrap(false),
                Attribute::Derive(false),
                Attribute::Trusted(false),
            ] {
                assert!(template.contains(&attr));
            }
            assert!(!template.iter().any(|attr| matches!(
                attr,
                Attribute::Value(_)
                    | Attribute::ModulusBits(_)
                    | Attribute::Sign(_)
                    | Attribute::Decrypt(_)
            )));
            assert!(!format!("{request:?}").contains("canary"));
            let encryption = PublicKeyImportRequest {
                purpose: ClassicalPublicKeyPurpose::Encryption,
                ..request
            };
            if name == "rsa" {
                let template = encryption.template().unwrap();
                assert!(template.contains(&Attribute::Encrypt(true)));
                assert!(template.contains(&Attribute::Verify(false)));
            } else {
                assert!(encryption.validate().is_err());
            }
            for value in [b"".as_slice(), &[0; 129]] {
                assert!(
                    PublicKeyImportRequest {
                        id: value,
                        ..encryption
                    }
                    .validate()
                    .is_err()
                );
                assert!(
                    PublicKeyImportRequest {
                        label: value,
                        ..encryption
                    }
                    .validate()
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn rejects_invalid_encoding_restricted_algorithms_points_and_rsa_components() {
        assert!(ClassicalPublicKey::from_spki_der(&[0; 4097]).is_err());
        for name in ["rsa", "p256", "p384", "p521"] {
            let mut bytes = spki(name);
            bytes.push(0);
            assert!(ClassicalPublicKey::from_spki_der(&bytes).is_err());
            assert!(ClassicalPublicKey::from_spki_der(&bytes[..bytes.len() / 2]).is_err());
        }
        let mut rsa = SubjectPublicKeyInfoOwned::from_der(&spki("rsa")).unwrap();
        rsa.algorithm.oid = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1");
        assert!(matches!(
            ClassicalPublicKey::from_spki_der(&rsa.to_der().unwrap()),
            Err(Error::InvalidPublicKey)
        ));
        rsa.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        assert!(ClassicalPublicKey::from_spki_der(&rsa.to_der().unwrap()).is_err());
        rsa.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        rsa.algorithm.parameters = Some(Any::from_der(&[0x02, 0x01, 0x03]).unwrap());
        assert!(ClassicalPublicKey::from_spki_der(&rsa.to_der().unwrap()).is_err());
        for (bytes, exponent) in [(128, 3u8), (2049, 3), (256, 2), (256, 1)] {
            let mut modulus = vec![0xFF; bytes];
            modulus[0] = 0x80;
            let exponent = [exponent];
            let public = rsa::pkcs1::RsaPublicKey {
                modulus: UintRef::new(&modulus).unwrap(),
                public_exponent: UintRef::new(&exponent).unwrap(),
            };
            rsa.algorithm.parameters = None;
            rsa.subject_public_key = BitString::from_bytes(&public.to_der().unwrap()).unwrap();
            assert!(ClassicalPublicKey::from_spki_der(&rsa.to_der().unwrap()).is_err());
        }
        for name in ["p256", "p384", "p521"] {
            let mut ec = SubjectPublicKeyInfoOwned::from_der(&spki(name)).unwrap();
            ec.subject_public_key = BitString::from_bytes(&[4; 65]).unwrap();
            assert!(ClassicalPublicKey::from_spki_der(&ec.to_der().unwrap()).is_err());
            ec.algorithm.parameters = Some(
                Any::from_der(
                    &ObjectIdentifier::new_unwrap("1.3.132.0.10")
                        .to_der()
                        .unwrap(),
                )
                .unwrap(),
            );
            assert!(ClassicalPublicKey::from_spki_der(&ec.to_der().unwrap()).is_err());
        }
    }
    #[test]
    fn normalizes_absent_rsa_null_parameters_and_compressed_ec_points() {
        let bytes = spki("rsa");
        let mut rsa = SubjectPublicKeyInfoOwned::from_der(&bytes).unwrap();
        rsa.algorithm.parameters = None;
        assert_eq!(
            ClassicalPublicKey::from_spki_der(&rsa.to_der().unwrap())
                .unwrap()
                .spki_der(),
            bytes
        );
        let bytes = spki("p256");
        let mut ec = SubjectPublicKeyInfoOwned::from_der(&bytes).unwrap();
        let point =
            p256::PublicKey::from_sec1_bytes(ec.subject_public_key.as_bytes().unwrap()).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        ec.subject_public_key =
            BitString::from_bytes(point.to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(
            ClassicalPublicKey::from_spki_der(&ec.to_der().unwrap())
                .unwrap()
                .spki_der(),
            bytes
        );
    }
}
