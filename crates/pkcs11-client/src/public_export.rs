// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, KeyKind, NamedCurve, PublicKeyMetadata};
use rsa::{BigUint, RsaPublicKey, pkcs8::EncodePublicKey};
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{Any, BitString, ObjectIdentifier, OctetString},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

pub(crate) fn encode_public_key(metadata: PublicKeyMetadata) -> Result<Vec<u8>, Error> {
    let invalid = || Error::InvalidPublicKey;
    match metadata.key {
        KeyKind::Rsa { .. } => {
            let modulus = metadata.modulus.ok_or_else(invalid)?;
            let exponent = metadata.public_exponent.ok_or_else(invalid)?;
            let key = RsaPublicKey::new_with_max_size(
                BigUint::from_bytes_be(&modulus),
                BigUint::from_bytes_be(&exponent),
                16384,
            )
            .map_err(|_| invalid())?;
            Ok(key
                .to_public_key_der()
                .map_err(|_| invalid())?
                .as_bytes()
                .to_vec())
        }
        KeyKind::Ec(curve) => {
            let params = metadata.ec_params.ok_or_else(invalid)?;
            let point = metadata.ec_point.ok_or_else(invalid)?;
            let point = OctetString::from_der(&point).map_err(|_| invalid())?;
            let bytes = point.as_bytes();
            let valid = match curve {
                NamedCurve::P256 => p256::PublicKey::from_sec1_bytes(bytes).is_ok(),
                NamedCurve::P384 => p384::PublicKey::from_sec1_bytes(bytes).is_ok(),
                NamedCurve::P521 => p521::PublicKey::from_sec1_bytes(bytes).is_ok(),
            };
            let oid = ObjectIdentifier::from_der(&params).map_err(|_| invalid())?;
            let expected = match curve {
                NamedCurve::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
                NamedCurve::P384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),
                NamedCurve::P521 => ObjectIdentifier::new_unwrap("1.3.132.0.35"),
            };
            if !valid || oid != expected {
                return Err(invalid());
            }
            SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                    parameters: Some(Any::from_der(&params).map_err(|_| invalid())?),
                },
                subject_public_key: BitString::from_bytes(bytes).map_err(|_| invalid())?,
            }
            .to_der()
            .map_err(|_| invalid())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn export_matches_independent_certificate_spki_and_rejects_invalid_points() {
        for name in ["rsa", "p256", "p384", "p521"] {
            let der = fixture(&format!("{name}.der"));
            let certificate = crate::Certificate::from_der(der.clone()).unwrap();
            let parsed = x509_cert::Certificate::from_der(&der).unwrap();
            let spki = parsed.tbs_certificate.subject_public_key_info;
            let mut metadata = PublicKeyMetadata {
                key: certificate.key_kind(),
                spki: Some(b"untrusted-spki".to_vec()),
                modulus: None,
                public_exponent: None,
                ec_params: None,
                ec_point: None,
            };
            match metadata.key {
                KeyKind::Rsa { .. } => {
                    let key = RsaPublicKey::from_public_key_der(certificate.spki_der()).unwrap();
                    metadata.modulus = Some(key.n().to_bytes_be());
                    metadata.public_exponent = Some(key.e().to_bytes_be());
                }
                KeyKind::Ec(_) => {
                    metadata.ec_params = Some(spki.algorithm.parameters.unwrap().to_der().unwrap());
                    metadata.ec_point = Some(
                        OctetString::new(spki.subject_public_key.as_bytes().unwrap().to_vec())
                            .unwrap()
                            .to_der()
                            .unwrap(),
                    );
                }
            }
            assert_eq!(
                encode_public_key(metadata.clone()).unwrap(),
                certificate.spki_der()
            );
            metadata.public_exponent = None;
            metadata.ec_point = Some(OctetString::new(vec![4; 65]).unwrap().to_der().unwrap());
            assert!(matches!(
                encode_public_key(metadata),
                Err(Error::InvalidPublicKey)
            ));
        }
    }
}
