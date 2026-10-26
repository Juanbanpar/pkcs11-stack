// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider-free verification against independent OpenSSL fixtures.
use pkcs11_client::{
    Error, MlDsaCertificate, MlDsaHedging, MlDsaParameterSet, MlDsaRequest, MlDsaVerifyingKey,
};
use std::path::Path;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{Any, BitString, ObjectIdentifier},
    },
    spki::SubjectPublicKeyInfoOwned,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}
const PARAMETERS: [(MlDsaParameterSet, &str); 3] = [
    (MlDsaParameterSet::MlDsa44, "mldsa44"),
    (MlDsaParameterSet::MlDsa65, "mldsa65"),
    (MlDsaParameterSet::MlDsa87, "mldsa87"),
];

#[test]
fn software_verification_checks_message_context_and_signature_encoding() {
    let message = fixture("message.txt");
    for (parameter, name) in PARAMETERS {
        let der = fixture(&format!("{name}.der"));
        let spki = fixture(&format!("{name}.spki.der"));
        let certificate = MlDsaCertificate::from_der(der.clone()).unwrap();
        let verifier = MlDsaVerifyingKey::from_spki_der(&spki).unwrap();
        assert_eq!(certificate.parameter_set(), parameter);
        assert_eq!(certificate.spki_der(), spki);
        assert_eq!(certificate.der(), der);
        assert_eq!(certificate.document().der(), der);
        let parsed = SubjectPublicKeyInfoOwned::from_der(&spki).unwrap();
        let raw =
            MlDsaVerifyingKey::from_bytes(parameter, parsed.subject_public_key.as_bytes().unwrap())
                .unwrap();
        for (suffix, context) in [
            ("sig", b"".as_slice()),
            ("context.sig", b"fixture-context".as_slice()),
        ] {
            let signature = fixture(&format!("{name}.{suffix}"));
            let request = MlDsaRequest {
                parameter_set: parameter,
                message: &message,
                context,
                hedging: MlDsaHedging::Required,
            };
            for key in [&verifier, &raw, certificate.verifying_key()] {
                key.verify_signature(&request, &signature).unwrap();
                for changed in [
                    MlDsaRequest {
                        message: b"changed",
                        ..request
                    },
                    MlDsaRequest {
                        context: b"wrong",
                        ..request
                    },
                ] {
                    assert!(matches!(
                        key.verify_signature(&changed, &signature),
                        Err(Error::SignatureMismatch)
                    ));
                }
                for length in [0, signature.len() - 1, signature.len() + 1] {
                    assert!(matches!(
                        key.verify_signature(&request, &vec![0; length]),
                        Err(Error::SignatureMismatch)
                    ));
                }
                let mut altered = signature.clone();
                altered[0] ^= 1;
                assert!(matches!(
                    key.verify_signature(&request, &altered),
                    Err(Error::SignatureMismatch)
                ));
            }
            certificate.verify_signature(&request, &signature).unwrap();
            assert!(matches!(
                certificate.verify_signature(
                    &MlDsaRequest {
                        context: &[0; 256],
                        ..request
                    },
                    &signature
                ),
                Err(Error::Runtime(_))
            ));
            let other = if parameter == MlDsaParameterSet::MlDsa44 {
                MlDsaParameterSet::MlDsa65
            } else {
                MlDsaParameterSet::MlDsa44
            };
            assert!(matches!(
                certificate.verify_signature(
                    &MlDsaRequest {
                        parameter_set: other,
                        ..request
                    },
                    &signature
                ),
                Err(Error::UnsupportedVerification)
            ));
        }
    }
}

#[test]
fn spki_and_certificate_parsing_reject_nonstandard_encodings() {
    for (_, name) in PARAMETERS {
        let spki_bytes = fixture(&format!("{name}.spki.der"));
        let mut trailing = spki_bytes.clone();
        trailing.push(0);
        assert!(matches!(
            MlDsaVerifyingKey::from_spki_der(&trailing),
            Err(Error::InvalidPublicKey)
        ));
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_bytes).unwrap();
        let bytes = spki.subject_public_key.as_bytes().unwrap();
        let mut with_null = spki.clone();
        with_null.algorithm.parameters = Some(Any::from_der(&[5, 0]).unwrap());
        let mut truncated = spki.clone();
        truncated.subject_public_key = BitString::from_bytes(&bytes[..bytes.len() - 1]).unwrap();
        let mut unaligned = spki.clone();
        unaligned.subject_public_key = BitString::new(1, vec![0; bytes.len()]).unwrap();
        for bad in [with_null, truncated, unaligned] {
            assert!(matches!(
                MlDsaVerifyingKey::from_spki_der(&bad.to_der().unwrap()),
                Err(Error::InvalidPublicKey)
            ));
            let mut certificate =
                x509_cert::Certificate::from_der(&fixture(&format!("{name}.der"))).unwrap();
            certificate.tbs_certificate.subject_public_key_info = bad;
            assert!(matches!(
                MlDsaCertificate::from_der(certificate.to_der().unwrap()),
                Err(Error::InvalidCertificate)
            ));
        }
        let mut unknown = spki;
        unknown.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        assert!(matches!(
            MlDsaVerifyingKey::from_spki_der(&unknown.to_der().unwrap()),
            Err(Error::UnsupportedCertificateKey)
        ));
        let mut certificate = fixture(&format!("{name}.der"));
        certificate.push(0);
        assert!(matches!(
            MlDsaCertificate::from_der(certificate),
            Err(Error::InvalidCertificate)
        ));
    }
    assert!(matches!(
        MlDsaCertificate::from_der(fixture("rsa.der")),
        Err(Error::UnsupportedCertificateKey)
    ));
}

#[test]
fn repeated_hint_indices_do_not_create_an_alternate_valid_signature() {
    // Duplicate an existing hint without changing the mathematical hint vector.
    // This must fail canonical decoding (GHSA-5x2r-hc65-25f9).
    let message = fixture("message.txt");
    for ((parameter, name), (omega, polynomials)) in
        PARAMETERS.into_iter().zip([(80, 4), (55, 6), (75, 8)])
    {
        let key = MlDsaVerifyingKey::from_spki_der(&fixture(&format!("{name}.spki.der"))).unwrap();
        let request = MlDsaRequest {
            parameter_set: parameter,
            message: &message,
            context: b"",
            hedging: MlDsaHedging::Preferred,
        };
        let mut signature = fixture(&format!("{name}.sig"));
        key.verify_signature(&request, &signature).unwrap();
        let start = signature.len() - omega - polynomials;
        let ends = signature[start + omega..].to_vec();
        let count = usize::from(ends[polynomials - 1]);
        assert!(
            count > 0 && count < omega,
            "fixture needs a spare hint slot"
        );
        let polynomial = ends.iter().position(|&end| end > 0).unwrap();
        signature.copy_within(start..start + count, start + 1);
        for end in &mut signature[start + omega + polynomial..] {
            *end += 1;
        }
        assert!(matches!(
            key.verify_signature(&request, &signature),
            Err(Error::SignatureMismatch)
        ));
    }
}

#[test]
fn parsing_and_message_verification_do_not_assert_issuer_trust() {
    let mut certificate = x509_cert::Certificate::from_der(&fixture("mldsa44.der")).unwrap();
    certificate.signature = BitString::from_bytes(&vec![0; 2420]).unwrap();
    let certificate = MlDsaCertificate::from_der(certificate.to_der().unwrap()).unwrap();
    let request = MlDsaRequest {
        parameter_set: MlDsaParameterSet::MlDsa44,
        message: &fixture("message.txt"),
        context: b"",
        hedging: MlDsaHedging::Preferred,
    };
    certificate
        .verify_signature(&request, &fixture("mldsa44.sig"))
        .unwrap();
}
