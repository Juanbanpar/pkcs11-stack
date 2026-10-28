// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8032 vectors, RFC 8410 encoding checks and independent OpenSSL signatures.
use pkcs11_client::*;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{Any, BitString},
    },
    spki::SubjectPublicKeyInfoOwned,
};

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/eddsa")
            .join(name),
    )
    .unwrap()
}
#[test]
fn rfc8032_empty_message_vectors_and_strict_decoding() {
    for (curve, public, signature) in [
        (
            EdDsaCurve::Ed25519,
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            EdDsaCurve::Ed448,
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
        ),
    ] {
        let public = unhex(public);
        let verifier = EdDsaVerifyingKey::from_bytes(curve, &public).unwrap();
        let signature = unhex(signature);
        let request = EdDsaRequest {
            curve,
            message: b"",
        };
        verifier
            .verify_signature(&request, &signature)
            .unwrap_or_else(|e| panic!("{curve:?}: {e}"));
        assert!(matches!(
            verifier.verify_signature(
                &EdDsaRequest {
                    message: b"changed",
                    ..request
                },
                &signature
            ),
            Err(Error::SignatureMismatch)
        ));
        for length in [0, signature.len() - 1, signature.len() + 1] {
            assert!(matches!(
                verifier.verify_signature(&request, &vec![0; length]),
                Err(Error::SignatureMismatch)
            ));
        }
        let mut malformed = signature.clone();
        malformed[curve.public_key_length()..].fill(255);
        assert!(matches!(
            verifier.verify_signature(&request, &malformed),
            Err(Error::SignatureMismatch)
        ));
        let der = verifier.to_spki_der().unwrap();
        assert_eq!(
            EdDsaVerifyingKey::from_spki_der(&der).unwrap().as_bytes(),
            public
        );
        let spki = SubjectPublicKeyInfoOwned::from_der(&der).unwrap();
        assert!(spki.algorithm.parameters.is_none());
        let mut bad = spki.clone();
        bad.algorithm.parameters = Some(Any::from_der(&[5, 0]).unwrap());
        assert!(matches!(
            EdDsaVerifyingKey::from_spki_der(&bad.to_der().unwrap()),
            Err(Error::InvalidPublicKey)
        ));
        bad = spki.clone();
        bad.subject_public_key = BitString::new(1, vec![0; public.len()]).unwrap();
        assert!(EdDsaVerifyingKey::from_spki_der(&bad.to_der().unwrap()).is_err());
        let mut trailing = der;
        trailing.push(0);
        assert!(EdDsaVerifyingKey::from_spki_der(&trailing).is_err());
        for point in [vec![0; public.len()], vec![255; public.len()], {
            let mut p = vec![0; public.len()];
            p[0] = 1;
            p
        }] {
            assert!(EdDsaVerifyingKey::from_bytes(curve, &point).is_err());
        }
        if curve == EdDsaCurve::Ed448 {
            let mut noncanonical = public;
            noncanonical[56] |= 1;
            assert!(EdDsaVerifyingKey::from_bytes(curve, &noncanonical).is_err());
        }
    }
}
#[test]
fn openssl_certificates_and_signatures_remain_independent_of_classical_profiles() {
    for (curve, name) in [
        (EdDsaCurve::Ed25519, "ed25519"),
        (EdDsaCurve::Ed448, "ed448"),
    ] {
        let der = fixture(&format!("{name}.der"));
        assert!(matches!(
            Certificate::from_der(der.clone()),
            Err(Error::UnsupportedCertificateKey)
        ));
        let certificate = EdDsaCertificate::from_der(der).unwrap();
        assert_eq!(certificate.curve(), curve);
        certificate
            .verify_signature(
                &EdDsaRequest {
                    curve,
                    message: &fixture("message.txt"),
                },
                &fixture(&format!("{name}.sig")),
            )
            .unwrap();
        assert!(matches!(
            certificate.verify_signature(
                &EdDsaRequest {
                    curve: if curve == EdDsaCurve::Ed25519 {
                        EdDsaCurve::Ed448
                    } else {
                        EdDsaCurve::Ed25519
                    },
                    message: b""
                },
                &[]
            ),
            Err(Error::UnsupportedVerification)
        ));
    }
}
