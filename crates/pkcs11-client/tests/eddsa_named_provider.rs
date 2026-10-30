// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8032 vectors through management and pooled client APIs.
#[path = "../../pkcs11-runtime/tests/fixtures/eddsa_named_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::EdDsaNamedScheme;
use pkcs11_client::{
    Authentication, EdDsaCurve, EdDsaNamedPublicKey, EdDsaNamedRequest as Request,
    EdDsaNamedScheme as Scheme, Error, Pin, PrivateKeyRef, Provider, PublicKeyRef, SessionMode,
};
use secrecy::SecretString;
use std::num::NonZeroUsize;
fn uri(id: u8, kind: &str) -> String {
    format!("pkcs11:token=kdf-test;id=%D9%ED%01%{id:02X};type={kind}")
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store with Edwards support"]
fn named_client_profiles_verify_rfc_vectors_and_protected_generated_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    assert_eq!(
        provider
            .generation_capabilities(&token)
            .unwrap()
            .eddsa_named,
        vec![EdDsaCurve::Ed25519, EdDsaCurve::Ed448]
    );
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (index, vector) in vectors::VECTORS.iter().enumerate() {
        let id = index as u8;
        let public = PublicKeyRef::new(uri(id, "public").parse().unwrap()).unwrap();
        let private = PrivateKeyRef::new(uri(id, "private").parse().unwrap()).unwrap();
        assert_eq!(
            session.export_named_eddsa_public_key(&public).unwrap(),
            vectors::hex(vector.public)
        );
        let message = vectors::hex(vector.message);
        let context = vectors::hex(vector.context);
        let request = Request {
            scheme: vector.scheme,
            message: &message,
            context: &context,
        };
        let signature = session.sign_named_eddsa(&private, &request, None).unwrap();
        assert_eq!(signature, vectors::hex(vector.signature));
        session
            .verify_named_eddsa(&public, &request, &signature)
            .unwrap();
        assert!(matches!(
            session.verify_named_eddsa(
                &public,
                &Request {
                    message: b"altered",
                    ..request
                },
                &signature
            ),
            Err(Error::SignatureMismatch)
        ));
        session.state().unwrap();
    }
    for (id, curve, scheme) in [
        (0xa0, EdDsaCurve::Ed25519, Scheme::Ed25519ph),
        (0xa1, EdDsaCurve::Ed448, Scheme::Ed448ph),
    ] {
        session
            .generate_named_eddsa_key_pair(
                curve,
                &[0xd9, 0xed, 1, id],
                b"client named EdDSA",
                false,
            )
            .unwrap();
        assert!(
            session
                .generate_named_eddsa_key_pair(curve, &[0xd9, 0xed, 1, id], b"duplicate", false)
                .is_err()
        );
        let public = PublicKeyRef::new(uri(id, "public").parse().unwrap()).unwrap();
        let private = PrivateKeyRef::new(uri(id, "private").parse().unwrap()).unwrap();
        let raw = session.export_named_eddsa_public_key(&public).unwrap();
        let key = EdDsaNamedPublicKey::from_bytes(curve, &raw).unwrap();
        session
            .import_named_eddsa_public_key(
                &key,
                &[0xd9, 0xed, 1, id + 2],
                b"client imported named EdDSA",
            )
            .unwrap();
        assert!(
            session
                .import_named_eddsa_public_key(&key, &[0xd9, 0xed, 1, id + 2], b"duplicate")
                .is_err()
        );
        let request = Request {
            scheme,
            message: b"client generated",
            context: &[0xa5; 255],
        };
        let signature = session.sign_named_eddsa(&private, &request, None).unwrap();
        session
            .verify_named_eddsa(
                &PublicKeyRef::new(uri(id + 2, "public").parse().unwrap()).unwrap(),
                &request,
                &signature,
            )
            .unwrap();
    }
    session.close().unwrap();
    let client = provider
        .client(
            &token,
            NonZeroUsize::new(1).unwrap(),
            pkcs11_client::SigningPolicy::default(),
        )
        .unwrap();
    for (index, vector) in vectors::VECTORS.iter().enumerate() {
        let message = vectors::hex(vector.message);
        let context = vectors::hex(vector.context);
        let request = Request {
            scheme: vector.scheme,
            message: &message,
            context: &context,
        };
        let public = PublicKeyRef::new(uri(index as u8, "public").parse().unwrap()).unwrap();
        let private = PrivateKeyRef::new(uri(index as u8, "private").parse().unwrap()).unwrap();
        let signature = client
            .sign_named_eddsa(
                &private,
                &request,
                Authentication::User(Pin::Value(&pin)),
                None,
            )
            .unwrap();
        assert_eq!(signature, vectors::hex(vector.signature));
        client
            .verify_named_eddsa(
                &public,
                &request,
                &signature,
                Authentication::User(Pin::Value(&pin)),
            )
            .unwrap();
    }
    client.close().unwrap();
    provider.finalize().unwrap();
}
