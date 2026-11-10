// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ed25519/Ed448 generation, signing and verification on disposable SoftHSM.

use pkcs11_runtime::{
    Authentication, EdDsaCurve, EdDsaRequest, Error, Module, Pin, PrivateKeyRef, PublicKeyRef,
    SessionMode,
};
use secrecy::SecretString;

fn private(token: &str, object: &str) -> PrivateKeyRef {
    PrivateKeyRef::new(
        format!("pkcs11:token={token};object={object};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn public(token: &str, object: &str) -> PublicKeyRef {
    PublicKeyRef::new(
        format!("pkcs11:token={token};object={object};type=public")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn eddsa_generation_signing_verification_and_curve_checks() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let module = Module::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=client-test".parse().unwrap())
        .unwrap();
    assert!(
        token
            .eddsa_generation_options()
            .unwrap()
            .contains(&EdDsaCurve::Ed25519)
    );
    let pin = SecretString::from("12345678");
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (curve, id) in [
        (EdDsaCurve::Ed25519, "eddsa-25519"),
        (EdDsaCurve::Ed448, "eddsa-448"),
    ] {
        session
            .generate_eddsa_key_pair(curve, id.as_bytes(), id.as_bytes(), false)
            .unwrap();
    }

    for (curve, id) in [
        (EdDsaCurve::Ed25519, "eddsa-25519"),
        (EdDsaCurve::Ed448, "eddsa-448"),
    ] {
        let key = private("client-test", id);
        let public_key = public("client-test", id);
        let capabilities = session.eddsa_capabilities(&key).unwrap();
        assert_eq!(capabilities.curve, curve);
        assert!(capabilities.can_sign);
        let exported = session.eddsa_public_key(&public_key).unwrap();
        assert_eq!(exported.curve(), curve);
        assert_eq!(exported.as_bytes().len(), curve.public_key_length());

        let request = EdDsaRequest {
            curve,
            message: b"pkcs11-stack EdDSA provider fixture",
        };
        let signature = session.sign_eddsa(&key, &request, None).unwrap();
        assert_eq!(signature.len(), curve.signature_length());
        session
            .verify_eddsa(&public_key, &request, &signature)
            .unwrap();

        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            session.verify_eddsa(&public_key, &request, &tampered),
            Err(Error::SignatureMismatch)
        ));
        session.info().unwrap();

        let wrong = if curve == EdDsaCurve::Ed25519 {
            EdDsaCurve::Ed448
        } else {
            EdDsaCurve::Ed25519
        };
        assert!(matches!(
            session.sign_eddsa(
                &key,
                &EdDsaRequest {
                    curve: wrong,
                    message: b"wrong curve",
                },
                None,
            ),
            Err(Error::UnsupportedSigning(_))
        ));
    }
}
