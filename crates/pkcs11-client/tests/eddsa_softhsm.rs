// SPDX-License-Identifier: MIT OR Apache-2.0
//! EdDSA client workflows on disposable SoftHSM.

use pkcs11_client::{
    Authentication, EdDsaCurve, EdDsaRequest, EdDsaVerifyingKey, Error, ManagementSession, Pin,
    Provider, SessionMode,
};
use secrecy::SecretString;
use std::num::NonZeroUsize;

fn private(token: &str, object: &str) -> pkcs11_client::PrivateKeyRef {
    pkcs11_client::PrivateKeyRef::new(
        format!("pkcs11:token={token};object={object};type=private")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn public(token: &str, object: &str) -> pkcs11_client::PublicKeyRef {
    pkcs11_client::PublicKeyRef::new(
        format!("pkcs11:token={token};object={object};type=public")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn client_eddsa_generation_signing_export_and_import() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=client-test";
    let pin = SecretString::from("12345678");
    let mut management: ManagementSession<'_> = provider
        .management(
            &token.parse().unwrap(),
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (curve, id) in [
        (EdDsaCurve::Ed25519, "client-eddsa-25519"),
        (EdDsaCurve::Ed448, "client-eddsa-448"),
    ] {
        management
            .generate_eddsa_key_pair(curve, id.as_bytes(), id.as_bytes(), false)
            .unwrap();
    }
    management.close().unwrap();

    let client = provider
        .client(
            &token.parse().unwrap(),
            NonZeroUsize::new(1).unwrap(),
            pkcs11_client::SigningPolicy::default(),
        )
        .unwrap();
    for (curve, id) in [
        (EdDsaCurve::Ed25519, "client-eddsa-25519"),
        (EdDsaCurve::Ed448, "client-eddsa-448"),
    ] {
        let key = private("client-test", id);
        let public_key = public("client-test", id);
        let caps = client
            .eddsa_capabilities(&key, Authentication::User(Pin::Value(&pin)))
            .unwrap();
        assert_eq!(caps.curve, curve);
        assert!(caps.can_sign);
        let request = EdDsaRequest {
            curve,
            message: b"client EdDSA provider fixture",
        };
        let signature = client
            .sign_eddsa(&key, &request, Authentication::User(Pin::Value(&pin)), None)
            .unwrap();
        client
            .verify_eddsa(
                &public_key,
                &request,
                &signature,
                Authentication::User(Pin::Value(&pin)),
            )
            .unwrap();
        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            client.verify_eddsa(
                &public_key,
                &request,
                &tampered,
                Authentication::User(Pin::Value(&pin)),
            ),
            Err(Error::SignatureMismatch)
        ));
        let spki = client
            .export_eddsa_public_key(&public_key, Authentication::User(Pin::Value(&pin)))
            .unwrap();
        let verifying = EdDsaVerifyingKey::from_spki_der(&spki).unwrap();
        assert_eq!(verifying.curve(), curve);
        verifying.verify_signature(&request, &signature).unwrap();
    }
    client.close().unwrap();
    provider.finalize().unwrap();
}
