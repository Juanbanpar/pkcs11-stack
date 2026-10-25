// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed generation and shared choices through the application API.
use pkcs11_client::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication, DeriveRequest, EcdhKeyPairRequest,
    EcdhPeer, Error, KeyOperation, NamedCurve, ObjectRef, Pin, Provider, SecretKeyIdentity,
    SessionMode,
};
use secrecy::SecretString;

fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=client-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-softhsm.sh disposable token"]
fn typed_generation_and_advisory_choices() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=client-test".parse().unwrap();
    let options = provider.generation_capabilities(&token).unwrap();
    assert_eq!(
        options.signing,
        provider.generation_options(&token).unwrap()
    );
    assert_eq!(
        options.ml_dsa,
        provider.ml_dsa_generation_options(&token).unwrap()
    );
    assert_eq!(
        options.ml_kem,
        provider.ml_kem_generation_options(&token).unwrap()
    );
    assert_eq!(
        options.ecdh,
        [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521]
    );
    assert_eq!(
        options.aes,
        [
            AesKeySize::Bits128,
            AesKeySize::Bits192,
            AesKeySize::Bits256
        ]
    );
    if std::env::var("PKCS11_TEST_REQUIRE_PQC").as_deref() == Ok("1") {
        assert_eq!(options.ml_dsa.len(), 3);
        assert_eq!(options.ml_kem.len(), 3);
    }
    assert!(
        provider
            .generation_capabilities(&"pkcs11:token=missing".parse().unwrap())
            .is_err()
    );
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let ec = EcdhKeyPairRequest {
        curve: NamedCurve::P256,
        id: &[0x96, 0],
        label: b"client ECDH",
    };
    let aes = AesKeyRequest {
        size: AesKeySize::Bits256,
        purpose: AesKeyPurpose::Wrapping,
        id: &[0x97],
        label: b"client AES",
    };
    let mut ro = provider
        .management(&token, SessionMode::ReadOnly, auth())
        .unwrap();
    assert!(ro.generate_ecdh_key_pair(&ec).is_err());
    assert!(ro.generate_aes_key(&aes).is_err());
    ro.close().unwrap();
    let mut session = provider
        .management(&token, SessionMode::ReadWrite, auth())
        .unwrap();
    let mut peers = vec![];
    for side in 0..2 {
        let id = [0x96, side];
        session
            .generate_ecdh_key_pair(&EcdhKeyPairRequest { id: &id, ..ec })
            .unwrap();
        assert!(
            session
                .generate_ecdh_key_pair(&EcdhKeyPairRequest { id: &id, ..ec })
                .is_err()
        );
        let public = session.export_public(&reference(&id, "public")).unwrap();
        peers.push(EcdhPeer::from_spki_der(&public).unwrap());
        assert!(matches!(
            session.export_public(&reference(&id, "private")),
            Err(Error::UnsupportedExport)
        ));
        session
            .key_operation_options(&reference(&id, "private"), KeyOperation::Derive)
            .unwrap();
    }
    for side in 0..2 {
        session
            .derive(
                &reference(&[0x96, side], "private"),
                &DeriveRequest {
                    peer: &peers[1 - side as usize],
                    identity: SecretKeyIdentity {
                        id: &[0x98, side],
                        label: b"client agreement",
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            session.export_public(&reference(&[0x98, side], "secret-key")),
            Err(Error::UnsupportedExport)
        ));
    }
    session.generate_aes_key(&aes).unwrap();
    session
        .key_operation_options(&reference(aes.id, "secret-key"), KeyOperation::Wrap)
        .unwrap();
    session
        .key_operation_options(&reference(aes.id, "secret-key"), KeyOperation::Unwrap)
        .unwrap();
    assert!(session.generate_aes_key(&aes).is_err());
    assert!(
        session
            .generate_aes_key(&AesKeyRequest { id: &[], ..aes })
            .is_err()
    );
    assert!(
        session
            .generate_ecdh_key_pair(&EcdhKeyPairRequest {
                label: &[0; 129],
                ..ec
            })
            .is_err()
    );
    assert!(matches!(
        session.export_public(&reference(aes.id, "secret-key")),
        Err(Error::UnsupportedExport)
    ));
    session.state().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}
