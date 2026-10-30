// SPDX-License-Identifier: MIT OR Apache-2.0
//! Application curveName provisioning/agreement against the RFC/OpenSSL reference.
use pkcs11_client::{
    AesGcmEncryptRequest, Authentication, DigestAlgorithm, KbkdfOutput, KbkdfRequest,
    MontgomeryNamedCurve as Curve, MontgomeryNamedKeyPairRequest as Pair,
    MontgomeryNamedPeer as Peer, MontgomeryNamedRequest as Request, ObjectRef, Pin, Provider,
    SecretKeyIdentity, SessionMode,
};
use secrecy::SecretString;
fn reference(group: u8, id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id=%D9%77%{group:02X}%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn client_named_profiles_generate_import_export_and_derive_without_secret_export() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let caps = provider.generation_capabilities(&token).unwrap();
    assert_eq!(
        caps.montgomery_named,
        vec![Curve::Curve25519, Curve::Curve448]
    );
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (group, curve) in [(1, Curve::Curve25519), (2, Curve::Curve448)] {
        let pair = Pair {
            curve,
            id: &[0xd9, 0x77, group, 0x20],
            label: b"client curveName",
        };
        session.generate_named_montgomery_key_pair(&pair).unwrap();
        assert!(session.generate_named_montgomery_key_pair(&pair).is_err());
        let generated = session
            .export_named_montgomery_public_key(&reference(group, 0x20, "public"), curve)
            .unwrap();
        let generated = Peer::from_bytes(curve, &generated).unwrap();
        session
            .import_named_montgomery_public_key(
                &generated,
                &[0xd9, 0x77, group, 0x21],
                b"client imported curveName",
            )
            .unwrap();
        assert!(
            session
                .import_named_montgomery_public_key(
                    &generated,
                    &[0xd9, 0x77, group, 0x21],
                    b"duplicate"
                )
                .is_err()
        );
        assert_eq!(
            session
                .export_named_montgomery_public_key(&reference(group, 0x21, "public"), curve)
                .unwrap(),
            generated.as_bytes()
        );
        let other = if curve == Curve::Curve25519 {
            Curve::Curve448
        } else {
            Curve::Curve25519
        };
        assert!(
            session
                .export_named_montgomery_public_key(&reference(group, 0x20, "public"), other)
                .is_err()
        );
        if group == 1 {
            assert!(
                session
                    .export_x25519_public_key(&reference(group, 0x20, "public"))
                    .is_err()
            );
        } else {
            assert!(
                session
                    .export_x448_public_key(&reference(group, 0x20, "public"))
                    .is_err()
            );
        }
        let bob = Peer::from_bytes(
            curve,
            &session
                .export_named_montgomery_public_key(&reference(group, 2, "public"), curve)
                .unwrap(),
        )
        .unwrap();
        let mut ciphers = Vec::new();
        for (base, peer, id) in [(1, &bob, 0x22), (0x20, &bob, 0x24), (2, &generated, 0x26)] {
            let request = Request {
                peer,
                identity: SecretKeyIdentity {
                    id: &[0xd9, 0x77, group, id],
                    label: b"client raw agreement",
                },
            };
            session
                .derive_named_montgomery(&reference(group, base, "private"), &request)
                .unwrap();
            assert!(
                session
                    .derive_named_montgomery(&reference(group, base, "private"), &request)
                    .is_err()
            );
            session
                .derive_kbkdf(
                    &reference(group, id, "secret-key"),
                    &KbkdfRequest {
                        digest: DigestAlgorithm::Sha512,
                        kdf_label: b"curveName test",
                        context: b"RFC7748 v1",
                        output: KbkdfOutput::Aes256,
                        id: &[0xd9, 0x77, group, id + 1],
                        label: b"client curveName AES",
                    },
                )
                .unwrap();
            ciphers.push(
                session
                    .encrypt_aes_gcm(
                        &reference(group, id + 1, "secret-key"),
                        &AesGcmEncryptRequest {
                            nonce: &[7; 12],
                            aad: b"curveName test",
                            plaintext: b"public agreement proof",
                        },
                    )
                    .unwrap(),
            );
        }
        let oracle = session
            .encrypt_aes_gcm(
                &reference(group, 5, "secret-key"),
                &AesGcmEncryptRequest {
                    nonce: &[7; 12],
                    aad: b"curveName test",
                    plaintext: b"public agreement proof",
                },
            )
            .unwrap();
        assert_eq!(ciphers[0], oracle);
        assert_eq!(ciphers[1], ciphers[2]);
        session.state().unwrap();
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}
