// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 curveName agreement, protected storage and independent KDF references.
#[path = "fixtures/x25519_vectors.rs"]
#[allow(dead_code)]
mod c255;
#[path = "fixtures/x448_vectors.rs"]
#[allow(dead_code)]
mod c448;
use pkcs11_runtime::{
    AesGcmEncryptRequest, Attribute, AttributeInfo, AttributeType as A, Authentication,
    DigestAlgorithm, KbkdfOutput, KbkdfRequest, KeyType, MechanismType, Module,
    MontgomeryNamedCurve as Curve, MontgomeryNamedPublicKey as Public, ObjectClass, ObjectRef, Pin,
    Session, SessionMode,
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
fn derived_cipher(session: &mut Session<'_>, group: u8, base: u8, id: u8) -> Vec<u8> {
    session
        .derive_kbkdf(
            &reference(group, base, "secret-key"),
            &KbkdfRequest {
                digest: DigestAlgorithm::Sha512,
                kdf_label: b"curveName test",
                context: b"RFC7748 v1",
                output: KbkdfOutput::Aes256,
                id: &[0xd9, 0x77, group, id],
                label: b"curveName AES",
            },
        )
        .unwrap();
    session
        .encrypt_aes_gcm(
            &reference(group, id, "secret-key"),
            &AesGcmEncryptRequest {
                nonce: &[7; 12],
                aad: b"curveName test",
                plaintext: b"public agreement proof",
            },
        )
        .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn named_profiles_preserve_parameters_and_match_rfc7748_and_openssl() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (group, curve, params, alice_private, alice_public, bob_private, bob_public, shared) in [
        (
            1,
            Curve::Curve25519,
            b"\x13\x0acurve25519".as_slice(),
            c255::ALICE_PRIVATE,
            c255::ALICE_PUBLIC,
            c255::BOB_PRIVATE,
            c255::BOB_PUBLIC,
            c255::SHARED,
        ),
        (
            2,
            Curve::Curve448,
            b"\x13\x08curve448".as_slice(),
            c448::ALICE_PRIVATE,
            c448::ALICE_PUBLIC,
            c448::BOB_PRIVATE,
            c448::BOB_PUBLIC,
            c448::SHARED,
        ),
    ] {
        assert!(token.named_montgomery_generation_supported(curve).unwrap());
        for (id, private, public) in [
            (1, alice_private, alice_public),
            (2, bob_private, bob_public),
        ] {
            // Private import exists only for these published RFC test fixtures.
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(KeyType::EC_MONTGOMERY),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                    Attribute::AlwaysAuthenticate(false),
                    Attribute::EcParams(params.to_vec()),
                    Attribute::Value(c255::hex(private)),
                    Attribute::Id(vec![0xd9, 0x77, group, id]),
                    Attribute::Label(b"RFC curveName test".to_vec()),
                ])
                .unwrap();
            let peer = Public::from_bytes(curve, &c255::hex(public)).unwrap();
            session
                .import_named_montgomery_public_key(
                    &peer,
                    &[0xd9, 0x77, group, id],
                    b"RFC curveName peer",
                )
                .unwrap();
            assert_eq!(
                session
                    .named_montgomery_public_key(&reference(group, id, "public"), curve)
                    .unwrap(),
                peer
            );
            assert!(
                session
                    .import_named_montgomery_public_key(
                        &peer,
                        &[0xd9, 0x77, group, id],
                        b"duplicate"
                    )
                    .is_err()
            );
            let object = session.resolve(&reference(group, id, "public")).unwrap();
            let values = object
                .read_attributes(&[
                    A::EcParams,
                    A::Trusted,
                    A::Private,
                    A::Derive,
                    A::Verify,
                    A::Encrypt,
                    A::Wrap,
                ])
                .unwrap();
            for attr in [
                Attribute::EcParams(params.to_vec()),
                Attribute::Trusted(false),
                Attribute::Private(false),
                Attribute::Derive(false),
                Attribute::Verify(false),
                Attribute::Encrypt(false),
                Attribute::Wrap(false),
            ] {
                assert!(values.expose_values().contains(&attr));
            }
        }
        session
            .generate_named_montgomery_key_pair(
                curve,
                &[0xd9, 0x77, group, 6],
                b"generated curveName",
            )
            .unwrap();
        assert!(
            session
                .generate_named_montgomery_key_pair(curve, &[0xd9, 0x77, group, 6], b"duplicate")
                .is_err()
        );
        let generated = session
            .named_montgomery_public_key(&reference(group, 6, "public"), curve)
            .unwrap();
        for kind in ["private", "public"] {
            let object = session.resolve(&reference(group, 6, kind)).unwrap();
            assert!(
                object
                    .read_attributes(&[A::EcParams])
                    .unwrap()
                    .expose_values()
                    .contains(&Attribute::EcParams(params.to_vec()))
            );
            if kind == "private" {
                let values = object
                    .read_attributes(&[
                        A::Private,
                        A::Sensitive,
                        A::Extractable,
                        A::Derive,
                        A::Local,
                        A::AllowedMechanisms,
                    ])
                    .unwrap();
                for attr in [
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                    Attribute::Local(true),
                    Attribute::AllowedMechanisms(vec![MechanismType::ECDH1_DERIVE]),
                ] {
                    assert!(values.expose_values().contains(&attr));
                }
                assert!(matches!(
                    object.attribute_info(&[A::Value]).unwrap().as_slice(),
                    [AttributeInfo::Sensitive]
                ));
            }
        }
        let bob = Public::from_bytes(curve, &c255::hex(bob_public)).unwrap();
        for (actor, peer, id) in [(1, &bob, 3), (6, &bob, 7), (2, &generated, 8)] {
            session
                .derive_named_montgomery_secret(
                    &reference(group, actor, "private"),
                    peer,
                    &[0xd9, 0x77, group, id],
                    b"curveName raw",
                )
                .unwrap();
            assert!(
                session
                    .derive_named_montgomery_secret(
                        &reference(group, actor, "private"),
                        peer,
                        &[0xd9, 0x77, group, id],
                        b"duplicate"
                    )
                    .is_err()
            );
            let object = session
                .resolve(&reference(group, id, "secret-key"))
                .unwrap();
            let values = object
                .read_attributes(&[
                    A::ValueLen,
                    A::Private,
                    A::Sensitive,
                    A::Extractable,
                    A::Derive,
                    A::Encrypt,
                    A::Decrypt,
                    A::Sign,
                    A::Verify,
                    A::Wrap,
                    A::Unwrap,
                ])
                .unwrap();
            for attr in [
                Attribute::ValueLen(peer.as_bytes().len().try_into().unwrap()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Derive(true),
                Attribute::Encrypt(false),
                Attribute::Decrypt(false),
                Attribute::Sign(false),
                Attribute::Verify(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
            ] {
                assert!(values.expose_values().contains(&attr));
            }
            assert!(matches!(
                object.attribute_info(&[A::Value]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        // The published shared value feeds only an independent reference. Neither
        // native private material nor derived values are requested from the token.
        let output =
            std::process::Command::new(std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap())
                .args([
                    "kdf",
                    "-binary",
                    "-keylen",
                    "32",
                    "-kdfopt",
                    "mode:COUNTER",
                    "-kdfopt",
                    "mac:HMAC",
                    "-kdfopt",
                    "digest:SHA512",
                    "-kdfopt",
                    &format!("hexkey:{shared}"),
                    "-kdfopt",
                    "salt:curveName test",
                    "-kdfopt",
                    "info:RFC7748 v1",
                    "-kdfopt",
                    "use-l:1",
                    "-kdfopt",
                    "use-separator:1",
                    "KBKDF",
                ])
                .output()
                .unwrap();
        assert!(
            output.status.success(),
            "OpenSSL KBKDF: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.len(), 32);
        session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Id(vec![0xd9, 0x77, group, 5]),
                Attribute::Value(output.stdout),
            ])
            .unwrap();
        let expected = session
            .encrypt_aes_gcm(
                &reference(group, 5, "secret-key"),
                &AesGcmEncryptRequest {
                    nonce: &[7; 12],
                    aad: b"curveName test",
                    plaintext: b"public agreement proof",
                },
            )
            .unwrap();
        assert_eq!(derived_cipher(&mut session, group, 3, 4), expected);
        assert_eq!(
            derived_cipher(&mut session, group, 7, 9),
            derived_cipher(&mut session, group, 8, 10)
        );
        session.info().unwrap();
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
