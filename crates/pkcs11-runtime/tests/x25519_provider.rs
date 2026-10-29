// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 agreement followed by token-side HKDF, without secret extraction.
#[path = "fixtures/x25519_vectors.rs"]
mod vectors;
use pkcs11_runtime::{
    AesGcmEncryptRequest, Attribute, AttributeInfo, AttributeType as A, Authentication,
    DigestAlgorithm, HkdfOutput, HkdfRequest, KeyType, Module, ObjectClass, ObjectRef, Pin,
    SessionMode, X25519Derivation, X25519KeyPairRequest, X25519PublicKey,
};
use secrecy::SecretString;
use std::{path::PathBuf, process::Command};
fn reference(id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id=%D9%58%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn generated_pair_and_public_import_interoperate_with_openssl() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    assert!(token.x25519_generation_supported().unwrap());
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let request = X25519KeyPairRequest {
        id: &[0xd9, 0x58, 0x50],
        label: b"generated X25519",
    };
    session.generate_x25519_key_pair(&request).unwrap();
    assert!(session.generate_x25519_key_pair(&request).is_err());
    let public = session
        .x25519_public_key(&reference(0x50, "public"))
        .unwrap();
    let alice = X25519PublicKey::from_bytes(&vectors::hex(vectors::ALICE_PUBLIC)).unwrap();
    session
        .import_x25519_public_key(&alice, &[0xd9, 0x58, 0x51], b"imported X25519")
        .unwrap();
    assert!(
        session
            .import_x25519_public_key(&alice, &[0xd9, 0x58, 0x51], b"duplicate")
            .is_err()
    );
    assert_eq!(
        session
            .x25519_public_key(&reference(0x51, "public"))
            .unwrap(),
        alice
    );
    for (kind, expected) in [
        (
            "private",
            vec![
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Derive(true),
                Attribute::Sign(false),
                Attribute::SignRecover(false),
                Attribute::Decrypt(false),
                Attribute::Unwrap(false),
                Attribute::AlwaysAuthenticate(false),
                Attribute::Local(true),
                Attribute::KeyGenMechanism(
                    pkcs11_runtime::MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN,
                ),
                Attribute::AllowedMechanisms(vec![pkcs11_runtime::MechanismType::ECDH1_DERIVE]),
            ],
        ),
        (
            "public",
            vec![
                Attribute::Private(false),
                Attribute::Derive(false),
                Attribute::Verify(false),
                Attribute::VerifyRecover(false),
                Attribute::Encrypt(false),
                Attribute::Wrap(false),
            ],
        ),
    ] {
        let object = session.resolve(&reference(0x50, kind)).unwrap();
        for attr in expected {
            let values = object.read_attributes(&[attr.attribute_type()]).unwrap();
            assert!(values.expose_values().contains(&attr));
        }
        if kind == "private" {
            assert!(matches!(
                object.attribute_info(&[A::Value]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
    }
    {
        let object = session.resolve(&reference(0x51, "public")).unwrap();
        let attrs = object
            .read_attributes(&[
                A::Trusted,
                A::Local,
                A::Derive,
                A::Verify,
                A::VerifyRecover,
                A::Encrypt,
                A::Wrap,
            ])
            .unwrap();
        for attr in [
            Attribute::Trusted(false),
            Attribute::Local(false),
            Attribute::Derive(false),
            Attribute::Verify(false),
            Attribute::VerifyRecover(false),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
        ] {
            assert!(attrs.expose_values().contains(&attr));
        }
    }
    let mut private_der = vectors::hex("302e020100300506032b656e04220420");
    private_der.extend(vectors::hex(vectors::ALICE_PRIVATE));
    std::fs::write(root.join("generated-x25519-alice.der"), private_der).unwrap();
    std::fs::write(
        root.join("generated-x25519-peer.der"),
        vectors::spki(public.as_bytes()),
    )
    .unwrap();
    let openssl = std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap();
    // OpenSSL uses the public RFC test private key. The generated private key
    // and both token-derived secrets are never requested from the provider.
    let agreement = Command::new(&openssl)
        .args([
            "pkeyutl",
            "-derive",
            "-keyform",
            "DER",
            "-peerform",
            "DER",
            "-inkey",
        ])
        .arg(root.join("generated-x25519-alice.der"))
        .arg("-peerkey")
        .arg(root.join("generated-x25519-peer.der"))
        .output()
        .unwrap();
    assert!(
        agreement.status.success(),
        "OpenSSL agreement: {}",
        agreement.status
    );
    assert_eq!(agreement.stdout.len(), 32);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut info = b"generated X25519 test v1".to_vec();
    info.extend(alice.as_bytes());
    info.extend(public.as_bytes());
    let expected = Command::new(&openssl)
        .args([
            "kdf",
            "-binary",
            "-keylen",
            "32",
            "-kdfopt",
            "digest:SHA256",
            "-kdfopt",
            &format!("hexkey:{}", hex(&agreement.stdout)),
            "-kdfopt",
            "salt:X25519 test salt",
            "-kdfopt",
            &format!("hexinfo:{}", hex(&info)),
            "HKDF",
        ])
        .output()
        .unwrap();
    assert!(expected.status.success());
    assert_eq!(expected.stdout.len(), 32);
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(vec![0xd9, 0x58, 0x54]),
            Attribute::Label(b"generated X25519 AES reference".to_vec()),
            Attribute::Value(expected.stdout),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ])
        .unwrap();
    session
        .derive_x25519_secret(
            &reference(0x50, "private"),
            &X25519Derivation {
                peer: &alice,
                id: &[0xd9, 0x58, 0x52],
                label: b"generated X25519 raw",
            },
        )
        .unwrap();
    session
        .derive_hkdf(
            &reference(0x52, "secret-key"),
            &HkdfRequest {
                digest: DigestAlgorithm::Sha256,
                salt: b"X25519 test salt",
                info: &info,
                output: HkdfOutput::Aes256,
                id: &[0xd9, 0x58, 0x53],
                label: b"generated X25519 AES",
            },
        )
        .unwrap();
    let encrypt = AesGcmEncryptRequest {
        nonce: &[2; 12],
        aad: b"generated X25519",
        plaintext: b"generated agreement proof",
    };
    assert_eq!(
        session
            .encrypt_aes_gcm(&reference(0x53, "secret-key"), &encrypt)
            .unwrap(),
        session
            .encrypt_aes_gcm(&reference(0x54, "secret-key"), &encrypt)
            .unwrap()
    );
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn rfc7748_agreement_and_hkdf_match_openssl_without_reading_secrets() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    for mechanism in [
        pkcs11_runtime::MechanismType::ECDH1_DERIVE,
        pkcs11_runtime::MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN,
    ] {
        assert_eq!(token.mechanism_info(mechanism).unwrap().min_key_size(), 255);
    }
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (id, private, public) in [
        (1, vectors::ALICE_PRIVATE, vectors::ALICE_PUBLIC),
        (2, vectors::BOB_PRIVATE, vectors::BOB_PUBLIC),
    ] {
        // Import public RFC test vectors for fixture setup, including test private
        // keys. The application adds no private-key import workflow.
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
            let private_object = class == ObjectClass::PRIVATE_KEY;
            let mut attrs = vec![
                Attribute::Class(class),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(true),
                Attribute::Private(private_object),
                Attribute::Id(vec![0xd9, 0x58, id]),
                Attribute::Label(format!("X25519 RFC {id}").into_bytes()),
                Attribute::EcParams(vec![6, 3, 43, 101, 110]),
            ];
            if private_object {
                attrs.extend([
                    Attribute::Value(vectors::hex(private)),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Derive(true),
                    Attribute::AlwaysAuthenticate(false),
                ]);
            } else {
                attrs.push(Attribute::EcPoint(vectors::hex(public)));
            }
            session.create_object(&attrs).unwrap();
        }
        assert_eq!(
            session
                .x25519_public_key(&reference(id, "public"))
                .unwrap()
                .as_bytes()
                .as_slice(),
            vectors::hex(public)
        );
    }
    let alice = vectors::hex(vectors::ALICE_PUBLIC);
    let bob = vectors::hex(vectors::BOB_PUBLIC);
    let mut private_der = vectors::hex("302e020100300506032b656e04220420");
    private_der.extend(vectors::hex(vectors::ALICE_PRIVATE));
    std::fs::write(root.join("x25519-private.der"), private_der).unwrap();
    std::fs::write(root.join("x25519-peer.der"), vectors::spki(&bob)).unwrap();
    let openssl = std::env::var_os("PKCS11_TEST_KDF_OPENSSL").unwrap();
    let agreement = Command::new(&openssl)
        .args([
            "pkeyutl",
            "-derive",
            "-keyform",
            "DER",
            "-peerform",
            "DER",
            "-inkey",
        ])
        .arg(root.join("x25519-private.der"))
        .arg("-peerkey")
        .arg(root.join("x25519-peer.der"))
        .output()
        .unwrap();
    assert!(
        agreement.status.success(),
        "OpenSSL X25519: {}",
        agreement.status
    );
    assert_eq!(agreement.stdout, vectors::hex(vectors::SHARED));
    let mut info = b"X25519 RFC7748 test v1".to_vec();
    info.extend(&alice);
    info.extend(&bob);
    let salt = b"X25519 test salt";
    std::fs::write(root.join("x25519-info"), &info).unwrap();
    std::fs::write(root.join("x25519-salt"), salt).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let expected = Command::new(&openssl)
        .args([
            "kdf",
            "-binary",
            "-keylen",
            "32",
            "-kdfopt",
            "digest:SHA256",
            "-kdfopt",
            &format!("hexkey:{}", vectors::SHARED),
            "-kdfopt",
            &format!("hexsalt:{}", hex(salt)),
            "-kdfopt",
            &format!("hexinfo:{}", hex(&info)),
            "HKDF",
        ])
        .output()
        .unwrap();
    assert!(expected.status.success());
    assert_eq!(expected.stdout.len(), 32);
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(vec![0xd9, 0x58, 0xff]),
            Attribute::Label(b"X25519 reference AES".to_vec()),
            Attribute::Value(expected.stdout),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ])
        .unwrap();
    let request = AesGcmEncryptRequest {
        nonce: &[1; 12],
        aad: b"X25519 test",
        plaintext: b"public X25519 challenge",
    };
    let expected_ciphertext = session
        .encrypt_aes_gcm(&reference(0xff, "secret-key"), &request)
        .unwrap();
    std::fs::write(root.join("x25519-expected-gcm"), &expected_ciphertext).unwrap();
    std::fs::write(root.join("x25519-aad"), request.aad).unwrap();
    std::fs::write(root.join("x25519-plaintext"), request.plaintext).unwrap();
    let mut bob_alias = bob.clone();
    bob_alias[31] |= 128;
    for (actor, peer, result) in [(1, &bob, 0x10), (2, &alice, 0x11), (1, &bob_alias, 0x12)] {
        let peer = X25519PublicKey::from_bytes(peer).unwrap();
        let id = [0xd9, 0x58, result];
        let derive = X25519Derivation {
            peer: &peer,
            id: &id,
            label: b"X25519 agreement",
        };
        session
            .derive_x25519_secret(&reference(actor, "private"), &derive)
            .unwrap();
        assert!(
            session
                .derive_x25519_secret(&reference(actor, "private"), &derive)
                .is_err()
        );
        {
            let object = session.resolve(&reference(result, "secret-key")).unwrap();
            let attrs = object
                .read_attributes(&[
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
                    A::ValueLen,
                ])
                .unwrap();
            for expected in [
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
                Attribute::ValueLen(32.into()),
            ] {
                assert!(attrs.expose_values().contains(&expected));
            }
            assert!(matches!(
                object.attribute_info(&[A::Value]).unwrap().as_slice(),
                [AttributeInfo::Sensitive]
            ));
        }
        let aes_id = [0xd9, 0x58, result + 0x10];
        session
            .derive_hkdf(
                &reference(result, "secret-key"),
                &HkdfRequest {
                    digest: DigestAlgorithm::Sha256,
                    salt,
                    info: &info,
                    output: HkdfOutput::Aes256,
                    id: &aes_id,
                    label: b"X25519 HKDF AES",
                },
            )
            .unwrap();
        assert_eq!(
            session
                .encrypt_aes_gcm(&reference(result + 0x10, "secret-key"), &request)
                .unwrap(),
            expected_ciphertext
        );
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
