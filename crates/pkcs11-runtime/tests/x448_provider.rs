// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748/OpenSSL agreement and independent SHA-512 KDF references.
#[path = "fixtures/x448_vectors.rs"]
mod vectors;
use pkcs11_runtime::{
    AesGcmEncryptRequest, AesKeySize, Attribute, AttributeInfo, AttributeType as A, Authentication,
    DigestAlgorithm, HkdfOutput, HkdfRequest, KeyType, Module, ObjectClass, ObjectRef, Pin,
    SessionMode, X448Derivation, X448Kdf, X448KeyPairRequest, X448Output, X448PublicKey,
};
use secrecy::SecretString;
use sha2::{Digest, Sha512};
use std::{path::PathBuf, process::Command};
fn reference(id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id=%D9%48%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn kdf(z: &[u8], info: &[u8], nist: bool) -> Vec<u8> {
    let mut hash = Sha512::new();
    if nist {
        hash.update(1u32.to_be_bytes());
        hash.update(z);
    } else {
        hash.update(z);
        hash.update(1u32.to_be_bytes());
    }
    hash.update(info);
    hash.finalize().to_vec()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn rfc7748_raw_width_sha512_kdfs_and_hkdf_keep_secrets_on_token() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (id, private, public) in [
        (1, vectors::ALICE_PRIVATE, vectors::ALICE_PUBLIC),
        (2, vectors::BOB_PRIVATE, vectors::BOB_PUBLIC),
    ] {
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
            let private_object = class == ObjectClass::PRIVATE_KEY;
            let mut attrs = vec![
                Attribute::Class(class),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(true),
                Attribute::Private(private_object),
                Attribute::Id(vec![0xd9, 0x48, id]),
                Attribute::Label(format!("X448 RFC {id}").into_bytes()),
                Attribute::EcParams(vec![6, 3, 43, 101, 111]),
            ];
            // Only public RFC test fixtures use private-key import. No application
            // private-key import API or secret extraction is introduced.
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
                .x448_public_key(&reference(id, "public"))
                .unwrap()
                .as_bytes()
                .as_slice(),
            vectors::hex(public)
        );
    }
    let alice = X448PublicKey::from_bytes(&vectors::hex(vectors::ALICE_PUBLIC)).unwrap();
    let bob = X448PublicKey::from_bytes(&vectors::hex(vectors::BOB_PUBLIC)).unwrap();
    let mut info = b"X448 RFC7748 test v1".to_vec();
    info.extend(alice.as_bytes());
    info.extend(bob.as_bytes());
    std::fs::write(root.join("x448-info"), &info).unwrap();
    std::fs::write(root.join("x448-peer.der"), vectors::spki(bob.as_bytes())).unwrap();
    let mut private_der = vectors::hex("3046020100300506032b656f043a0438");
    private_der.extend(vectors::hex(vectors::ALICE_PRIVATE));
    std::fs::write(root.join("x448-private.der"), private_der).unwrap();
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
        .arg(root.join("x448-private.der"))
        .arg("-peerkey")
        .arg(root.join("x448-peer.der"))
        .output()
        .unwrap();
    assert!(
        agreement.status.success(),
        "OpenSSL X448: {}",
        agreement.status
    );
    assert_eq!(agreement.stdout, vectors::hex(vectors::SHARED));
    for (actor, peer, id) in [(1, &bob, 0x10), (2, &alice, 0x11)] {
        let request = X448Derivation {
            peer,
            kdf: X448Kdf::Null,
            shared_info: &[],
            output: X448Output::RawSecret,
            id: &[0xd9, 0x48, id],
            label: b"X448 raw secret",
        };
        session
            .derive_x448_key(&reference(actor, "private"), &request)
            .unwrap();
        assert!(
            session
                .derive_x448_key(&reference(actor, "private"), &request)
                .is_err()
        );
        {
            let object = session.resolve(&reference(id, "secret-key")).unwrap();
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
                Attribute::ValueLen(56.into()),
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
        assert!(
            session
                .hkdf_capabilities(&reference(id, "secret-key"), DigestAlgorithm::Sha512)
                .is_err()
        );
        session.info().unwrap();
    }
    let encrypt = AesGcmEncryptRequest {
        nonce: &[4; 12],
        aad: b"X448 test",
        plaintext: b"public X448 challenge",
    };
    let mut nist_reference = Vec::new();
    for (nist, mode, start, name) in [
        (false, X448Kdf::X963Sha512, 0x20, "x963"),
        (true, X448Kdf::Sp80056aSha512, 0x30, "nist"),
    ] {
        let expected = kdf(&vectors::hex(vectors::SHARED), &info, nist);
        if nist {
            nist_reference = expected.clone();
        }
        for (offset, size) in [
            AesKeySize::Bits128,
            AesKeySize::Bits192,
            AesKeySize::Bits256,
        ]
        .into_iter()
        .enumerate()
        {
            let oracle = 0xe0 + (nist as u8) * 3 + offset as u8;
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Id(vec![0xd9, 0x48, oracle]),
                    Attribute::Label(b"X448 reference AES".to_vec()),
                    Attribute::Value(expected[..size.length()].to_vec()),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                ])
                .unwrap();
            let ciphertext = session
                .encrypt_aes_gcm(&reference(oracle, "secret-key"), &encrypt)
                .unwrap();
            std::fs::write(
                root.join(format!("x448-{name}-cipher-{}", size.length())),
                &ciphertext,
            )
            .unwrap();
            for (actor, peer, actor_offset) in [(1, &bob, 0), (2, &alice, 4)] {
                let id = [0xd9, 0x48, start + offset as u8 + actor_offset];
                session
                    .derive_x448_key(
                        &reference(actor, "private"),
                        &X448Derivation {
                            peer,
                            kdf: mode,
                            shared_info: &info,
                            output: X448Output::Aes(size),
                            id: &id,
                            label: b"X448 derived AES",
                        },
                    )
                    .unwrap();
                let key = reference(id[2], "secret-key");
                {
                    let object = session.resolve(&key).unwrap();
                    let attrs = object
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
                        Attribute::ValueLen(size.length().try_into().unwrap()),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(false),
                        Attribute::Derive(false),
                        Attribute::Encrypt(true),
                        Attribute::Decrypt(true),
                        Attribute::Sign(false),
                        Attribute::Verify(false),
                        Attribute::Wrap(false),
                        Attribute::Unwrap(false),
                    ] {
                        assert!(attrs.expose_values().contains(&attr));
                    }
                    assert!(matches!(
                        object.attribute_info(&[A::Value]).unwrap().as_slice(),
                        [AttributeInfo::Sensitive]
                    ));
                }
                assert_eq!(session.encrypt_aes_gcm(&key, &encrypt).unwrap(), ciphertext);
            }
        }
        session
            .derive_x448_key(
                &reference(1, "private"),
                &X448Derivation {
                    peer: &bob,
                    kdf: mode,
                    shared_info: &info,
                    output: X448Output::DerivationSecret,
                    id: &[0xd9, 0x48, if nist { 0x41 } else { 0x40 }],
                    label: b"X448 hashed secret",
                },
            )
            .unwrap();
    }
    // Noncanonical p+5 and canonical base point 5 must agree. For the RFC
    // Alice private fixture, the full shared value here is Alice's public key.
    let mut base_point = [0; 56];
    base_point[0] = 5;
    let mut alias = [255; 56];
    alias[..28].fill(0);
    alias[0] = 4;
    let expected_alias = kdf(&vectors::hex(vectors::ALICE_PUBLIC), &info, false);
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(vec![0xd9, 0x48, 0xee]),
            Attribute::Label(b"X448 alias reference".to_vec()),
            Attribute::Value(expected_alias[..32].to_vec()),
            Attribute::Encrypt(true),
        ])
        .unwrap();
    let alias_cipher = session
        .encrypt_aes_gcm(&reference(0xee, "secret-key"), &encrypt)
        .unwrap();
    for (index, bytes) in [base_point, alias].into_iter().enumerate() {
        let peer = X448PublicKey::from_bytes(&bytes).unwrap();
        let id = [0xd9, 0x48, 0x60 + index as u8];
        session
            .derive_x448_key(
                &reference(1, "private"),
                &X448Derivation {
                    peer: &peer,
                    kdf: X448Kdf::X963Sha512,
                    shared_info: &info,
                    output: X448Output::Aes(AesKeySize::Bits256),
                    id: &id,
                    label: b"X448 encoding alias",
                },
            )
            .unwrap();
        assert_eq!(
            session
                .encrypt_aes_gcm(&reference(id[2], "secret-key"), &encrypt)
                .unwrap(),
            alias_cipher
        );
    }
    let hkdf = Command::new(&openssl)
        .args([
            "kdf",
            "-binary",
            "-keylen",
            "32",
            "-kdfopt",
            "digest:SHA512",
            "-kdfopt",
            &format!("hexkey:{}", hex(&nist_reference)),
            "-kdfopt",
            "salt:X448 salt",
            "-kdfopt",
            "info:X448 HKDF v1",
            "HKDF",
        ])
        .output()
        .unwrap();
    assert!(hkdf.status.success());
    assert_eq!(hkdf.stdout.len(), 32);
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(vec![0xd9, 0x48, 0xef]),
            Attribute::Label(b"X448 reference HKDF".to_vec()),
            Attribute::Value(hkdf.stdout),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ])
        .unwrap();
    session
        .derive_hkdf(
            &reference(0x41, "secret-key"),
            &HkdfRequest {
                digest: DigestAlgorithm::Sha512,
                salt: b"X448 salt",
                info: b"X448 HKDF v1",
                output: HkdfOutput::Aes256,
                id: &[0xd9, 0x48, 0x51],
                label: b"X448 HKDF AES",
            },
        )
        .unwrap();
    let ciphertext = session
        .encrypt_aes_gcm(&reference(0xef, "secret-key"), &encrypt)
        .unwrap();
    assert_eq!(
        session
            .encrypt_aes_gcm(&reference(0x51, "secret-key"), &encrypt)
            .unwrap(),
        ciphertext
    );
    std::fs::write(root.join("x448-hkdf-cipher"), ciphertext).unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
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
    assert!(token.x448_generation_supported().unwrap());
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    let pin = SecretString::from("12345678");
    session
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    let request = X448KeyPairRequest {
        id: &[0xd9, 0x48, 0x90],
        label: b"generated X448",
    };
    session.generate_x448_key_pair(&request).unwrap();
    assert!(session.generate_x448_key_pair(&request).is_err());
    let public = session.x448_public_key(&reference(0x90, "public")).unwrap();
    let alice = X448PublicKey::from_bytes(&vectors::hex(vectors::ALICE_PUBLIC)).unwrap();
    session
        .import_x448_public_key(&alice, &[0xd9, 0x48, 0x91], b"imported X448")
        .unwrap();
    assert!(
        session
            .import_x448_public_key(&alice, &[0xd9, 0x48, 0x91], b"duplicate")
            .is_err()
    );
    assert_eq!(
        session.x448_public_key(&reference(0x91, "public")).unwrap(),
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
        let object = session.resolve(&reference(0x90, kind)).unwrap();
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
        let object = session.resolve(&reference(0x91, "public")).unwrap();
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
    let mut private_der = vectors::hex("3046020100300506032b656f043a0438");
    private_der.extend(vectors::hex(vectors::ALICE_PRIVATE));
    std::fs::write(root.join("generated-x448-alice.der"), private_der).unwrap();
    std::fs::write(
        root.join("generated-x448-peer.der"),
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
        .arg(root.join("generated-x448-alice.der"))
        .arg("-peerkey")
        .arg(root.join("generated-x448-peer.der"))
        .output()
        .unwrap();
    assert!(
        agreement.status.success(),
        "OpenSSL agreement: {}",
        agreement.status
    );
    assert_eq!(agreement.stdout.len(), 56);
    let mut info = b"generated X448 test v1".to_vec();
    info.extend(alice.as_bytes());
    info.extend(public.as_bytes());
    let expected = kdf(&agreement.stdout, &info, true);
    session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Id(vec![0xd9, 0x48, 0x94]),
            Attribute::Label(b"generated X448 AES reference".to_vec()),
            Attribute::Value(expected[..32].to_vec()),
            Attribute::Encrypt(true),
        ])
        .unwrap();
    session
        .derive_x448_key(
            &reference(0x90, "private"),
            &X448Derivation {
                peer: &alice,
                kdf: X448Kdf::Sp80056aSha512,
                shared_info: &info,
                output: X448Output::Aes(AesKeySize::Bits256),
                id: &[0xd9, 0x48, 0x93],
                label: b"generated X448 AES",
            },
        )
        .unwrap();
    let encrypt = AesGcmEncryptRequest {
        nonce: &[5; 12],
        aad: b"generated X448",
        plaintext: b"generated agreement proof",
    };
    assert_eq!(
        session
            .encrypt_aes_gcm(&reference(0x93, "secret-key"), &encrypt)
            .unwrap(),
        session
            .encrypt_aes_gcm(&reference(0x94, "secret-key"), &encrypt)
            .unwrap()
    );
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
