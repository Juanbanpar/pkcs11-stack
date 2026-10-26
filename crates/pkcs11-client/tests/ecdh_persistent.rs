// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent ECDH/KDF calculations against a disposable Kryoptic token.
use pkcs11_client::{
    AesGcmEncryptRequest, AesKeySize, Authentication, DigestAlgorithm, EcdhKdf, EcdhKeyPairRequest,
    EcdhOutput, EcdhPeer, EcdhRequest, Error, HkdfOutput, HkdfRequest, NamedCurve, ObjectRef, Pin,
    Provider, SecretKeyIdentity, SessionMode,
};
use pkcs11_runtime::{Attribute, AttributeInfo, AttributeType, KeyType, Module, ObjectClass};
use secrecy::SecretString;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{path::PathBuf, process::Command};

fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn openssl(args: &[&str]) -> Vec<u8> {
    let output = Command::new(std::env::var("PKCS11_TEST_KDF_OPENSSL").unwrap())
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "OpenSSL failed: {}", output.status);
    output.stdout
}
fn hash(digest: DigestAlgorithm, input: &[u8]) -> Vec<u8> {
    match digest {
        DigestAlgorithm::Sha256 => Sha256::digest(input).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(input).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(input).to_vec(),
    }
}
fn x963_or_sp800(kdf: EcdhKdf, secret: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let (digest, counter_first) = match kdf {
        EcdhKdf::X963(digest) => (digest, false),
        EcdhKdf::Sp80056a(digest) => (digest, true),
        EcdhKdf::Null => panic!("expected a hash KDF"),
    };
    let mut output = Vec::new();
    for counter in 1u32.. {
        let mut block = Vec::new();
        if counter_first {
            block.extend_from_slice(&counter.to_be_bytes());
        }
        block.extend_from_slice(secret);
        if !counter_first {
            block.extend_from_slice(&counter.to_be_bytes());
        }
        block.extend_from_slice(info);
        output.extend_from_slice(&hash(digest, &block));
        if output.len() >= length {
            output.truncate(length);
            return output;
        }
    }
    unreachable!()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn sha2_ecdh_profiles_match_independent_ecdh_and_kdf_calculations() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap()).join("ecdh");
    std::fs::create_dir(&root).unwrap();
    let path = std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap();
    let provider = Provider::load(&path).unwrap();
    let token_uri = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let auth = || Authentication::User(Pin::Value(&pin));
    let mut session = provider
        .management(&token_uri, SessionMode::ReadWrite, auth())
        .unwrap();
    let mut comparisons = Vec::new();
    let mut created = Vec::new();
    let message = b"independent ECDH KDF proof";
    // Repeated nonces here compare independently derived test keys only.
    let challenge = AesGcmEncryptRequest {
        nonce: &[0xEC; 12],
        aad: b"ECDH test",
        plaintext: message,
    };
    for (curve_index, (curve, name)) in [
        (NamedCurve::P256, "prime256v1"),
        (NamedCurve::P384, "secp384r1"),
        (NamedCurve::P521, "secp521r1"),
    ]
    .into_iter()
    .enumerate()
    {
        let base_id = [0xE5, curve_index as u8];
        session
            .generate_ecdh_key_pair(&EcdhKeyPairRequest {
                curve,
                id: &base_id,
                label: b"ECDH KDF base",
            })
            .unwrap();
        created.extend([(base_id.to_vec(), "public"), (base_id.to_vec(), "private")]);
        let base = reference(&base_id, "private");
        let public = root.join(format!("{curve_index}-token.der"));
        std::fs::write(
            &public,
            session
                .export_public(&reference(&base_id, "public"))
                .unwrap(),
        )
        .unwrap();
        let private = root.join(format!("{curve_index}-peer.key"));
        let peer_public = root.join(format!("{curve_index}-peer.der"));
        openssl(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            &format!("ec_paramgen_curve:{name}"),
            "-out",
            private.to_str().unwrap(),
        ]);
        openssl(&[
            "pkey",
            "-in",
            private.to_str().unwrap(),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            peer_public.to_str().unwrap(),
        ]);
        let peer = EcdhPeer::from_spki_der(&std::fs::read(&peer_public).unwrap()).unwrap();
        let secret = openssl(&[
            "pkeyutl",
            "-derive",
            "-inkey",
            private.to_str().unwrap(),
            "-peerkey",
            public.to_str().unwrap(),
            "-peerform",
            "DER",
        ]);
        assert_eq!(secret.len(), EcdhOutput::RawSecret.length(curve));
        let raw_id = [0xE5, curve_index as u8, 0xFF];
        session
            .derive_ecdh(
                &base,
                &EcdhRequest {
                    peer: &peer,
                    kdf: EcdhKdf::Null,
                    shared_info: &[],
                    output: EcdhOutput::RawSecret,
                    identity: SecretKeyIdentity {
                        id: &raw_id,
                        label: b"complete raw secret",
                    },
                },
            )
            .unwrap();
        created.push((raw_id.to_vec(), "secret-key"));
        if curve == NamedCurve::P521 {
            assert!(
                session
                    .hkdf_options(&reference(&raw_id, "secret-key"))
                    .unwrap()
                    .is_empty()
            );
        }
        for (index, kdf) in [
            EcdhKdf::X963(DigestAlgorithm::Sha256),
            EcdhKdf::X963(DigestAlgorithm::Sha384),
            EcdhKdf::X963(DigestAlgorithm::Sha512),
            EcdhKdf::Sp80056a(DigestAlgorithm::Sha256),
            EcdhKdf::Sp80056a(DigestAlgorithm::Sha384),
            EcdhKdf::Sp80056a(DigestAlgorithm::Sha512),
        ]
        .into_iter()
        .enumerate()
        {
            let id = [0xE6, curve_index as u8, index as u8];
            let size = [
                AesKeySize::Bits128,
                AesKeySize::Bits192,
                AesKeySize::Bits256,
            ][index % 3];
            let info = b"protocol v1\0both peers and transcript";
            let request = EcdhRequest {
                peer: &peer,
                kdf,
                shared_info: info,
                output: EcdhOutput::Aes(size),
                identity: SecretKeyIdentity {
                    id: &id,
                    label: b"ECDH AES output",
                },
            };
            if index == 0 {
                let mut ro = provider
                    .management(&token_uri, SessionMode::ReadOnly, Authentication::None)
                    .unwrap();
                assert!(ro.derive_ecdh(&base, &request).is_err());
                ro.close().unwrap();
            }
            session.derive_ecdh(&base, &request).unwrap();
            assert!(session.derive_ecdh(&base, &request).is_err());
            session.state().unwrap();
            created.push((id.to_vec(), "secret-key"));
            let output = reference(&id, "secret-key");
            assert!(matches!(
                session.export_public(&output),
                Err(Error::UnsupportedExport)
            ));
            let actual = session.encrypt_aes_gcm(&output, &challenge).unwrap();
            comparisons.push((
                id.to_vec(),
                size,
                x963_or_sp800(kdf, &secret, info, size.length()),
                actual,
            ));
            // A 64-byte generic output exercises multiple SHA-256/384 KDF blocks,
            // then feeds a standard hash-length HKDF base (including on P-521).
            let generic_id = [0xE7, curve_index as u8, index as u8];
            session
                .derive_ecdh(
                    &base,
                    &EcdhRequest {
                        output: EcdhOutput::DerivationSecret { length: 64 },
                        identity: SecretKeyIdentity {
                            id: &generic_id,
                            label: b"ECDH HKDF base",
                        },
                        ..request
                    },
                )
                .unwrap();
            created.push((generic_id.to_vec(), "secret-key"));
            let generic = reference(&generic_id, "secret-key");
            assert_eq!(
                session.hkdf_options(&generic).unwrap()[0].digest,
                DigestAlgorithm::Sha512
            );
            let expanded_id = [0xE8, curve_index as u8, index as u8];
            session
                .derive_hkdf(
                    &generic,
                    &HkdfRequest {
                        digest: DigestAlgorithm::Sha512,
                        salt: b"salt",
                        info: b"info",
                        output: HkdfOutput::Aes256,
                        id: &expanded_id,
                        label: b"ECDH to HKDF AES",
                    },
                )
                .unwrap();
            created.push((expanded_id.to_vec(), "secret-key"));
            let input = x963_or_sp800(kdf, &secret, info, 64);
            let expected = openssl(&[
                "kdf",
                "-keylen",
                "32",
                "-kdfopt",
                "digest:SHA512",
                "-kdfopt",
                &format!("hexkey:{}", hex(&input)),
                "-kdfopt",
                "salt:salt",
                "-kdfopt",
                "info:info",
                "-binary",
                "HKDF",
            ]);
            let actual = session
                .encrypt_aes_gcm(&reference(&expanded_id, "secret-key"), &challenge)
                .unwrap();
            comparisons.push((expanded_id.to_vec(), AesKeySize::Bits256, expected, actual));
        }
    }
    session.close().unwrap();
    provider.finalize().unwrap();
    // Test-only reference key import lets AES-GCM compare keys without ever
    // making the production-derived keys extractable or granting them new uses.
    let module = Module::load(path).unwrap();
    let token = module.resolve_token_uri(&token_uri).unwrap();
    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
    session.authenticate(auth()).unwrap();
    for (index, (id, size, expected, actual)) in comparisons.into_iter().enumerate() {
        let key = session.resolve(&reference(&id, "secret-key")).unwrap();
        let attrs = key
            .read_attributes(&[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Encrypt,
                AttributeType::Decrypt,
                AttributeType::Derive,
                AttributeType::Sign,
                AttributeType::Verify,
                AttributeType::Wrap,
                AttributeType::Unwrap,
                AttributeType::ValueLen,
            ])
            .unwrap();
        for expected in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Derive(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::ValueLen(size.length().try_into().unwrap()),
        ] {
            assert!(attrs.expose_values().contains(&expected));
        }
        assert!(matches!(
            key.attribute_info(&[AttributeType::Value])
                .unwrap()
                .as_slice(),
            [AttributeInfo::Sensitive]
        ));
        let expected_id = format!("ecdh-reference-{index}").into_bytes();
        session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Id(expected_id.clone()),
                Attribute::Value(expected),
            ])
            .unwrap();
        created.push((expected_id.clone(), "secret-key"));
        assert_eq!(
            session
                .encrypt_aes_gcm(&reference(&expected_id, "secret-key"), &challenge)
                .unwrap(),
            actual
        );
    }
    for (id, kind) in created {
        session
            .resolve(&reference(&id, kind))
            .unwrap()
            .destroy()
            .unwrap();
    }
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
