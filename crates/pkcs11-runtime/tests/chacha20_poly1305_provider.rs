// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8439 known answers, independent EVP adapter and protected generated keys.
#[path = "fixtures/chacha20_poly1305_vectors.rs"]
mod vectors;
use pkcs11_runtime::*;
use secrecy::{ExposeSecret, SecretString};
use std::{path::PathBuf, process::Command};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn locator(label: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;object={label};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh isolated Kryoptic store"]
fn chacha_rfc8439_vectors_empty_large_inputs_tampering_and_generated_keys() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let module_path = PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap());
    let prefix = module_path
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("openssl");
    let helper = root.join("chacha-openssl");
    let compile = Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(prefix.join("include"))
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/chacha20_poly1305_openssl.c"),
        )
        .arg(prefix.join("lib/libcrypto.a"))
        .args(["-ldl", "-lpthread", "-o"])
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let native = root.join("chacha-parameters");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let compile = Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-I"])
        .arg(fixtures.join("headers/3.2"))
        .arg(fixtures.join("chacha20_poly1305_parameters.c"))
        .args(["-ldl", "-o"])
        .arg(&native)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let probe = Command::new(native).arg(&module_path).output().unwrap();
    assert!(
        probe.status.success(),
        "nonce-bit probe: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let module = Module::load(module_path).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    for (index, v) in vectors::VECTORS.iter().enumerate() {
        let label = format!("chacha-kat-{index}");
        setup
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::CHACHA20),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Verify(false),
                Attribute::Unwrap(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(label.as_bytes().to_vec()),
                Attribute::AllowedMechanisms(vec![MechanismType::CHACHA20_POLY1305]),
                Attribute::Value(hex(v.key)),
            ])
            .unwrap();
        let key = locator(&label);
        let nonce: [u8; 12] = hex(v.nonce).try_into().unwrap();
        let aad = hex(v.aad);
        let message = hex(v.plaintext);
        let expected = hex(v.ciphertext);
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        assert_eq!(
            session
                .chacha20_poly1305_capabilities(&key, ChaCha20Poly1305Operation::Encrypt)
                .unwrap()
                .key_length,
            v.key.len() / 2
        );
        assert!(
            session
                .aes_gcm_capabilities(&key, AesGcmOperation::Encrypt)
                .is_err()
        );
        let request = ChaCha20Poly1305EncryptRequest {
            nonce: &nonce,
            aad: &aad,
            plaintext: &message,
        };
        assert_eq!(
            session.encrypt_chacha20_poly1305(&key, &request).unwrap(),
            expected
        );
        assert_eq!(
            session
                .decrypt_chacha20_poly1305(
                    &key,
                    &ChaCha20Poly1305DecryptRequest {
                        nonce: &nonce,
                        aad: &aad,
                        ciphertext: &expected
                    }
                )
                .unwrap()
                .expose_secret(),
            &message
        );
        session.close().unwrap();
        // Native malformed ciphertext/nonce/AAD failures discard each session.
        for kind in 0..4 {
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let mut ct = expected.clone();
            let mut bad_nonce = nonce;
            let mut bad_aad = aad.clone();
            match kind {
                0 => ct[0] ^= 1,
                1 => *ct.last_mut().unwrap() ^= 1,
                2 => bad_nonce[0] ^= 1,
                _ => bad_aad[0] ^= 1,
            }
            assert!(
                session
                    .decrypt_chacha20_poly1305(
                        &key,
                        &ChaCha20Poly1305DecryptRequest {
                            nonce: &bad_nonce,
                            aad: &bad_aad,
                            ciphertext: &ct
                        }
                    )
                    .is_err()
            );
            assert!(session.info().is_err());
            session.close().unwrap();
        }
        // Empty payload/AAD, block boundaries, chunk-size boundary and the exact ChaCha20-Poly1305 length limit.
        for (case, length) in [
            0,
            1,
            15,
            16,
            17,
            64,
            65,
            65537,
            CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,
        ]
        .into_iter()
        .enumerate()
        {
            let mut nonce = [0x72; 12];
            nonce[0] = index as u8;
            nonce[1] = case as u8;
            let message = vec![0xA7; length];
            let aad = if length == CHACHA20_POLY1305_MAXIMUM_PLAINTEXT {
                vec![0x51; CHACHA20_POLY1305_MAXIMUM_AAD]
            } else if case % 2 == 0 {
                vec![]
            } else {
                vec![0x52; 33]
            };
            let aad_file = root.join("ccm.aad");
            let message_file = root.join("ccm.message");
            let out = root.join("ccm.reference");
            std::fs::write(&aad_file, &aad).unwrap();
            std::fs::write(&message_file, &message).unwrap();
            let nonce_hex = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let oracle = Command::new(&helper)
                .arg(v.key)
                .arg(&nonce_hex)
                .arg(&aad_file)
                .arg(&message_file)
                .arg(&out)
                .output()
                .unwrap();
            assert!(
                oracle.status.success(),
                "EVP {index}/{case}: {}",
                String::from_utf8_lossy(&oracle.stderr)
            );
            let expected = std::fs::read(out).unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let ct = session
                .encrypt_chacha20_poly1305(
                    &key,
                    &ChaCha20Poly1305EncryptRequest {
                        nonce: &nonce,
                        aad: &aad,
                        plaintext: &message,
                    },
                )
                .unwrap();
            assert_eq!(ct, expected, "EVP {index}/{case}");
            assert_eq!(
                session
                    .decrypt_chacha20_poly1305(
                        &key,
                        &ChaCha20Poly1305DecryptRequest {
                            nonce: &nonce,
                            aad: &aad,
                            ciphertext: &ct
                        }
                    )
                    .unwrap()
                    .expose_secret(),
                &message
            );
            session.close().unwrap();
        }
    }
    {
        let label = "chacha-generated".to_string();
        setup
            .generate_chacha20_poly1305_key(&ChaCha20Poly1305KeyRequest {
                id: label.as_bytes(),
                label: label.as_bytes(),
            })
            .unwrap();
        assert!(
            setup
                .generate_chacha20_poly1305_key(&ChaCha20Poly1305KeyRequest {
                    id: label.as_bytes(),
                    label: label.as_bytes()
                })
                .is_err()
        );
        let key = locator(&label);
        let object = setup.resolve(&key).unwrap();
        let attrs = object
            .read_attributes(&[
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Encrypt,
                AttributeType::Decrypt,
                AttributeType::Verify,
                AttributeType::Unwrap,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Sign,
                AttributeType::Wrap,
                AttributeType::Derive,
                AttributeType::AllowedMechanisms,
                AttributeType::KeyType,
                AttributeType::ValueLen,
            ])
            .unwrap();
        for attr in [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Verify(false),
            Attribute::Unwrap(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::AllowedMechanisms(vec![MechanismType::CHACHA20_POLY1305]),
            Attribute::KeyType(KeyType::CHACHA20),
            Attribute::ValueLen(32.into()),
        ] {
            assert!(attrs.expose_values().contains(&attr));
        }
        assert!(matches!(
            object
                .attribute_info(&[AttributeType::Value])
                .unwrap()
                .as_slice(),
            [AttributeInfo::Sensitive]
        ));
        let ct = setup
            .encrypt_chacha20_poly1305(
                &key,
                &ChaCha20Poly1305EncryptRequest {
                    nonce: &[0x59; 12],
                    aad: b"generated",
                    plaintext: b"protected canary",
                },
            )
            .unwrap();
        let pt = setup
            .decrypt_chacha20_poly1305(
                &key,
                &ChaCha20Poly1305DecryptRequest {
                    nonce: &[0x59; 12],
                    aad: b"generated",
                    ciphertext: &ct,
                },
            )
            .unwrap();
        assert_eq!(pt.expose_secret(), b"protected canary");
        assert!(!format!("{pt:?}").contains("canary"));
    }
    setup.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
