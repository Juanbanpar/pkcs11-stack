// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client generation, protected policy and agreement with runtime reference keys.
use pkcs11_client::*;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
fn key(id: &[u8]) -> ObjectRef {
    let id: String = id.iter().map(|b| format!("%{b:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type=secret-key")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires isolated tools/test-kem-hkdf.sh provider"]
fn pbkdf2_client_permissions_readonly_duplicates_and_runtime_agreement() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let pin = SecretString::from("12345678");
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let mut s = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    assert!(s.pbkdf2_supported().unwrap());
    let password = SecretSlice::from(vec![b'p', 0, 0xff, b'\n']);
    for (i, prf) in Pbkdf2Prf::ALL.into_iter().enumerate() {
        for (case, output) in [
            Pbkdf2Output::Aes256,
            Pbkdf2Output::DerivationSecret { length: 65 },
        ]
        .into_iter()
        .enumerate()
        {
            let id = [0xFA, 0xB3, i as u8, case as u8];
            let request = Pbkdf2Request {
                password: &password,
                salt: b"salt",
                prf,
                iterations: 2,
                output,
                id: &id,
                label: b"client PBKDF2",
            };
            let mut ro = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            assert!(ro.pbkdf2_supported().unwrap());
            assert_eq!(
                ro.generate_pbkdf2(&request).unwrap_err().kind(),
                ErrorKind::Policy
            );
            ro.close().unwrap();
            s.generate_pbkdf2(&request).unwrap();
            assert_eq!(
                s.generate_pbkdf2(&request).unwrap_err().kind(),
                ErrorKind::Input
            );
            s.state().unwrap();
            let generic = case == 1;
            let derived = key(&id);
            let attrs = s
                .inspect(
                    &derived,
                    &[
                        AttributeType::Token,
                        AttributeType::Private,
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Sign,
                        AttributeType::Verify,
                        AttributeType::Wrap,
                        AttributeType::Unwrap,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                        AttributeType::Derive,
                    ],
                )
                .unwrap();
            for expected in [
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(false),
                Attribute::Verify(false),
                Attribute::Wrap(false),
                Attribute::Unwrap(false),
                Attribute::Encrypt(!generic),
                Attribute::Decrypt(!generic),
                Attribute::Derive(generic),
            ] {
                assert!(attrs.iter().any(|a| {
                    a.values
                        .as_ref()
                        .is_some_and(|v| v.expose_values().contains(&expected))
                }));
            }
            if generic {
                assert_eq!(s.kbkdf_capabilities(&derived).unwrap().input_length, 65);
            } else {
                let nonce = [i as u8; 12];
                let ciphertext = s
                    .encrypt_aes_gcm(
                        &derived,
                        &AesGcmEncryptRequest {
                            nonce: &nonce,
                            aad: b"PBKDF2 proof",
                            plaintext: b"client agreement",
                        },
                    )
                    .unwrap();
                let plaintext = s
                    .decrypt_aes_gcm(
                        &key(&[0xFA, 0xB0, i as u8]),
                        &AesGcmDecryptRequest {
                            nonce: &nonce,
                            aad: b"PBKDF2 proof",
                            ciphertext: &ciphertext,
                        },
                    )
                    .unwrap();
                assert_eq!(plaintext.expose_secret(), b"client agreement");
            }
            s.delete(&derived).unwrap();
        }
    }
    s.close().unwrap();
    provider.finalize().unwrap();
}
