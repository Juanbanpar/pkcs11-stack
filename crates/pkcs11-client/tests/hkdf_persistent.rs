// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client-only selectors and typed requests against a disposable Kryoptic token.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, Attribute, AttributeType, Authentication,
    DigestAlgorithm, ErrorKind, HkdfOutput, HkdfRequest, MlKemParameterSet, MlKemRequest,
    ObjectRef, Pin, PrivateKeyRef, Provider, PublicKeyRef, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};

fn reference(id: &[u8], kind: &str) -> ObjectRef {
    let id: String = id.iter().map(|byte| format!("%{byte:02X}")).collect();
    ObjectRef::new(
        format!("pkcs11:token=kdf-test;id={id};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn client_ml_kem_to_hkdf_permissions_errors_and_cleanup() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=kdf-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for (index, parameter) in [
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
        MlKemParameterSet::MlKem1024,
    ]
    .into_iter()
    .enumerate()
    {
        let id = [0xC0, index as u8];
        session
            .generate_ml_kem_key_pair(parameter, &id, b"client KEM recipient")
            .unwrap();
        let public =
            PublicKeyRef::new(reference(&id, "public").uri().to_string().parse().unwrap()).unwrap();
        let private =
            PrivateKeyRef::new(reference(&id, "private").uri().to_string().parse().unwrap())
                .unwrap();
        let ciphertext = session
            .encapsulate_ml_kem(
                &public,
                &MlKemRequest {
                    parameter_set: parameter,
                    id: &[0xC1, index as u8, 0],
                    label: b"client sender",
                },
            )
            .unwrap();
        session
            .decapsulate_ml_kem(
                &private,
                &MlKemRequest {
                    parameter_set: parameter,
                    id: &[0xC1, index as u8, 1],
                    label: b"client receiver",
                },
                &ciphertext,
            )
            .unwrap();
        let mut encrypted = None;
        for direction in 0..=1 {
            let base = reference(&[0xC1, index as u8, direction], "secret-key");
            assert_eq!(
                session
                    .hkdf_capabilities(&base, DigestAlgorithm::Sha256)
                    .unwrap()
                    .input_length,
                32
            );
            assert_eq!(
                session
                    .hkdf_capabilities(&base, DigestAlgorithm::Sha384)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Policy
            );
            let id = [0xC2, index as u8, direction];
            let request = HkdfRequest {
                digest: DigestAlgorithm::Sha256,
                salt: b"client public salt",
                info: b"client protocol v1",
                output: HkdfOutput::Aes256,
                id: &id,
                label: b"client encryption key",
            };
            assert_eq!(
                session
                    .derive_hkdf(
                        &base,
                        &HkdfRequest {
                            output: HkdfOutput::DerivationSecret { length: 0 },
                            ..request
                        }
                    )
                    .unwrap_err()
                    .kind(),
                ErrorKind::Input
            );
            session.derive_hkdf(&base, &request).unwrap();
            assert_eq!(
                session.derive_hkdf(&base, &request).unwrap_err().kind(),
                ErrorKind::Input
            );
            let derived = reference(&id, "secret-key");
            let attrs = session
                .inspect(
                    &derived,
                    &[
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                        AttributeType::Derive,
                    ],
                )
                .unwrap();
            for expected in [
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Derive(false),
            ] {
                assert!(attrs.iter().any(|entry| {
                    entry
                        .values
                        .as_ref()
                        .is_some_and(|values| values.expose_values().contains(&expected))
                }));
            }
            assert!(session.export_public(&derived).is_err());
            assert!(session.export_value(&derived).is_err());
            if direction == 0 {
                encrypted = Some(
                    session
                        .encrypt_aes_gcm(
                            &derived,
                            &AesGcmEncryptRequest {
                                nonce: &[0x73; 12],
                                aad: b"client key exchange v1",
                                plaintext: b"client KEM HKDF GCM canary",
                            },
                        )
                        .unwrap(),
                );
            } else {
                let plaintext = session
                    .decrypt_aes_gcm(
                        &derived,
                        &AesGcmDecryptRequest {
                            nonce: &[0x73; 12],
                            aad: b"client key exchange v1",
                            ciphertext: encrypted.as_ref().unwrap(),
                        },
                    )
                    .unwrap();
                assert_eq!(plaintext.expose_secret(), b"client KEM HKDF GCM canary");
                assert!(!format!("{plaintext:?}").contains("canary"));
            }
            session.delete(&derived).unwrap();
            session.delete(&base).unwrap();
        }
        session.delete(private.as_object_ref()).unwrap();
        session.delete(public.as_object_ref()).unwrap();
    }
    let classical = reference(&[0xF1, 0], "secret-key");
    let pq = reference(&[0xF3, 0], "secret-key");
    let hybrid = HkdfRequest {
        digest: DigestAlgorithm::Sha512,
        salt: b"client salt",
        info: b"client hybrid protocol v1",
        output: HkdfOutput::Aes256,
        id: &[0xF8],
        label: b"client hybrid key",
    };
    assert_eq!(
        session
            .derive_hybrid_hkdf(
                &classical,
                &pq,
                &HkdfRequest {
                    digest: DigestAlgorithm::Sha256,
                    ..hybrid
                }
            )
            .unwrap_err()
            .kind(),
        ErrorKind::Input
    );
    session
        .derive_hybrid_hkdf(&classical, &pq, &hybrid)
        .unwrap();
    assert_eq!(
        session
            .derive_hybrid_hkdf(&classical, &pq, &hybrid)
            .unwrap_err()
            .kind(),
        ErrorKind::Input
    );
    let derived = reference(&[0xF8], "secret-key");
    assert!(session.export_value(&derived).is_err());
    let ciphertext = session
        .encrypt_aes_gcm(
            &derived,
            &AesGcmEncryptRequest {
                nonce: &[0x74; 12],
                aad: b"hybrid transcript",
                plaintext: b"hybrid GCM canary",
            },
        )
        .unwrap();
    let plaintext = session
        .decrypt_aes_gcm(
            &derived,
            &AesGcmDecryptRequest {
                nonce: &[0x74; 12],
                aad: b"hybrid transcript",
                ciphertext: &ciphertext,
            },
        )
        .unwrap();
    assert_eq!(plaintext.expose_secret(), b"hybrid GCM canary");
    session.delete(&derived).unwrap();
    session.close().unwrap();
    let mut ro = provider
        .management(
            &token,
            SessionMode::ReadOnly,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    assert_eq!(
        ro.derive_hkdf(
            &reference(b"missing", "secret-key"),
            &HkdfRequest {
                digest: DigestAlgorithm::Sha256,
                salt: &[],
                info: &[],
                output: HkdfOutput::Aes128,
                id: b"read-only",
                label: b"read-only"
            }
        )
        .unwrap_err()
        .kind(),
        ErrorKind::Policy
    );
    ro.close().unwrap();
    provider.finalize().unwrap();
}
