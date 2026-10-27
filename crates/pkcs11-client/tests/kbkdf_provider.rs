// SPDX-License-Identifier: MIT OR Apache-2.0
//! Counter-mode client permissions and agreement with runtime reference keys.
use pkcs11_client::{
    AesGcmDecryptRequest, AesGcmEncryptRequest, Attribute, AttributeType, Authentication,
    DigestAlgorithm, ErrorKind, KbkdfOutput, KbkdfRequest, ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::{ExposeSecret, SecretString};
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
#[ignore = "requires tools/test-kem-hkdf.sh SP800-108 provider"]
fn client_counter_kdf_permissions_outputs_and_runtime_agreement() {
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
    for (index, digest) in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .enumerate()
    {
        let base = key(&[0xA0, index as u8]);
        let caps = session.kbkdf_capabilities(&base).unwrap();
        assert_eq!(caps.input_length, digest.output_len());
        for (case, output) in [
            KbkdfOutput::Aes256,
            KbkdfOutput::DerivationSecret { length: 32 },
        ]
        .into_iter()
        .enumerate()
        {
            let id = [0xFA, 0x86, index as u8, case as u8];
            let request = KbkdfRequest {
                digest,
                kdf_label: b"application",
                context: b"v1 context",
                output,
                id: &id,
                label: b"client counter key",
            };
            let mut ro = provider
                .management(&token, SessionMode::ReadOnly, Authentication::None)
                .unwrap();
            assert_eq!(ro.kbkdf_capabilities(&base).unwrap(), caps);
            assert_eq!(
                ro.derive_kbkdf(&base, &request).unwrap_err().kind(),
                ErrorKind::Policy
            );
            ro.close().unwrap();
            session.derive_kbkdf(&base, &request).unwrap();
            assert_eq!(
                session.derive_kbkdf(&base, &request).unwrap_err().kind(),
                ErrorKind::Input
            );
            session.state().unwrap();
            let derived = key(&id);
            assert!(session.export_public(&derived).is_err());
            let attrs = session
                .inspect(
                    &derived,
                    &[
                        AttributeType::Derive,
                        AttributeType::Sign,
                        AttributeType::Verify,
                        AttributeType::Sensitive,
                        AttributeType::Extractable,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                    ],
                )
                .unwrap();
            let generic = matches!(output, KbkdfOutput::DerivationSecret { .. });
            for expected in [
                Attribute::Derive(generic),
                Attribute::Sign(false),
                Attribute::Verify(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(!generic),
                Attribute::Decrypt(!generic),
            ] {
                assert!(attrs.iter().any(|a| {
                    a.values
                        .as_ref()
                        .is_some_and(|v| v.expose_values().contains(&expected))
                }));
            }
            if generic {
                assert!(
                    session
                        .kbkdf_capabilities(&derived)
                        .unwrap()
                        .supports(DigestAlgorithm::Sha512)
                );
                assert_eq!(
                    session
                        .hkdf_capabilities(&derived, DigestAlgorithm::Sha256)
                        .unwrap()
                        .input_length,
                    32
                );
            } else {
                let nonce = [index as u8; 12];
                let ciphertext = session
                    .encrypt_aes_gcm(
                        &derived,
                        &AesGcmEncryptRequest {
                            nonce: &nonce,
                            aad: b"counter proof",
                            plaintext: b"client counter agreement",
                        },
                    )
                    .unwrap();
                let recovered = session
                    .decrypt_aes_gcm(
                        &key(&[0xFA, 0x82, index as u8]),
                        &AesGcmDecryptRequest {
                            nonce: &nonce,
                            aad: b"counter proof",
                            ciphertext: &ciphertext,
                        },
                    )
                    .unwrap();
                assert_eq!(recovered.expose_secret(), b"client counter agreement");
                assert_eq!(
                    session.kbkdf_capabilities(&derived).unwrap_err().kind(),
                    ErrorKind::Policy
                );
            }
            session.delete(&derived).unwrap();
        }
        session.kbkdf_capabilities(&base).unwrap();
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}
