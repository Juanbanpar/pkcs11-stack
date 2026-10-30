// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client profile dispatch and protected derivation against independent references.
#[path = "../../pkcs11-runtime/tests/fixtures/montgomery_kdf_cases.rs"]
#[allow(dead_code)]
mod cases;
use pkcs11_client::{
    AesGcmEncryptRequest, AesKeySize, Authentication, DigestAlgorithm, EcdhKdf, KbkdfOutput,
    KbkdfRequest, MontgomeryKdfRequest, MontgomeryNamedCurve as C, MontgomeryNamedPeer,
    MontgomeryOutput, ObjectRef, Pin, Provider, SecretKeyIdentity, SessionMode, X448Peer,
    X25519Peer,
};
use secrecy::SecretString;
fn reference(group: u8, curve: usize, id: u8, kind: &str) -> ObjectRef {
    ObjectRef::new(cases::uri(group, curve, id, kind).parse().unwrap()).unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn client_kdfs_preserve_profile_and_output_purpose() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let pin = SecretString::from("12345678");
    let mut session = provider
        .management(
            &"pkcs11:token=kdf-test".parse().unwrap(),
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for curve in 0..4 {
        let bytes = cases::peer_input(curve);
        for kdf in 0..8 {
            for output in [1, 5] {
                let request = MontgomeryKdfRequest {
                    kdf: cases::kdf(kdf),
                    shared_info: cases::info(output),
                    output: cases::output(output),
                    identity: SecretKeyIdentity {
                        id: &[0xd9, 0x4c, curve as u8, 1],
                        label: b"client KDF key",
                    },
                };
                let base = reference(0x4b, curve, 0, "private");
                match curve {
                    0 => session.derive_x25519_with_kdf(
                        &base,
                        &X25519Peer::from_spki_der(&bytes).unwrap(),
                        &request,
                    ),
                    1 => session.derive_x448_with_kdf(
                        &base,
                        &X448Peer::from_spki_der(&bytes).unwrap(),
                        &request,
                    ),
                    _ => session.derive_named_montgomery_with_kdf(
                        &base,
                        &MontgomeryNamedPeer::from_bytes(
                            if curve == 2 {
                                C::Curve25519
                            } else {
                                C::Curve448
                            },
                            &bytes,
                        )
                        .unwrap(),
                        &request,
                    ),
                }
                .unwrap();
                let key = reference(0x4c, curve, 1, "secret-key");
                let proof_key = if output == 1 {
                    session
                        .derive_kbkdf(
                            &key,
                            &KbkdfRequest {
                                digest: DigestAlgorithm::Sha512,
                                kdf_label: b"Montgomery proof",
                                context: b"v1",
                                output: KbkdfOutput::Aes256,
                                id: &[0xd9, 0x4c, curve as u8, 2],
                                label: b"client KDF proof",
                            },
                        )
                        .unwrap();
                    reference(0x4c, curve, 2, "secret-key")
                } else {
                    reference(0x4c, curve, 1, "secret-key")
                };
                let cipher = session
                    .encrypt_aes_gcm(
                        &proof_key,
                        &AesGcmEncryptRequest {
                            nonce: &[6; 12],
                            aad: b"Montgomery KDF test",
                            plaintext: b"protected KDF proof",
                        },
                    )
                    .unwrap();
                assert_eq!(
                    cipher,
                    std::fs::read(root.join(cases::cipher_name(curve, kdf, output))).unwrap(),
                    "{curve}/{kdf}/{output}"
                );
                if output == 1 {
                    session.delete(&proof_key).unwrap();
                }
                session.delete(&key).unwrap();
            }
        }
    }
    session.close().unwrap();
    provider.finalize().unwrap();
}
