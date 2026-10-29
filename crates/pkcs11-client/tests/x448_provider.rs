// SPDX-License-Identifier: MIT OR Apache-2.0
//! X448 application requests against independently computed KDF references.
#[path = "../../pkcs11-runtime/tests/fixtures/x448_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::{
    AesGcmEncryptRequest, AesKeySize, Authentication, DigestAlgorithm, HkdfOutput, HkdfRequest,
    ObjectRef, Pin, Provider, SecretKeyIdentity, SessionMode, X448Kdf, X448Output, X448Peer,
    X448Request, object_reference,
};
use secrecy::SecretString;
fn reference(id: u8, kind: &str) -> ObjectRef {
    object_reference(
        format!("pkcs11:token=kdf-test;id=%D9%48%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn x448_client_export_raw_and_hashed_agreement_match_reference_ciphertexts() {
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
    assert_eq!(
        session
            .export_x448_public_key(&reference(1, "public"))
            .unwrap(),
        vectors::spki(&vectors::hex(vectors::ALICE_PUBLIC))
    );
    let peer =
        X448Peer::from_spki_der(&std::fs::read(root.join("x448-peer.der")).unwrap()).unwrap();
    let info = std::fs::read(root.join("x448-info")).unwrap();
    for (id, kdf, output, context, name) in [
        (0x70, X448Kdf::Null, X448Output::RawSecret, &[][..], None),
        (
            0x71,
            X448Kdf::X963Sha512,
            X448Output::Aes(AesKeySize::Bits256),
            info.as_slice(),
            Some("x963"),
        ),
        (
            0x72,
            X448Kdf::Sp80056aSha512,
            X448Output::Aes(AesKeySize::Bits256),
            info.as_slice(),
            Some("nist"),
        ),
        (
            0x73,
            X448Kdf::Sp80056aSha512,
            X448Output::DerivationSecret,
            info.as_slice(),
            None,
        ),
    ] {
        let id_bytes = [0xd9, 0x48, id];
        let request = X448Request {
            peer: &peer,
            kdf,
            shared_info: context,
            output,
            identity: SecretKeyIdentity {
                id: &id_bytes,
                label: b"client X448",
            },
        };
        session
            .derive_x448(&reference(1, "private"), &request)
            .unwrap();
        assert!(
            session
                .derive_x448(&reference(1, "private"), &request)
                .is_err()
        );
        session.state().unwrap();
        if let Some(name) = name {
            assert_eq!(
                session
                    .encrypt_aes_gcm(
                        &reference(id, "secret-key"),
                        &AesGcmEncryptRequest {
                            nonce: &[4; 12],
                            aad: b"X448 test",
                            plaintext: b"public X448 challenge"
                        }
                    )
                    .unwrap(),
                std::fs::read(root.join(format!("x448-{name}-cipher-32"))).unwrap()
            );
        }
    }
    session
        .derive_hkdf(
            &reference(0x73, "secret-key"),
            &HkdfRequest {
                digest: DigestAlgorithm::Sha512,
                salt: b"X448 salt",
                info: b"X448 HKDF v1",
                output: HkdfOutput::Aes256,
                id: &[0xd9, 0x48, 0x74],
                label: b"client X448 HKDF",
            },
        )
        .unwrap();
    assert_eq!(
        session
            .encrypt_aes_gcm(
                &reference(0x74, "secret-key"),
                &AesGcmEncryptRequest {
                    nonce: &[4; 12],
                    aad: b"X448 test",
                    plaintext: b"public X448 challenge"
                }
            )
            .unwrap(),
        std::fs::read(root.join("x448-hkdf-cipher")).unwrap()
    );
    session.close().unwrap();
    provider.finalize().unwrap();
}
