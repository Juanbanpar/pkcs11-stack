// SPDX-License-Identifier: MIT OR Apache-2.0
//! Existing X25519 keys through the management API and protected HKDF output.
#[path = "../../pkcs11-runtime/tests/fixtures/x25519_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::{
    AesGcmEncryptRequest, Authentication, DigestAlgorithm, HkdfOutput, HkdfRequest, ObjectRef, Pin,
    Provider, SecretKeyIdentity, SessionMode, X25519KeyPairRequest, X25519Peer, X25519Request,
    object_reference,
};
use secrecy::SecretString;
fn reference(id: u8, kind: &str) -> ObjectRef {
    object_reference(
        format!("pkcs11:token=kdf-test;id=%D9%58%{id:02X};type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn application_x25519_export_agreement_and_hkdf_match_reference_ciphertext() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("PKCS11_TEST_KDF_DIR").unwrap());
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    assert!(
        provider
            .generation_capabilities(&"pkcs11:token=kdf-test".parse().unwrap())
            .unwrap()
            .x25519
    );
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
            .export_x25519_public_key(&reference(1, "public"))
            .unwrap(),
        vectors::spki(&vectors::hex(vectors::ALICE_PUBLIC))
    );
    let peer =
        X25519Peer::from_spki_der(&std::fs::read(root.join("x25519-peer.der")).unwrap()).unwrap();
    let request = X25519Request {
        peer: &peer,
        identity: SecretKeyIdentity {
            id: &[0xd9, 0x58, 0x30],
            label: b"client X25519",
        },
    };
    session
        .derive_x25519(&reference(1, "private"), &request)
        .unwrap();
    assert!(
        session
            .derive_x25519(&reference(1, "private"), &request)
            .is_err()
    );
    session.state().unwrap();
    session
        .derive_hkdf(
            &reference(0x30, "secret-key"),
            &HkdfRequest {
                digest: DigestAlgorithm::Sha256,
                salt: &std::fs::read(root.join("x25519-salt")).unwrap(),
                info: &std::fs::read(root.join("x25519-info")).unwrap(),
                output: HkdfOutput::Aes256,
                id: &[0xd9, 0x58, 0x31],
                label: b"client X25519 HKDF",
            },
        )
        .unwrap();
    let encrypted = session
        .encrypt_aes_gcm(
            &reference(0x31, "secret-key"),
            &AesGcmEncryptRequest {
                nonce: &[1; 12],
                aad: b"X25519 test",
                plaintext: b"public X25519 challenge",
            },
        )
        .unwrap();
    assert_eq!(
        encrypted,
        std::fs::read(root.join("x25519-expected-gcm")).unwrap()
    );
    let pair = X25519KeyPairRequest {
        id: &[0xd9, 0x58, 0x60],
        label: b"client generated X25519",
    };
    session.generate_x25519_key_pair(&pair).unwrap();
    assert!(session.generate_x25519_key_pair(&pair).is_err());
    let generated = session
        .export_x25519_public_key(&reference(0x60, "public"))
        .unwrap();
    let generated_peer = X25519Peer::from_spki_der(&generated).unwrap();
    session
        .import_x25519_public_key(
            &generated_peer,
            &[0xd9, 0x58, 0x61],
            b"client imported X25519",
        )
        .unwrap();
    assert!(
        session
            .import_x25519_public_key(&generated_peer, &[0xd9, 0x58, 0x61], b"duplicate")
            .is_err()
    );
    assert_eq!(
        session
            .export_x25519_public_key(&reference(0x61, "public"))
            .unwrap(),
        generated
    );
    let bob =
        X25519Peer::from_spki_der(&vectors::spki(&vectors::hex(vectors::BOB_PUBLIC))).unwrap();
    let mut ciphers = Vec::new();
    for (base, peer, id) in [(0x60, &bob, 0x62), (2, &generated_peer, 0x64)] {
        session
            .derive_x25519(
                &reference(base, "private"),
                &X25519Request {
                    peer,
                    identity: SecretKeyIdentity {
                        id: &[0xd9, 0x58, id],
                        label: b"client generated agreement",
                    },
                },
            )
            .unwrap();
        session
            .derive_hkdf(
                &reference(id, "secret-key"),
                &HkdfRequest {
                    digest: DigestAlgorithm::Sha256,
                    salt: b"client generation test",
                    info: &generated,
                    output: HkdfOutput::Aes256,
                    id: &[0xd9, 0x58, id + 1],
                    label: b"client generated HKDF",
                },
            )
            .unwrap();
        ciphers.push(
            session
                .encrypt_aes_gcm(
                    &reference(id + 1, "secret-key"),
                    &AesGcmEncryptRequest {
                        nonce: &[3; 12],
                        aad: b"client X25519",
                        plaintext: b"generated pair agreement",
                    },
                )
                .unwrap(),
        );
    }
    assert_eq!(ciphers[0], ciphers[1]);
    session.state().unwrap();
    session.close().unwrap();
    provider.finalize().unwrap();
}
