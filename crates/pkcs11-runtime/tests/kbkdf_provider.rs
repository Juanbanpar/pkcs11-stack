// SPDX-License-Identifier: MIT OR Apache-2.0
//! SP 800-108 derivation against a disposable Kryoptic store.
//!
//! The test proves determinism and usable output without exporting key bytes:
//! two independently derived AES keys must decrypt each other's ciphertext.

use pkcs11_runtime::{
    AES_GCM_NONCE_LENGTH, AesDecryptRequest, AesEncryptRequest, AesGcmDecryptRequest,
    AesGcmEncryptRequest, AesGcmOperation, AesMode, Attribute, Authentication, Error, KbkdfMode,
    KbkdfOutput, KbkdfPrf, KbkdfRequest, KeyType, Module, ObjectClass, ObjectRef, Pin, SessionMode,
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

fn base_template(id: &[u8]) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Id(id.to_vec()),
        Attribute::Label(id.to_vec()),
        Attribute::Value(vec![0x0B; 32]),
    ]
}

fn request<'a>(id: &'a [u8]) -> KbkdfRequest<'a> {
    KbkdfRequest {
        prf: KbkdfPrf::HmacSha256,
        kdf_label: b"kbkdf test label",
        context: b"protocol v1",
        output: KbkdfOutput::Aes256,
        id,
        label: b"kbkdf derived key",
    }
}

#[test]
#[ignore = "requires tools/test-kem-hkdf.sh disposable Kryoptic store"]
fn sp800108_modes_are_deterministic_and_usable() {
    assert_eq!(
        std::env::var("PKCS11_TEST_KDF_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Module::load(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=kdf-test".parse().unwrap())
        .unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = token.open_session(SessionMode::ReadWrite).unwrap();
    setup
        .authenticate(Authentication::User(Pin::Value(&pin)))
        .unwrap();
    setup.create_object(&base_template(b"kbkdf-base")).unwrap();
    let base = reference(b"kbkdf-base", "secret-key");
    let options = setup.kbkdf_options(&base).unwrap();
    assert!(
        options
            .iter()
            .any(|option| option.mode == KbkdfMode::Counter && option.prf == KbkdfPrf::HmacSha256)
    );
    for (mode, iv) in [
        (KbkdfMode::Counter, &[][..]),
        (KbkdfMode::Feedback, &[][..]),
        (KbkdfMode::DoublePipeline, &[][..]),
    ] {
        let first = format!("kbkdf-{mode}-a").into_bytes();
        let second = format!("kbkdf-{mode}-b").into_bytes();
        let first_request = request(&first);
        let second_request = request(&second);
        if setup
            .kbkdf_capabilities(&base, KbkdfPrf::HmacSha256, mode)
            .is_err()
        {
            continue;
        }
        setup.derive_kbkdf(&base, &first_request, mode, iv).unwrap();
        setup
            .derive_kbkdf(&base, &second_request, mode, iv)
            .unwrap();

        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let one = reference(&first, "secret-key");
        let two = reference(&second, "secret-key");
        let nonce = [7u8; AES_GCM_NONCE_LENGTH];
        let plaintext = b"deterministic SP800-108 output";
        let ciphertext = session
            .encrypt_aes_gcm(
                &one,
                &AesGcmEncryptRequest {
                    nonce: &nonce,
                    aad: b"",
                    plaintext,
                },
            )
            .unwrap();
        let recovered = session
            .decrypt_aes_gcm(
                &two,
                &AesGcmDecryptRequest {
                    nonce: &nonce,
                    aad: b"",
                    ciphertext: &ciphertext,
                },
            )
            .unwrap();
        assert_eq!(recovered.expose_secret().as_slice(), plaintext);
        session.close().unwrap();
    }

    // Counter mode rejects an external IV before any provider call.
    let id = b"kbkdf-invalid";
    assert!(matches!(
        setup.derive_kbkdf(&base, &request(id), KbkdfMode::Counter, &[0; 32]),
        Err(Error::InvalidParameters(_))
    ));
    // The derived AES key can also be used through the block-cipher wrapper.
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    let key = reference(b"kbkdf-counter-a", "secret-key");
    let iv = [3u8; 16];
    let plaintext = [9u8; 16];
    let ciphertext = session
        .encrypt_aes(
            &key,
            &AesEncryptRequest {
                mode: AesMode::Cbc,
                iv: Some(&iv),
                plaintext: &plaintext,
            },
        )
        .unwrap();
    let recovered = session
        .decrypt_aes(
            &key,
            &AesDecryptRequest {
                mode: AesMode::Cbc,
                iv: Some(&iv),
                ciphertext: &ciphertext,
            },
        )
        .unwrap();
    assert_eq!(recovered.expose_secret().as_slice(), &plaintext);
    assert!(
        session
            .aes_cipher_capabilities(&key, AesMode::Cbc, pkcs11_runtime::AesDirection::Encrypt)
            .is_ok()
    );
    assert_eq!(
        session
            .aes_gcm_capabilities(&key, AesGcmOperation::Encrypt)
            .unwrap()
            .key_size
            .length(),
        32
    );
}
