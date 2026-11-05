// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real NSS message API probe against independent NIST known answers.
#[path = "fixtures/aes_gcm_vectors.rs"]
mod vectors;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11},
    mechanism::{
        Mechanism, MechanismType, MessageParam,
        aead::{GcmMessageParams, GeneratorFunction},
    },
    object::{Attribute, KeyType, ObjectClass},
};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
#[ignore = "requires tools/test-nss.sh disposable database"]
fn nss_native_message_probe() {
    assert_eq!(
        std::env::var("PKCS11_TEST_NSS_ISOLATED").as_deref(),
        Ok("1")
    );
    let module = Pkcs11::new(std::env::var_os("PKCS11_TEST_KDF_MODULE").unwrap()).unwrap();
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    assert!(module.interface().version.major() >= 3);
    for f in [
        Function::MessageEncryptInit,
        Function::EncryptMessage,
        Function::MessageEncryptFinal,
        Function::MessageDecryptInit,
        Function::DecryptMessage,
        Function::MessageDecryptFinal,
    ] {
        assert!(module.is_fn_supported(f));
    }
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| module.get_token_info(*s).unwrap().label() == "kdf-test")
        .unwrap();
    let info = module
        .get_mechanism_info(slot, MechanismType::AES_GCM)
        .unwrap();
    assert!(info.message_encrypt() && info.message_decrypt());
    let session = module.open_rw_session(slot).unwrap();
    for v in vectors::VECTORS {
        let key = session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Value(hex(v.key)),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ])
            .unwrap();
        let original = hex(v.nonce);
        let aad = hex(v.aad);
        let plaintext = hex(v.plaintext);
        let expected = hex(v.ciphertext);
        let mut nonce = original.clone();
        let mut tag = [0; 16];
        session
            .message_encrypt_init(&Mechanism::AesGcmMessageInit, key)
            .unwrap();
        let mut ciphertext = vec![0; plaintext.len()];
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .unwrap(),
        );
        assert_eq!(
            session
                .encrypt_message_into(&mut params, &aad, &plaintext, &mut ciphertext)
                .unwrap(),
            plaintext.len()
        );
        assert_eq!(nonce, original);
        ciphertext.extend(tag);
        assert_eq!(ciphertext, expected);
        session.message_encrypt_final().unwrap();
        session
            .message_decrypt_init(&Mechanism::AesGcmMessageInit, key)
            .unwrap();
        let mut params = MessageParam::AesGcmMessage(
            GcmMessageParams::new(
                &mut nonce,
                0.into(),
                GeneratorFunction::NoGenerate,
                &mut tag,
            )
            .unwrap(),
        );
        let mut decrypted = vec![0; plaintext.len()];
        assert_eq!(
            session
                .decrypt_message_into(
                    &mut params,
                    &aad,
                    &ciphertext[..ciphertext.len() - 16],
                    &mut decrypted
                )
                .unwrap(),
            plaintext.len()
        );
        assert_eq!(decrypted, plaintext);
        session.message_decrypt_final().unwrap();
        session.destroy_object(key).unwrap();
    }
    session.close().unwrap();
    module.finalize().unwrap();
}
