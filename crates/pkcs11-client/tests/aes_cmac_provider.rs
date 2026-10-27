// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native AES-CMAC through typed client selectors.
use pkcs11_client::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, Authentication, Error, ErrorKind, MacOperation,
    ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::SecretString;
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn client_cmac_generation_verification_policy_and_reusable_mismatches() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let provider = Provider::load(std::env::var_os("PKCS11_TEST_MODULE").unwrap()).unwrap();
    let token = "pkcs11:token=client-test".parse().unwrap();
    let pin = SecretString::from("12345678");
    let mut setup = provider
        .management(
            &token,
            SessionMode::ReadWrite,
            Authentication::User(Pin::Value(&pin)),
        )
        .unwrap();
    for size in [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ] {
        let label = format!("client-cmac-{}", size.length());
        let request = AesKeyRequest {
            size,
            purpose: AesKeyPurpose::Authentication,
            id: label.as_bytes(),
            label: label.as_bytes(),
        };
        setup.generate_aes_key(&request).unwrap();
        let key = ObjectRef::new(
            format!("pkcs11:token=client-test;object={label};type=secret-key")
                .parse()
                .unwrap(),
        )
        .unwrap();
        assert!(setup.export_public(&key).is_err());
        let mut ro = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        assert_eq!(
            ro.generate_aes_key(&request).unwrap_err().kind(),
            ErrorKind::Policy
        );
        for op in [MacOperation::Generate, MacOperation::Verify] {
            assert_eq!(ro.aes_cmac_capabilities(&key, op).unwrap().key_size, size);
        }
        assert!(
            ro.aes_gcm_capabilities(&key, pkcs11_client::AesGcmOperation::Encrypt)
                .is_err()
        );
        assert!(
            ro.aes_key_wrap_options(&key, pkcs11_client::KeyOperation::Wrap)
                .is_err()
        );
        for message in [&[][..], b"client MAC message"] {
            let tag = ro.mac_aes_cmac(&key, message).unwrap();
            ro.verify_aes_cmac(&key, message, &tag).unwrap();
            let mut changed = tag;
            changed[15] ^= 1;
            for tag in [&[][..], changed.as_slice(), &[0; 17][..]] {
                assert!(matches!(
                    ro.verify_aes_cmac(&key, message, tag),
                    Err(Error::MacMismatch)
                ));
                ro.state().unwrap();
            }
            assert!(matches!(
                ro.verify_aes_cmac(&key, b"altered", &tag),
                Err(Error::MacMismatch)
            ));
            ro.verify_aes_cmac(&key, message, &tag).unwrap();
        }
        ro.close().unwrap();
        setup.delete(&key).unwrap();
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}
