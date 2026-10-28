// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed HMAC generation, verification and permission boundaries.
use pkcs11_client::{
    Authentication, Error, ErrorKind, HmacAlgorithm, HmacKeyRequest, HmacTagProfile, MacOperation,
    ObjectRef, Pin, Provider, SessionMode,
};
use secrecy::SecretString;
#[test]
#[ignore = "requires tools/test-softhsm.sh disposable store"]
fn hmac_client_selected_algorithm_permissions_export_and_reuse() {
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
    let options = provider.generation_capabilities(&token).unwrap().hmac;
    for required in [
        HmacAlgorithm::Sha256,
        HmacAlgorithm::Sha384,
        HmacAlgorithm::Sha512,
        HmacAlgorithm::Sha224,
    ] {
        assert!(options.contains(&required));
    }
    for (index, algorithm) in options.into_iter().enumerate() {
        let label = format!("client-hmac-{index}");
        let request = HmacKeyRequest {
            algorithm,
            id: label.as_bytes(),
            label: label.as_bytes(),
        };
        setup.generate_hmac_key(&request).unwrap();
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
            ro.generate_hmac_key(&request).unwrap_err().kind(),
            ErrorKind::Policy
        );
        assert!(ro.hkdf_options(&key).unwrap().is_empty());
        for op in [MacOperation::Generate, MacOperation::Verify] {
            let caps = ro.hmac_capabilities(&key, op).unwrap();
            assert_eq!(caps.key_length, algorithm.tag_length());
            for a in HmacAlgorithm::ALL {
                assert_eq!(caps.supports(a), a == algorithm);
            }
        }
        for message in [&[][..], b"client HMAC context"] {
            let tag = ro.mac_hmac(&key, algorithm, message).unwrap();
            assert_eq!(
                ro.hmac_reader(
                    &key,
                    algorithm,
                    HmacTagProfile::Full,
                    &mut std::io::Cursor::new(message)
                )
                .unwrap(),
                tag
            );
            ro.verify_hmac_reader(
                &key,
                algorithm,
                HmacTagProfile::Full,
                &mut std::io::Cursor::new(message),
                &tag,
            )
            .unwrap();
            ro.verify_hmac(&key, algorithm, message, &tag).unwrap();
            let mut changed = tag.clone();
            changed[0] ^= 1;
            for supplied in [&[][..], changed.as_slice(), &tag[..tag.len() - 1]] {
                assert!(matches!(
                    ro.verify_hmac(&key, algorithm, message, supplied),
                    Err(Error::MacMismatch)
                ));
                ro.state().unwrap();
                assert!(matches!(
                    ro.verify_hmac_reader(
                        &key,
                        algorithm,
                        HmacTagProfile::Full,
                        &mut std::io::Cursor::new(message),
                        supplied
                    ),
                    Err(Error::MacMismatch)
                ));
                ro.state().unwrap();
            }
            for wrong in HmacAlgorithm::ALL.into_iter().filter(|a| *a != algorithm) {
                assert_eq!(
                    ro.mac_hmac(&key, wrong, message).unwrap_err().kind(),
                    ErrorKind::Policy
                );
                ro.state().unwrap();
            }
            ro.verify_hmac(&key, algorithm, message, &tag).unwrap();
        }
        ro.close().unwrap();
        setup.delete(&key).unwrap();
    }
    setup.close().unwrap();
    provider.finalize().unwrap();
}
