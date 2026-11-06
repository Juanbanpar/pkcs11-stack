// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official CCM layouts, no native size queries, permission and failure boundaries.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use pkcs11_runtime::*;
use secrecy::ExposeSecret;
#[test]
fn exact_capacity_empty_input_all_tables_and_failed_sessions() {
    for (version, table) in ["2.40", "3.0", "3.1", "3.2"].into_iter().enumerate() {
        for size in 0..3 {
            for fault in [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                25, 26,
            ] {
                if fault == 26 && version != 3 {
                    continue;
                }
                let fixture = fixture::MetadataModule::with_case(
                    "aes_ccm.c",
                    version * 1000 + size * 100 + fault,
                    table,
                );
                let module = Module::load(fixture.path()).unwrap();
                assert_eq!(
                    module.interface().version,
                    [
                        InterfaceVersion::V2_40,
                        InterfaceVersion::V3_0,
                        InterfaceVersion::V3_1,
                        InterfaceVersion::V3_2
                    ][version]
                );
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let key =
                    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
                        .unwrap();
                for decrypt in [false, true] {
                    for message in [b"".as_slice(), b"abc"] {
                        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                        let ciphertext = message
                            .iter()
                            .map(|b| b ^ 0x80)
                            .chain([0xef; 16])
                            .collect::<Vec<_>>();
                        let result = if decrypt {
                            session
                                .decrypt_aes_ccm(
                                    &key,
                                    &AesCcmDecryptRequest {
                                        nonce: &[0xa5; 12],
                                        aad: b"",
                                        ciphertext: &ciphertext,
                                    },
                                )
                                .map(|p| p.expose_secret().clone())
                        } else {
                            session.encrypt_aes_ccm(
                                &key,
                                &AesCcmEncryptRequest {
                                    nonce: &[0xa5; 12],
                                    aad: b"",
                                    plaintext: message,
                                },
                            )
                        };
                        let preflight = matches!(fault, 5..=9 | 12 | 15)
                            || if decrypt {
                                matches!(fault, 2 | 4 | 13 | 14)
                            } else {
                                matches!(fault, 1 | 3 | 10 | 11)
                            };
                        let native = matches!(fault, 16..=22 | 25 | 26);
                        assert_eq!(
                            result.is_err(),
                            preflight || native,
                            "{table}/{size}/{fault}/{decrypt}: {result:?}"
                        );
                        if !preflight && !native {
                            assert_eq!(
                                result.unwrap(),
                                if decrypt {
                                    message.to_vec()
                                } else {
                                    ciphertext
                                }
                            );
                        }
                        assert_eq!(session.info().is_err(), native, "{table}/{fault}/{decrypt}");
                        if !native {
                            assert_eq!(
                                session.info().unwrap().device_error(),
                                if preflight { 0 } else { (1 << 16) | 1 }
                            );
                        }
                        session.close().unwrap();
                    }
                }
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn binding_ccm_length_bounds_and_redaction() {
    use cryptoki::mechanism::aead::CcmParams;
    for nonce_length in 6..=14 {
        for tag in [0, 3, 4, 6, 8, 10, 12, 14, 16, 17] {
            let mut nonce = vec![0xa5; nonce_length];
            assert_eq!(
                CcmParams::new(0.into(), &mut nonce, b"aad", tag.into()).is_ok(),
                (7..=13).contains(&nonce_length) && [4, 6, 8, 10, 12, 14, 16].contains(&tag)
            );
        }
    }
    let mut nonce = [0; 12];
    CcmParams::new(0xffffff.into(), &mut nonce, b"", 16.into()).unwrap();
    assert!(CcmParams::new(0x1000000.into(), &mut nonce, b"", 16.into()).is_err());
    let mut nonce = [0; 13];
    assert!(CcmParams::new(0x10000.into(), &mut nonce, b"", 16.into()).is_err());
    let mut nonce = [0; 7];
    assert!(
        !format!(
            "{:?}",
            CcmParams::new(0.into(), &mut nonce, b"aad-canary", 16.into()).unwrap()
        )
        .contains("canary")
    );
}
