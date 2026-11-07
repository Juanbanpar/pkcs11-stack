// SPDX-License-Identifier: MIT OR Apache-2.0
//! Official ChaCha20-Poly1305 layouts, no native size queries, permission and failure boundaries.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod fixture;
use pkcs11_runtime::*;
use secrecy::ExposeSecret;
#[test]
fn exact_capacity_empty_input_all_tables_and_failed_sessions() {
    for (version, table) in ["2.40", "3.0", "3.1", "3.2"].into_iter().enumerate() {
        for fault in [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25,
            26,
        ] {
            if fault == 26 && version != 3 {
                continue;
            }
            let fixture = fixture::MetadataModule::with_case(
                "chacha20_poly1305.c",
                version * 1000 + fault,
                if version == 0 { "3.0" } else { table },
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
            let key = ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap())
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
                            .decrypt_chacha20_poly1305(
                                &key,
                                &ChaCha20Poly1305DecryptRequest {
                                    nonce: &[0xa5; 12],
                                    aad: b"",
                                    ciphertext: &ciphertext,
                                },
                            )
                            .map(|p| p.expose_secret().clone())
                    } else {
                        session.encrypt_chacha20_poly1305(
                            &key,
                            &ChaCha20Poly1305EncryptRequest {
                                nonce: &[0xa5; 12],
                                aad: b"",
                                plaintext: message,
                            },
                        )
                    };
                    let preflight = matches!(fault, 5..=8 | 12)
                        || if decrypt {
                            matches!(fault, 2 | 4 | 13 | 14)
                        } else {
                            matches!(fault, 1 | 3 | 10 | 11)
                        };
                    let native = matches!(fault, 16..=22 | 25 | 26);
                    assert_eq!(
                        result.is_err(),
                        preflight || native,
                        "{table}/{fault}/{decrypt}: {result:?}"
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

#[test]
fn protected_generation_templates_gates_identity_and_failures() {
    for version in 0..4 {
        for fault in [0, 30, 31, 32, 33, 34, 35, 36] {
            let fixture = fixture::MetadataModule::with_case(
                "chacha20_poly1305.c",
                version * 1000 + 100 + fault,
                if version == 3 {
                    "3.2"
                } else if version == 2 {
                    "3.1"
                } else {
                    "3.0"
                },
            );
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let request = ChaCha20Poly1305KeyRequest {
                id: b"fresh",
                label: b"fresh",
            };
            let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
            assert!(matches!(
                ro.generate_chacha20_poly1305_key(&request),
                Err(Error::ReadWriteRequired)
            ));
            assert_eq!(ro.info().unwrap().device_error(), 0);
            ro.close().unwrap();
            let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
            let result = session.generate_chacha20_poly1305_key(&request);
            assert_eq!(result.is_err(), fault != 0, "{version}/{fault}: {result:?}");
            if fault == 36 {
                assert!(session.info().is_err());
            } else {
                assert_eq!(
                    session.info().unwrap().device_error(),
                    if fault == 0 { 1 << 24 } else { 0 }
                );
            }
            if fault == 0 {
                assert!(session.generate_chacha20_poly1305_key(&request).is_err());
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
    for (id, label) in [
        (b"".as_slice(), b"fresh".as_slice()),
        (b"fresh", b""),
        (&[1; 129], b"fresh"),
        (b"fresh", &[1; 129]),
    ] {
        assert!(ChaCha20Poly1305KeyRequest { id, label }.validate().is_err());
    }
    assert!(
        !format!(
            "{:?}",
            ChaCha20Poly1305KeyRequest {
                id: b"canary",
                label: b"canary"
            }
        )
        .contains("canary")
    );
}
