// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit AES-CMAC KDF native layout and policy across independent 3.x headers.
#![cfg(unix)]
#[path = "fixtures/kbkdf_cmac_module.rs"]
mod fixture;
use fixture::KbkdfCmacModule;
use pkcs11_runtime::*;
fn base() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
fn request() -> KbkdfPrfRequest<'static> {
    KbkdfPrfRequest {
        prf: KbkdfPrf::AesCmac,
        kdf_label: b"label",
        context: b"ctx",
        output: KbkdfOutput::Aes256,
        id: &[3],
        label: b"output",
    }
}
#[test]
fn all_aes_sizes_modes_native_parameters_and_omitted_or_block_length_feedback_iv() {
    for minor in [0, 1, 2] {
        for length in [16, 24, 32] {
            for (fault, mode) in [
                (0, KbkdfMode::Counter),
                (20, KbkdfMode::Feedback),
                (40, KbkdfMode::DoublePipeline),
            ] {
                let fixture = KbkdfCmacModule::new(3, minor, fault, length);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                let caps = session
                    .kbkdf_prf_capabilities(&base(), KbkdfPrf::AesCmac, mode)
                    .unwrap();
                assert_eq!(caps.input_length, length);
                assert_eq!(caps.prf, KbkdfPrf::AesCmac);
                assert_eq!(caps.mode, mode);
                // Legacy discovery remains HMAC-only; no reinterpretation of AES keys.
                assert!(matches!(
                    session.kbkdf_capabilities_with_mode(&base(), mode),
                    Err(Error::UnsupportedKeyOperation)
                ));
                for candidate in KbkdfMode::ALL {
                    if candidate != mode {
                        assert!(
                            session
                                .kbkdf_prf_capabilities(&base(), KbkdfPrf::AesCmac, candidate)
                                .is_err()
                        );
                    }
                }
                session
                    .derive_kbkdf_prf(&base(), &request(), mode, &[])
                    .unwrap();
                if mode == KbkdfMode::Feedback {
                    session
                        .derive_kbkdf_prf(&base(), &request(), mode, &[0xA5; 16])
                        .unwrap();
                }
                session
                    .derive_kbkdf_prf(
                        &base(),
                        &KbkdfPrfRequest {
                            kdf_label: &[],
                            context: &[],
                            ..request()
                        },
                        mode,
                        &[],
                    )
                    .unwrap();
                assert!(
                    !format!(
                        "{:?}",
                        KbkdfPrfRequest {
                            kdf_label: b"redaction-canary",
                            ..request()
                        }
                    )
                    .contains("canary")
                );
                session.info().unwrap();
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn policy_bit_bounds_key_type_and_invalid_aes_lengths_fail_without_derivation() {
    for mode in KbkdfMode::ALL {
        let offset = match mode {
            KbkdfMode::Counter => 0,
            KbkdfMode::Feedback => 20,
            KbkdfMode::DoublePipeline => 40,
        };
        for fault in [1, 2, 3, 4, 6, 7, 8, 12, 13, 14, 15, 16] {
            let fixture = KbkdfCmacModule::new(3, 2, offset + fault, 32);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
            assert!(
                session
                    .derive_kbkdf_prf(&base(), &request(), mode, &[])
                    .is_err(),
                "fault {fault}"
            );
            session.info().unwrap();
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn native_derivation_failure_discards_while_token_query_failure_propagates() {
    for mode in KbkdfMode::ALL {
        let offset = match mode {
            KbkdfMode::Counter => 0,
            KbkdfMode::Feedback => 20,
            KbkdfMode::DoublePipeline => 40,
        };
        for fault in [5, 9] {
            let fixture = KbkdfCmacModule::new(3, 2, offset + fault, 32);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
            assert!(
                session
                    .derive_kbkdf_prf(&base(), &request(), mode, &[])
                    .is_err()
            );
            if fault == 5 {
                assert!(session.info().is_err());
            } else {
                session.info().unwrap();
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn request_bounds_and_iv_contracts_are_checked_without_provider_access() {
    let request = request();
    for mode in KbkdfMode::ALL {
        request.validate_with_mode(mode, &[]).unwrap();
        for length in [1, 15, 16, 17, 32, 64] {
            assert_eq!(
                request.validate_with_mode(mode, &vec![0; length]).is_ok(),
                mode == KbkdfMode::Feedback && length == 16
            );
        }
    }
    for bad in [
        KbkdfPrfRequest { id: b"", ..request },
        KbkdfPrfRequest {
            label: &[0; 129],
            ..request
        },
        KbkdfPrfRequest {
            kdf_label: &[0; 4097],
            ..request
        },
        KbkdfPrfRequest {
            context: &[0; 4097],
            ..request
        },
        KbkdfPrfRequest {
            output: KbkdfOutput::DerivationSecret { length: 0 },
            ..request
        },
        KbkdfPrfRequest {
            output: KbkdfOutput::DerivationSecret { length: 4097 },
            ..request
        },
    ] {
        assert!(bad.validate().is_err());
    }
}
