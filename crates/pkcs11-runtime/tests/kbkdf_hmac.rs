// SPDX-License-Identifier: MIT OR Apache-2.0
//! Additional standard HMAC PRFs: independent identifiers, IV lengths and policy.
#![cfg(unix)]
#[path = "fixtures/kbkdf_cmac_module.rs"]
mod fixture;
use fixture::KbkdfCmacModule;
use pkcs11_runtime::*;
const PROFILES: [(KbkdfPrf, &str, &str, usize); 5] = [
    (
        KbkdfPrf::HmacSha224,
        "CKM_SHA224_HMAC",
        "CKK_SHA224_HMAC",
        28,
    ),
    (
        KbkdfPrf::HmacSha3_224,
        "CKM_SHA3_224_HMAC",
        "CKK_SHA3_224_HMAC",
        28,
    ),
    (
        KbkdfPrf::HmacSha3_256,
        "CKM_SHA3_256_HMAC",
        "CKK_SHA3_256_HMAC",
        32,
    ),
    (
        KbkdfPrf::HmacSha3_384,
        "CKM_SHA3_384_HMAC",
        "CKK_SHA3_384_HMAC",
        48,
    ),
    (
        KbkdfPrf::HmacSha3_512,
        "CKM_SHA3_512_HMAC",
        "CKK_SHA3_512_HMAC",
        64,
    ),
];
fn base() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap()
}
fn request(prf: KbkdfPrf) -> KbkdfPrfRequest<'static> {
    KbkdfPrfRequest {
        prf,
        kdf_label: b"label",
        context: b"ctx",
        output: KbkdfOutput::Aes256,
        id: &[3],
        label: b"output",
    }
}
#[test]
fn native_prfs_modes_typed_and_generic_keys_with_independent_headers() {
    for minor in [0, 1, 2] {
        for (prf, mechanism, typed, length) in PROFILES {
            for key_type in [typed, "CKK_GENERIC_SECRET"] {
                for (fault, mode) in [
                    (0, KbkdfMode::Counter),
                    (20, KbkdfMode::Feedback),
                    (40, KbkdfMode::DoublePipeline),
                ] {
                    let fixture =
                        KbkdfCmacModule::hmac(3, minor, fault, mechanism, key_type, length);
                    let module = Module::load(fixture.path()).unwrap();
                    let token = module
                        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                        .unwrap();
                    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                    let caps = session.kbkdf_prf_capabilities(&base(), prf, mode).unwrap();
                    assert_eq!(caps.input_length, 31);
                    assert_eq!(caps.prf, prf);
                    assert_eq!(caps.mode, mode);
                    assert_eq!(prf.output_len(), length);
                    if key_type != "CKK_GENERIC_SECRET" {
                        // Equal output lengths never make typed HMAC keys interchangeable.
                        for (other, ..) in PROFILES {
                            if other != prf {
                                assert!(matches!(
                                    session.kbkdf_prf_capabilities(&base(), other, mode),
                                    Err(Error::UnsupportedKeyOperation)
                                ));
                            }
                        }
                        assert!(session.kbkdf_capabilities_with_mode(&base(), mode).is_err());
                    }
                    session
                        .derive_kbkdf_prf(&base(), &request(prf), mode, &[])
                        .unwrap();
                    if mode == KbkdfMode::Feedback {
                        session
                            .derive_kbkdf_prf(&base(), &request(prf), mode, &vec![0xA5; length])
                            .unwrap();
                    }
                    session
                        .derive_kbkdf_prf(
                            &base(),
                            &KbkdfPrfRequest {
                                kdf_label: &[],
                                context: &[],
                                ..request(prf)
                            },
                            mode,
                            &[],
                        )
                        .unwrap();
                    session.info().unwrap();
                    session.close().unwrap();
                    drop(token);
                    module.finalize().unwrap();
                }
            }
        }
    }
}
#[test]
fn permissions_bit_bounds_missing_pointers_and_native_failures_remain_checked() {
    for (prf, mechanism, typed, length) in PROFILES {
        for fault in [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 15] {
            let fixture = KbkdfCmacModule::hmac(3, 2, fault, mechanism, typed, length);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
            assert!(
                session
                    .derive_kbkdf_prf(&base(), &request(prf), KbkdfMode::Counter, &[])
                    .is_err()
            );
            assert_eq!(session.info().is_ok(), fault != 5);
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
#[test]
fn feedback_requires_the_selected_prf_output_length_and_legacy_profiles_stay_restricted() {
    for (prf, _, _, length) in PROFILES {
        for mode in KbkdfMode::ALL {
            for n in [0, 1, 27, 28, 29, 31, 32, 33, 47, 48, 49, 63, 64, 65] {
                assert_eq!(
                    request(prf).validate_with_mode(mode, &vec![0; n]).is_ok(),
                    n == 0 || (mode == KbkdfMode::Feedback && n == length)
                );
            }
        }
    }
    for digest in [
        DigestAlgorithm::Sha224,
        DigestAlgorithm::Sha3_224,
        DigestAlgorithm::Sha3_256,
        DigestAlgorithm::Sha3_384,
        DigestAlgorithm::Sha3_512,
    ] {
        assert!(KbkdfPrf::try_from(digest).is_err());
    }
}
