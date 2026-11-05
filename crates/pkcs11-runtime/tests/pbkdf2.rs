// SPDX-License-Identifier: MIT OR Apache-2.0
//! Corrected PBKDF2 layout and protected output policy against independent headers.
#![cfg(unix)]
#[path = "fixtures/pbkdf2_module.rs"]
mod fixture;
use fixture::Pbkdf2Module;
use pkcs11_runtime::*;
use secrecy::SecretSlice;
fn request(password: &SecretSlice<u8>) -> Pbkdf2Request<'_> {
    Pbkdf2Request {
        password,
        salt: b"salt",
        prf: Pbkdf2Prf::HmacSha256,
        iterations: 2,
        output: Pbkdf2Output::Aes256,
        id: &[3],
        label: b"output",
    }
}
#[test]
fn corrected_layout_all_sha2_prfs_and_output_permissions_on_all_headers() {
    for (major, minor) in [(2, 40), (3, 0), (3, 1), (3, 2)] {
        for (prf, name) in Pbkdf2Prf::ALL.into_iter().zip([
            "CKP_PKCS5_PBKD2_HMAC_SHA224",
            "CKP_PKCS5_PBKD2_HMAC_SHA256",
            "CKP_PKCS5_PBKD2_HMAC_SHA384",
            "CKP_PKCS5_PBKD2_HMAC_SHA512",
            "CKP_PKCS5_PBKD2_HMAC_SHA512_224",
            "CKP_PKCS5_PBKD2_HMAC_SHA512_256",
        ]) {
            let fixture = Pbkdf2Module::new(major, minor, 0, name);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let password = SecretSlice::from(vec![b'p', 0, 0xff, b'\n']);
            for output in [
                Pbkdf2Output::Aes256,
                Pbkdf2Output::DerivationSecret { length: 32 },
            ] {
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                assert!(session.pbkdf2_supported().unwrap());
                session
                    .generate_pbkdf2(&Pbkdf2Request {
                        prf,
                        output,
                        ..request(&password)
                    })
                    .unwrap();
                session.close().unwrap();
            }
            module.finalize().unwrap();
        }
    }
}
#[test]
fn gates_duplicate_readonly_native_failure_and_cleanup() {
    for fault in 0..=8 {
        let fixture = Pbkdf2Module::new(3, 2, fault, "CKP_PKCS5_PBKD2_HMAC_SHA256");
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let password = SecretSlice::from(vec![b'p', 0, 0xff, b'\n']);
        let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
        assert!(matches!(
            ro.generate_pbkdf2(&request(&password)),
            Err(Error::ReadWriteRequired)
        ));
        let close = ro.close();
        assert_eq!(close.is_err(), fault == 6);
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        let result = session.generate_pbkdf2(&request(&password));
        assert_eq!(result.is_ok(), matches!(fault, 0 | 6 | 7));
        if fault == 5 {
            assert!(session.pbkdf2_supported().is_err());
        }
        let close = session.close();
        assert_eq!(close.is_err(), fault == 6);
        let finalize = module.finalize();
        assert_eq!(finalize.is_err(), fault == 7);
    }
}
#[test]
fn preflight_bounds_work_and_redaction() {
    let password = SecretSlice::from(b"password-canary".to_vec());
    let base = Pbkdf2Request {
        salt: b"salt-canary",
        id: b"id-canary",
        label: b"label-canary",
        ..request(&password)
    };
    assert!(!format!("{base:?}").contains("canary"));
    let empty = SecretSlice::from(Vec::new());
    Pbkdf2Request {
        password: &empty,
        ..base
    }
    .validate()
    .unwrap();
    for prf in Pbkdf2Prf::ALL {
        for length in [1, prf.output_len(), prf.output_len() + 1, 4096] {
            let blocks = length.div_ceil(prf.output_len()) as u64;
            let iterations = (PBKDF2_MAXIMUM_WORK / blocks) as u32;
            let r = Pbkdf2Request {
                prf,
                iterations,
                output: Pbkdf2Output::DerivationSecret { length },
                ..base
            };
            r.validate().unwrap();
            assert!(
                Pbkdf2Request {
                    iterations: iterations + 1,
                    ..r
                }
                .validate()
                .is_err()
            );
        }
    }
    let large = SecretSlice::from(vec![0; 4097]);
    for bad in [
        Pbkdf2Request {
            password: &large,
            ..base
        },
        Pbkdf2Request { salt: &[], ..base },
        Pbkdf2Request {
            salt: &[0; 4097],
            ..base
        },
        Pbkdf2Request {
            iterations: 0,
            ..base
        },
        Pbkdf2Request {
            iterations: u32::MAX,
            ..base
        },
        Pbkdf2Request { id: &[], ..base },
        Pbkdf2Request {
            label: &[0; 129],
            ..base
        },
        Pbkdf2Request {
            output: Pbkdf2Output::DerivationSecret { length: 0 },
            ..base
        },
        Pbkdf2Request {
            output: Pbkdf2Output::DerivationSecret { length: 4097 },
            ..base
        },
    ] {
        assert!(bad.validate().is_err());
    }
}
