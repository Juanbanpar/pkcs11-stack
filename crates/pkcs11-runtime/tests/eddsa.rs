// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native EdDSA layout, bounds, permissions and failure lifecycle checks.
#![cfg(unix)]
use pkcs11_runtime::*;
use secrecy::SecretString;
use std::{path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new(curve: EdDsaCurve, fault: u8) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pkcs11-eddsa-{}-{curve:?}-{fault}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let output = Command::new("cc")
            .args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                if cfg!(target_os = "macos") {
                    "-dynamiclib"
                } else {
                    "-shared"
                },
            ])
            .arg(format!("-DFAULT={fault}"))
            .arg(format!(
                "-DCURVE448={}",
                u8::from(curve == EdDsaCurve::Ed448)
            ))
            .arg("-I")
            .arg(root.join("headers/3.0"))
            .arg(root.join("eddsa.c"))
            .arg("-o")
            .arg(fixture.0.join("module.so"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn native_pure_profiles_bounds_permissions_and_failure_lifecycle() {
    for curve in [EdDsaCurve::Ed25519, EdDsaCurve::Ed448] {
        for fault in 0..=22 {
            let fixture = Fixture::new(curve, fault);
            let module = Module::load(fixture.0.join("module.so")).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let private =
                PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap())
                    .unwrap();
            let public =
                PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap();
            let pin = SecretString::from("1234");
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let request = EdDsaRequest {
                curve,
                message: b"abc",
            };
            let signature = session.sign_eddsa(&private, &request, Some(Pin::Value(&pin)));
            match fault {
                0 | 8 | 9 | 10 | 13 | 14 | 19 | 20 => {
                    assert_eq!(signature.unwrap(), vec![0xAB; curve.signature_length()])
                }
                _ => assert!(signature.is_err(), "{curve:?} fault {fault}"),
            }
            if matches!(fault, 3..=7 | 15) {
                assert!(matches!(session.info(), Err(Error::Closed)));
            } else {
                session.info().unwrap();
            }
            session.close().unwrap();

            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let result =
                session.verify_eddsa(&public, &request, &vec![0xAB; curve.signature_length()]);
            match fault {
                0 | 2 | 4..=7 | 12 | 14 | 18 | 20 | 22 => result.unwrap(),
                _ => assert!(result.is_err(), "{curve:?} verify fault {fault}"),
            }
            if matches!(fault, 3 | 8 | 9 | 15) {
                assert!(matches!(session.info(), Err(Error::Closed)));
            } else {
                session.info().unwrap();
            }
            session.close().unwrap();

            if fault == 0 {
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                assert!(matches!(
                    session.sign_eddsa(&private, &request, None),
                    Err(Error::ContextAuthenticationRequired)
                ));
                assert!(matches!(
                    session.verify_eddsa(&public, &request, &[]),
                    Err(Error::SignatureMismatch)
                ));
                assert!(matches!(
                    session.verify_eddsa(&public, &request, &vec![0; curve.signature_length()]),
                    Err(Error::SignatureMismatch)
                ));
                session
                    .verify_eddsa(&public, &request, &vec![0xAB; curve.signature_length()])
                    .unwrap();
                session
                    .sign_eddsa(
                        &private,
                        &EdDsaRequest {
                            message: b"",
                            ..request
                        },
                        Some(Pin::Value(&pin)),
                    )
                    .unwrap();
                assert_eq!(
                    session.eddsa_public_key(&public).unwrap().as_bytes(),
                    vec![0; curve.public_key_length()]
                );
                session.close().unwrap();
            }
            if fault == 0 {
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let bad_pin = SecretString::from("incorrect");
                assert!(
                    session
                        .sign_eddsa(&private, &request, Some(Pin::Value(&bad_pin)))
                        .is_err()
                );
                assert!(matches!(session.info(), Err(Error::Closed)));
                session.close().unwrap();
                assert!(
                    !format!(
                        "{:?}",
                        EdDsaRequest {
                            curve,
                            message: b"message-secret-canary"
                        }
                    )
                    .contains("message-secret-canary")
                );
            }
            if fault == 14 {
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                assert!(matches!(
                    session.eddsa_public_key(&public),
                    Err(Error::InvalidKeyOutput)
                ));
                session.close().unwrap();
            }
            module.finalize().unwrap();
        }
    }
}
#[test]
fn curves_accept_only_exact_standard_named_parameters() {
    for (curve, name) in [
        (EdDsaCurve::Ed25519, &b"\x13\x0cedwards25519"[..]),
        (EdDsaCurve::Ed448, &b"\x13\x0aedwards448"[..]),
    ] {
        assert_eq!(
            EdDsaCurve::from_ec_params(curve.ec_params()).unwrap(),
            curve
        );
        assert_eq!(EdDsaCurve::from_ec_params(name).unwrap(), curve);
        let mut trailing = curve.ec_params().to_vec();
        trailing.push(0);
        assert!(EdDsaCurve::from_ec_params(&trailing).is_err());
        assert!(EdDsaPublicKey::from_bytes(curve, vec![0; curve.public_key_length() - 1]).is_err());
    }
    for params in [
        &b""[..],
        &[6, 3, 43, 101, 110],
        &[6, 3, 43, 101, 111],
        b"edwards25519",
    ] {
        assert!(EdDsaCurve::from_ec_params(params).is_err());
    }
}
