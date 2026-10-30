// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent OASIS layouts, exact RFC 8032 parameters and failure lifecycle.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{
    EdDsaNamedRequest as Request, EdDsaNamedScheme as Scheme, Error, Module, Pin, PrivateKeyRef,
    PublicKeyRef, SessionMode,
};
use secrecy::SecretString;
const SCHEMES: [Scheme; 5] = [
    Scheme::Ed25519,
    Scheme::Ed25519ctx,
    Scheme::Ed25519ph,
    Scheme::Ed448,
    Scheme::Ed448ph,
];
#[test]
fn native_named_schemes_contexts_permissions_and_failure_lifecycle() {
    for (index, scheme) in SCHEMES.into_iter().enumerate() {
        for headers in ["3.0", "3.1", "3.2"] {
            for fault in 0..=25 {
                if [23, 24].contains(&fault) {
                    continue;
                }
                let fixture = MetadataModule::with_headers(
                    "eddsa_named.c",
                    index as u8 * 32 + fault,
                    headers,
                );
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let private =
                    PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap())
                        .unwrap();
                let public =
                    PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap())
                        .unwrap();
                let context = vec![
                    0xA5;
                    if scheme == Scheme::Ed25519 {
                        0
                    } else if fault == 25 {
                        255
                    } else {
                        3
                    }
                ];
                let request = Request {
                    scheme,
                    message: b"abc",
                    context: &context,
                };
                let pin = SecretString::from("1234");
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let result = session.sign_named_eddsa(&private, &request, Some(Pin::Value(&pin)));
                assert_eq!(
                    result.is_ok(),
                    [0, 8, 9, 10, 13, 14, 19, 25].contains(&fault),
                    "{scheme:?}/{headers}/{fault}: {result:?}"
                );
                if [3, 4, 5, 6, 7, 15].contains(&fault) {
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    session.info().unwrap();
                }
                session.close().unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                let result = session.verify_named_eddsa(
                    &public,
                    &request,
                    &vec![0xAB; scheme.curve().signature_length()],
                );
                assert_eq!(
                    result.is_ok(),
                    [0, 2, 4, 5, 6, 7, 12, 14, 18, 22, 25].contains(&fault),
                    "verify {scheme:?}/{headers}/{fault}: {result:?}"
                );
                if [3, 8, 9, 15].contains(&fault) {
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    session.info().unwrap();
                }
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
        let fixture = MetadataModule::from_source("eddsa_named.c", index as u8 * 32 + 24);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let private =
            PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        session
            .sign_named_eddsa(
                &private,
                &Request {
                    scheme,
                    message: b"",
                    context: &[],
                },
                Some(Pin::Value(&SecretString::from("1234"))),
            )
            .unwrap();
        session.close().unwrap();
        drop(token);
        assert!(module.finalize().is_err());
    }
}
#[test]
fn contexts_are_bounded_and_invalid_requests_do_not_touch_native_state() {
    for scheme in SCHEMES {
        for length in [0, 1, 255, 256] {
            let bytes = vec![0xa5; length];
            let request = Request {
                scheme,
                message: b"secret canary",
                context: &bytes,
            };
            assert_eq!(
                request.validate().is_ok(),
                length <= 255 && (scheme != Scheme::Ed25519 || length == 0)
            );
            assert!(!format!("{request:?}").contains("secret canary"));
        }
    }
    let fixture = MetadataModule::from_source("eddsa_named.c", 32);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    let private =
        PrivateKeyRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap();
    let public =
        PublicKeyRef::new("pkcs11:token=cmac;id=%01;type=public".parse().unwrap()).unwrap();
    let bad = Request {
        scheme: Scheme::Ed25519ctx,
        message: b"abc",
        context: &[0; 256],
    };
    assert!(matches!(
        session.sign_named_eddsa(&private, &bad, None),
        Err(Error::InvalidParameters(_))
    ));
    assert!(matches!(
        session.verify_named_eddsa(&public, &bad, &[0; 64]),
        Err(Error::InvalidParameters(_))
    ));
    let good = Request {
        context: &[0xa5; 3],
        ..bad
    };
    assert!(matches!(
        session.sign_named_eddsa(&private, &good, None),
        Err(Error::ContextAuthenticationRequired)
    ));
    assert!(matches!(
        session.verify_named_eddsa(&public, &good, &[0; 63]),
        Err(Error::SignatureMismatch)
    ));
    assert!(matches!(
        session.verify_named_eddsa(&public, &good, &[0; 64]),
        Err(Error::SignatureMismatch)
    ));
    session
        .verify_named_eddsa(&public, &good, &[0xab; 64])
        .unwrap();
    session.info().unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
}
