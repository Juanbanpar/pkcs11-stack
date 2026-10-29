// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent native templates, profile isolation and failure handling.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{
    Error, Module, MontgomeryNamedCurve as Curve, MontgomeryNamedPublicKey as Public, ObjectRef,
    SessionMode, X448Derivation, X448Kdf, X448Output, X448PublicKey, X25519Derivation,
    X25519PublicKey,
};
fn reference(kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=cmac;id=%01;type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
fn profiles() -> [(Curve, &'static str, Vec<u8>); 2] {
    let mut c255 = vec![0; 32];
    c255[0] = 9;
    let mut c448 = vec![0; 56];
    c448[0] = 5;
    [
        (Curve::Curve25519, "curve25519", c255),
        (Curve::Curve448, "curve448", c448),
    ]
}
#[test]
fn named_native_agreement_checks_metadata_permissions_bounds_and_session_health() {
    for (curve, name, bytes) in profiles() {
        let peer = Public::from_bytes(curve, &bytes).unwrap();
        for headers in ["3.0", "3.1", "3.2"] {
            for fault in [
                0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 27,
            ] {
                let fixture = MetadataModule::with_headers(&format!("{name}.c"), fault, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                let result = session.derive_named_montgomery_secret(
                    &reference("private"),
                    &peer,
                    &[2],
                    b"shared",
                );
                assert_eq!(
                    result.is_ok(),
                    [0, 26].contains(&fault),
                    "{name}/{headers}/{fault}: {result:?}"
                );
                if [15, 16, 17, 22].contains(&fault) {
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    session.info().unwrap();
                }
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn named_public_reads_reject_oid_keys_wrapped_points_and_malformed_metadata() {
    for (curve, name, bytes) in profiles() {
        for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17] {
            let fixture = MetadataModule::from_source(&format!("{name}.c"), fault);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            let result = session.named_montgomery_public_key(&reference("public"), curve);
            assert_eq!(result.is_ok(), fault == 0, "{name}/{fault}");
            if let Ok(peer) = result {
                assert_eq!(peer.as_bytes(), bytes);
                assert_eq!(peer.curve(), curve);
                assert!(matches!(
                    session.derive_named_montgomery_secret(
                        &reference("private"),
                        &peer,
                        &[2],
                        b"shared"
                    ),
                    Err(Error::ReadWriteRequired)
                ));
                let other = if curve == Curve::Curve25519 {
                    Curve::Curve448
                } else {
                    Curve::Curve25519
                };
                assert!(
                    session
                        .named_montgomery_public_key(&reference("public"), other)
                        .is_err()
                );
            }
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
        let fixture = MetadataModule::from_source(&format!("{name}.c"), 0);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
        // Existing RFC 8410 APIs must not accept a curveName key, in either direction.
        if curve == Curve::Curve25519 {
            assert!(session.x25519_public_key(&reference("public")).is_err());
            let peer = X25519PublicKey::from_bytes(&bytes).unwrap();
            assert!(
                session
                    .derive_x25519_secret(
                        &reference("private"),
                        &X25519Derivation {
                            peer: &peer,
                            id: &[2],
                            label: b"shared"
                        }
                    )
                    .is_err()
            );
        } else {
            assert!(session.x448_public_key(&reference("public")).is_err());
            let peer = X448PublicKey::from_bytes(&bytes).unwrap();
            assert!(
                session
                    .derive_x448_key(
                        &reference("private"),
                        &X448Derivation {
                            peer: &peer,
                            kdf: X448Kdf::Null,
                            shared_info: &[],
                            output: X448Output::RawSecret,
                            id: &[2],
                            label: b"shared"
                        }
                    )
                    .is_err()
            );
        }
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn named_generation_import_and_preflight_validation() {
    for (curve, name, bytes) in profiles() {
        let peer = Public::from_bytes(curve, &bytes).unwrap();
        for headers in ["3.0", "3.1", "3.2"] {
            for generate in [true, false] {
                for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15] {
                    let fixture = MetadataModule::with_headers(
                        &format!("{name}_management.c"),
                        fault,
                        headers,
                    );
                    let module = Module::load(fixture.path()).unwrap();
                    let token = module
                        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                        .unwrap();
                    if ![11, 15].contains(&fault) {
                        assert_eq!(
                            token.named_montgomery_generation_supported(curve).unwrap(),
                            ![1, 2, 3, 4, 5].contains(&fault)
                        );
                    }
                    let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                    let result = if generate {
                        session
                            .generate_named_montgomery_key_pair(curve, &[2], name.as_bytes())
                            .map(|_| ())
                    } else {
                        session
                            .import_named_montgomery_public_key(&peer, &[2], name.as_bytes())
                            .map(|_| ())
                    };
                    let fails = if generate {
                        [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 15].contains(&fault)
                    } else {
                        [7, 8, 9, 12].contains(&fault)
                    };
                    assert_eq!(
                        result.is_err(),
                        fails,
                        "{name}/{headers}/{generate}/{fault}: {result:?}"
                    );
                    if (generate && fault == 6) || (!generate && fault == 7) || fault == 12 {
                        assert!(matches!(session.info(), Err(Error::Closed)));
                    } else {
                        session.info().unwrap();
                    }
                    session.close().unwrap();
                    drop(token);
                    module.finalize().unwrap();
                }
            }
        }
        let fixture = MetadataModule::from_source(&format!("{name}_management.c"), 0);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        for (id, label) in [
            (&[][..], b"shared".as_slice()),
            (&[2][..], &[][..]),
            (&[2; 129][..], b"shared".as_slice()),
            (&[2][..], &[1; 129][..]),
        ] {
            assert!(matches!(
                session.generate_named_montgomery_key_pair(curve, id, label),
                Err(Error::InvalidParameters(_))
            ));
            assert!(matches!(
                session.import_named_montgomery_public_key(&peer, id, label),
                Err(Error::InvalidParameters(_))
            ));
            assert!(matches!(
                session.derive_named_montgomery_secret(&reference("private"), &peer, id, label),
                Err(Error::InvalidParameters(_))
            ));
        }
        assert!(matches!(
            session.generate_named_montgomery_key_pair(curve, &[2], name.as_bytes()),
            Err(Error::ReadWriteRequired)
        ));
        assert!(matches!(
            session.import_named_montgomery_public_key(&peer, &[2], name.as_bytes()),
            Err(Error::ReadWriteRequired)
        ));
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
#[test]
fn checked_named_public_input_rejects_bad_lengths_and_noncontributory_points() {
    for (curve, _, bytes) in profiles() {
        let length = bytes.len();
        for invalid in [
            vec![],
            vec![9; length - 1],
            vec![9; length + 1],
            vec![0; length],
        ] {
            assert!(Public::from_bytes(curve, &invalid).is_err());
        }
        let mut one = vec![0; length];
        one[0] = 1;
        assert!(Public::from_bytes(curve, &one).is_err());
        let peer = Public::from_bytes(curve, &bytes).unwrap();
        assert_eq!(format!("{peer:?}"), "MontgomeryNamedPublicKey([REDACTED])");
    }
}
