// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generation/import templates and failures against independent 3.x headers.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{Error, Module, SessionMode, X25519KeyPairRequest, X25519PublicKey};

#[test]
fn native_generation_and_import_require_exact_profiles_and_preserve_session_health() {
    let mut bytes = [0; 32];
    bytes[0] = 9;
    let peer = X25519PublicKey::from_bytes(&bytes).unwrap();
    for headers in ["3.0", "3.1", "3.2"] {
        for generate in [true, false] {
            for fault in 0..=15 {
                if [13, 14].contains(&fault) {
                    continue;
                }
                let fixture = MetadataModule::with_headers("x25519_management.c", fault, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                if generate && ![11, 12, 15].contains(&fault) {
                    assert_eq!(
                        token.x25519_generation_supported().unwrap(),
                        ![1, 2, 3, 4, 5].contains(&fault)
                    );
                }
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                let result = if generate {
                    session
                        .generate_x25519_key_pair(&X25519KeyPairRequest {
                            id: &[2],
                            label: b"X25519",
                        })
                        .map(|_| ())
                } else {
                    session
                        .import_x25519_public_key(&peer, &[2], b"X25519")
                        .map(|_| ())
                };
                let fail = if generate {
                    [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 15].contains(&fault)
                } else {
                    [7, 8, 9, 12].contains(&fault)
                };
                assert_eq!(
                    result.is_err(),
                    fail,
                    "{headers}/{generate}/{fault}: {result:?}"
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
}

#[test]
fn read_only_and_invalid_identity_are_rejected_before_provider_mutation() {
    let fixture = MetadataModule::from_source("x25519_management.c", 0);
    let module = Module::load(fixture.path()).unwrap();
    let token = module
        .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
        .unwrap();
    let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
    let mut bytes = [0; 32];
    bytes[0] = 9;
    let peer = X25519PublicKey::from_bytes(&bytes).unwrap();
    for (id, label) in [
        (&[][..], &b"X25519"[..]),
        (&[2][..], &[][..]),
        (&[2; 129][..], &b"X25519"[..]),
        (&[2][..], &[1; 129][..]),
    ] {
        let request = X25519KeyPairRequest { id, label };
        assert!(request.validate().is_err());
        assert!(matches!(
            session.generate_x25519_key_pair(&request),
            Err(Error::InvalidParameters(_))
        ));
        assert!(matches!(
            session.import_x25519_public_key(&peer, id, label),
            Err(Error::InvalidParameters(_))
        ));
    }
    let request = X25519KeyPairRequest {
        id: &[2],
        label: b"X25519",
    };
    assert!(matches!(
        session.generate_x25519_key_pair(&request),
        Err(Error::ReadWriteRequired)
    ));
    assert!(matches!(
        session.import_x25519_public_key(&peer, &[2], b"X25519"),
        Err(Error::ReadWriteRequired)
    ));
    assert_eq!(format!("{request:?}"), "X25519KeyPairRequest([REDACTED])");
    session.info().unwrap();
    session.close().unwrap();
    drop(token);
    module.finalize().unwrap();
    X25519KeyPairRequest {
        id: &[2; 128],
        label: &[1; 128],
    }
    .validate()
    .unwrap();
}
