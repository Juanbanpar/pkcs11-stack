// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 inputs and independently compiled PKCS #11 operation profiles.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{Error, Module, ObjectRef, SessionMode, X25519Derivation, X25519PublicKey};

fn reference(kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=cmac;id=%01;type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
fn x25519_native_parameters_permissions_bounds_and_failures() {
    let mut public = [0; 32];
    public[0] = 9;
    let peer = X25519PublicKey::from_bytes(&public).unwrap();
    for headers in ["3.0", "3.1", "3.2"] {
        for fault in [
            0, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 27,
        ] {
            let fixture = MetadataModule::with_headers("x25519.c", fault, headers);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
            let result = session.derive_x25519_secret(
                &reference("private"),
                &X25519Derivation {
                    peer: &peer,
                    id: &[2],
                    label: b"shared",
                },
            );
            if [0, 26].contains(&fault) {
                result.unwrap_or_else(|e| panic!("{headers}/{fault}: {e:?}"));
            } else {
                assert!(result.is_err(), "{headers}/{fault}");
            }
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
#[test]
fn public_points_use_raw_bytes_and_oid_parameters_and_ro_sessions_cannot_derive() {
    for fault in [0, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17] {
        let fixture = MetadataModule::from_source("x25519.c", fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let result = session.x25519_public_key(&reference("public"));
        if fault == 0 {
            let key = result.unwrap();
            assert_eq!(key.as_bytes()[0], 9);
            assert!(matches!(
                session.derive_x25519_secret(
                    &reference("private"),
                    &X25519Derivation {
                        peer: &key,
                        id: &[2],
                        label: b"shared"
                    }
                ),
                Err(Error::ReadWriteRequired)
            ));
        } else {
            assert!(result.is_err(), "fault {fault}");
        }
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
