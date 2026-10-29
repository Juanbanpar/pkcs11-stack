// SPDX-License-Identifier: MIT OR Apache-2.0
//! X448 native inputs and independently compiled PKCS #11 operation profiles.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{
    AesKeySize, Error, Module, ObjectRef, SessionMode, X448Derivation, X448Kdf, X448Output,
    X448PublicKey,
};

fn reference(kind: &str) -> ObjectRef {
    ObjectRef::new(
        format!("pkcs11:token=cmac;id=%01;type={kind}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}
#[test]
fn x448_native_parameters_permissions_bounds_and_failures() {
    let mut public = [0; 56];
    public[0] = 5;
    let peer = X448PublicKey::from_bytes(&public).unwrap();
    for profile in 0..7 {
        for headers in ["3.0", "3.1", "3.2"] {
            for fault in [
                0, 1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 27, 28,
            ] {
                if profile > 2 && fault != 0 {
                    continue;
                }
                let fixture = MetadataModule::with_headers("x448.c", fault + 40 * profile, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                let result = session.derive_x448_key(
                    &reference("private"),
                    &X448Derivation {
                        peer: &peer,
                        kdf: if profile == 0 {
                            X448Kdf::Null
                        } else if [1, 3, 6].contains(&profile) {
                            X448Kdf::X963Sha512
                        } else {
                            X448Kdf::Sp80056aSha512
                        },
                        shared_info: if profile == 0 { &[] } else { b"context" },
                        output: match profile {
                            0 => X448Output::RawSecret,
                            1 | 5 => X448Output::DerivationSecret,
                            3 => X448Output::Aes(AesKeySize::Bits128),
                            4 => X448Output::Aes(AesKeySize::Bits192),
                            _ => X448Output::Aes(AesKeySize::Bits256),
                        },
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
}
#[test]
fn public_points_use_raw_bytes_and_oid_parameters_and_ro_sessions_cannot_derive() {
    for fault in [0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17] {
        let fixture = MetadataModule::from_source("x448.c", fault);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        let result = session.x448_public_key(&reference("public"));
        if fault == 0 {
            let key = result.unwrap();
            assert_eq!(key.as_bytes()[0], 5);
            assert!(matches!(
                session.derive_x448_key(
                    &reference("private"),
                    &X448Derivation {
                        peer: &key,
                        kdf: X448Kdf::Null,
                        shared_info: &[],
                        output: X448Output::RawSecret,
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
