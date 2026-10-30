// SPDX-License-Identifier: MIT OR Apache-2.0
//! Native KDF descriptors, protected outputs and exact profile isolation.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{
    AesKeySize, DigestAlgorithm as D, EcdhKdf, Error, Module, MontgomeryKdfRequest,
    MontgomeryNamedCurve as C, MontgomeryNamedPublicKey, MontgomeryOutput as O, ObjectRef, Session,
    SessionMode, X448PublicKey, X25519PublicKey,
};
fn base() -> ObjectRef {
    ObjectRef::new("pkcs11:token=cmac;id=%01;type=private".parse().unwrap()).unwrap()
}
fn request(kdf: usize, output: usize) -> MontgomeryKdfRequest<'static> {
    let digest = [D::Sha224, D::Sha256, D::Sha384, D::Sha512][kdf % 4];
    MontgomeryKdfRequest {
        kdf: if kdf < 4 {
            EcdhKdf::X963(digest)
        } else {
            EcdhKdf::Sp80056a(digest)
        },
        shared_info: match output {
            1 => b"",
            2 => &[b'c'; 4096],
            _ => b"context\0",
        },
        output: [
            O::DerivationSecret { length: 1 },
            O::DerivationSecret { length: 64 },
            O::DerivationSecret { length: 4096 },
            O::Aes(AesKeySize::Bits128),
            O::Aes(AesKeySize::Bits192),
            O::Aes(AesKeySize::Bits256),
        ][output],
        id: &[2],
        label: b"shared",
    }
}
fn derive(
    session: &mut Session<'_>,
    curve: usize,
    request: &MontgomeryKdfRequest<'_>,
) -> Result<(), Error> {
    let mut raw = vec![0; if curve % 2 == 0 { 32 } else { 56 }];
    raw[0] = if curve % 2 == 0 { 9 } else { 5 };
    match curve {
        0 => session.derive_x25519_with_kdf(
            &base(),
            &X25519PublicKey::from_bytes(&raw).unwrap(),
            request,
        ),
        1 => session.derive_x448_with_kdf(
            &base(),
            &X448PublicKey::from_bytes(&raw).unwrap(),
            request,
        ),
        _ => session.derive_named_montgomery_with_kdf(
            &base(),
            &MontgomeryNamedPublicKey::from_bytes(
                if curve == 2 {
                    C::Curve25519
                } else {
                    C::Curve448
                },
                &raw,
            )
            .unwrap(),
            request,
        ),
    }
}
#[test]
fn all_kdfs_outputs_and_context_bounds_reach_the_native_abi() {
    for curve in 0..4 {
        for kdf in 0..8 {
            for output in 0..6 {
                let fixture = MetadataModule::with_case(
                    "montgomery_kdf.c",
                    40 * (curve * 48 + kdf * 6 + output),
                    "3.2",
                );
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                derive(&mut session, curve, &request(kdf, output)).unwrap();
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn native_faults_profile_confusion_and_read_only_sessions_fail_closed() {
    for curve in 0..4 {
        for headers in ["3.0", "3.1", "3.2"] {
            for fault in [
                1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 27,
            ] {
                let fixture = MetadataModule::with_case(
                    "montgomery_kdf.c",
                    40 * (curve * 48 + 6) + fault,
                    headers,
                );
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadWrite).unwrap();
                let result = derive(&mut session, curve, &request(1, 0));
                assert_eq!(
                    result.is_ok(),
                    fault == 26,
                    "{curve}/{headers}/{fault}: {result:?}"
                );
                if [15, 16, 17, 22].contains(&fault) {
                    assert!(matches!(session.info(), Err(Error::Closed)));
                } else {
                    session.info().unwrap();
                }
                session.close().unwrap();
                let mut ro = token.open_session(SessionMode::ReadOnly).unwrap();
                assert!(matches!(
                    derive(&mut ro, curve, &request(1, 0)),
                    Err(Error::ReadWriteRequired)
                ));
                ro.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[test]
fn invalid_requests_are_rejected_before_provider_access() {
    let good = request(1, 0);
    for output in [
        O::DerivationSecret { length: 0 },
        O::DerivationSecret { length: 4097 },
        O::DerivationSecret { length: usize::MAX },
        O::RawSecret,
    ] {
        assert!(MontgomeryKdfRequest { output, ..good }.validate().is_err());
    }
    for kdf in [EcdhKdf::X963(D::Sha3_224), EcdhKdf::Sp80056a(D::Sha3_256)] {
        assert!(MontgomeryKdfRequest { kdf, ..good }.validate().is_err());
    }
    for (id, label) in [
        (b"".as_slice(), b"label".as_slice()),
        (&[0; 129], b"label"),
        (b"id", b""),
        (b"id", &[0; 129]),
    ] {
        assert!(
            MontgomeryKdfRequest { id, label, ..good }
                .validate()
                .is_err()
        );
    }
    assert!(
        MontgomeryKdfRequest {
            shared_info: &[0; 4097],
            ..good
        }
        .validate()
        .is_err()
    );
    let raw = MontgomeryKdfRequest {
        kdf: EcdhKdf::Null,
        shared_info: b"",
        output: O::RawSecret,
        ..good
    };
    raw.validate().unwrap();
    assert!(
        MontgomeryKdfRequest {
            shared_info: b"x",
            ..raw
        }
        .validate()
        .is_err()
    );
    assert!(
        MontgomeryKdfRequest {
            output: O::Aes(AesKeySize::Bits256),
            ..raw
        }
        .validate()
        .is_err()
    );
    let debug = format!("{good:?}");
    assert!(!debug.contains("context") && !debug.contains("shared"));
}
