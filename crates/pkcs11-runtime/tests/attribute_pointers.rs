// SPDX-License-Identifier: MIT OR Apache-2.0
//! Provider descriptors cannot redirect decoding to unowned memory or types.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{Attribute, AttributeInfo, AttributeType as A, Error, Module, SessionMode};

#[test]
fn rewritten_attribute_pointers_and_types_invalidate_sessions_before_decoding() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        for fault in [0, 1, 2, 3, 4, 5, 6, 8] {
            for information_only in [false, true] {
                if information_only && ((2..=4).contains(&fault) || fault == 8) {
                    continue;
                }
                let fixture = MetadataModule::with_headers("attribute_pointers.c", fault, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                {
                    let objects = session.find_objects(&[Attribute::Id(vec![1])]).unwrap();
                    let kind = if fault <= 1 { A::Class } else { A::Label };
                    let result = if information_only {
                        objects[0].attribute_info(&[kind]).map(|_| ())
                    } else {
                        objects[0]
                            .read_attributes_bounded(&[kind], 1024)
                            .map(|_| ())
                    };
                    assert!(
                        matches!(
                            result,
                            Err(Error::Backend {
                                source: cryptoki::error::Error::InvalidValue,
                                ..
                            })
                        ),
                        "{headers}/{fault}/info={information_only}: {result:?}"
                    );
                }
                assert!(matches!(session.info(), Err(Error::Closed)));
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}

#[test]
fn unchanged_fixed_and_variable_descriptors_remain_readable() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        let fixture = MetadataModule::with_headers("attribute_pointers.c", 7, headers);
        let module = Module::load(fixture.path()).unwrap();
        let token = module
            .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
            .unwrap();
        let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
        {
            let objects = session.find_objects(&[Attribute::Id(vec![1])]).unwrap();
            assert!(matches!(
                objects[0].attribute_info(&[A::Label]).unwrap()[0],
                AttributeInfo::Available(8)
            ));
            let values = objects[0]
                .read_attributes_bounded(&[A::Class, A::Label], 1024)
                .unwrap();
            assert!(
                matches!(values.expose_values(), [Attribute::Class(_), Attribute::Label(v)] if v == b"metadata")
            );
        }
        session.info().unwrap();
        session.close().unwrap();
        drop(token);
        module.finalize().unwrap();
    }
}
