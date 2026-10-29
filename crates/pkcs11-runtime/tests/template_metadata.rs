// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent native layouts, metadata-only pointers and bounded tree discovery.
#![cfg(unix)]
#[path = "fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_runtime::{
    Attribute, AttributeInfo, Error, Module, SessionMode, TemplateAttribute as T,
};

#[test]
fn templates_preserve_structure_unknown_ids_and_availability_without_leaf_reads() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        for fault in [0, 1, 2, 3, 4, 22, 23, 24, 25, 26] {
            for kind in [T::Wrap, T::Unwrap, T::Derive] {
                let fixture = MetadataModule::with_headers("template_metadata.c", fault, headers);
                let module = Module::load(fixture.path()).unwrap();
                let token = module
                    .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                    .unwrap();
                let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
                {
                    let objects = session.find_objects(&[Attribute::Id(vec![1])]).unwrap();
                    let report = objects[0]
                        .template_metadata(kind)
                        .unwrap_or_else(|e| panic!("{headers}/{fault}/{kind:?}: {e:?}"));
                    assert_eq!(report.kind, kind);
                    assert_eq!(
                        kind.id(),
                        0x40000211
                            + match kind {
                                T::Wrap => 0,
                                T::Unwrap => 1,
                                T::Derive => 2,
                            }
                    );
                    match fault {
                        1 => assert!(matches!(report.status, AttributeInfo::Available(0))),
                        2 => assert!(matches!(report.status, AttributeInfo::Sensitive)),
                        3 => assert!(matches!(report.status, AttributeInfo::TypeInvalid)),
                        4 => assert!(matches!(report.status, AttributeInfo::Unavailable)),
                        _ => {
                            assert!(matches!(report.status, AttributeInfo::Available(_)));
                            assert_eq!(report.members.len(), if fault == 25 { 128 } else { 8 });
                            if fault != 25 {
                                assert_eq!(report.members[1].attribute_type, 0x11);
                                assert!(matches!(
                                    report.members[1].status,
                                    AttributeInfo::Available(32)
                                ));
                                assert!(report.members[1].template.is_none());
                                assert_eq!(report.members[3].attribute_type, kind_native_max());
                                assert!(matches!(
                                    report.members[3].status,
                                    AttributeInfo::Available(0)
                                ));
                                assert!(report.members[4].template.is_none());
                                assert!(
                                    report.members[5]
                                        .template
                                        .as_ref()
                                        .is_some_and(|v| v.len() == 2)
                                );
                                assert!(matches!(
                                    report.members[6].status,
                                    AttributeInfo::Unavailable
                                ));
                                assert!(
                                    report.members[7]
                                        .template
                                        .as_ref()
                                        .is_some_and(Vec::is_empty)
                                );
                                assert!(!format!("{report:?}").contains("canary"));
                            }
                        }
                    }
                }
                session.info().unwrap();
                session.close().unwrap();
                drop(token);
                module.finalize().unwrap();
            }
        }
    }
}
#[allow(clippy::useless_conversion)]
fn kind_native_max() -> u64 {
    std::os::raw::c_ulong::MAX.into()
}

#[test]
fn malformed_changed_or_excessive_template_layouts_invalidate_sessions() {
    for headers in ["2.40", "3.0", "3.1", "3.2"] {
        for fault in [
            5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 27,
        ] {
            let fixture = MetadataModule::with_headers("template_metadata.c", fault, headers);
            let module = Module::load(fixture.path()).unwrap();
            let token = module
                .resolve_token_uri(&"pkcs11:token=cmac".parse().unwrap())
                .unwrap();
            let mut session = token.open_session(SessionMode::ReadOnly).unwrap();
            {
                let objects = session.find_objects(&[Attribute::Id(vec![1])]).unwrap();
                assert!(
                    objects[0].template_metadata(T::Wrap).is_err(),
                    "{headers}/{fault}"
                );
            }
            assert!(
                matches!(session.info(), Err(Error::Closed)),
                "{headers}/{fault}"
            );
            session.close().unwrap();
            drop(token);
            module.finalize().unwrap();
        }
    }
}
