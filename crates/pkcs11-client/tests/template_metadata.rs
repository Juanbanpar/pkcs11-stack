// SPDX-License-Identifier: MIT OR Apache-2.0
//! Template inspection through unique, bounded application object selection.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
#[allow(dead_code)]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_client::{
    AttributeInfo, Authentication, Provider, SessionMode, TemplateAttribute, object_reference,
};

#[test]
fn application_template_metadata_preserves_status_and_session_health() {
    for fault in [0, 1, 2, 3, 4, 8, 12, 17, 22, 23, 25, 26] {
        let fixture = MetadataModule::from_source("template_metadata.c", fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        let key =
            object_reference("pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap()).unwrap();
        let result = session.template_metadata(&key, TemplateAttribute::Derive);
        if [8, 12, 17].contains(&fault) {
            assert!(result.is_err(), "fault {fault}");
            assert!(session.state().is_err());
        } else {
            let result = result.unwrap_or_else(|e| panic!("fault {fault}: {e:?}"));
            match fault {
                1 => assert!(matches!(result.status, AttributeInfo::Available(0))),
                2 => assert!(matches!(result.status, AttributeInfo::Sensitive)),
                3 => assert!(matches!(result.status, AttributeInfo::TypeInvalid)),
                4 => assert!(matches!(result.status, AttributeInfo::Unavailable)),
                _ => assert!(!result.members.is_empty()),
            }
            session.state().unwrap();
        }
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
