// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mixed metadata inspection retains opaque IDs without widening export policy.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_client::{
    Attribute, AttributeType, Authentication, Error, ErrorKind, Provider, SessionMode,
    object_locator, object_reference,
};

#[test]
fn opaque_objects_do_not_hide_known_objects_or_enable_key_export() {
    for fault in 0..=2 {
        let fixture = MetadataModule::new(fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let token = "pkcs11:token=cmac".parse().unwrap();
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let reads = session
            .objects(&[
                AttributeType::Class,
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::KeyType,
                AttributeType::CertificateType,
                AttributeType::ProfileId,
                AttributeType::ValidationType,
                AttributeType::ValidationAuthorityType,
            ])
            .unwrap();
        assert_eq!(reads.len(), 8);
        let locators: Vec<_> = reads
            .iter()
            .map(|a| object_locator(&token, a).unwrap())
            .collect();
        for (index, locator) in locators.iter().enumerate() {
            assert_eq!(locator.is_some(), (1..=5).contains(&index));
        }
        assert!(reads[5].iter().any(|r| r.values.as_ref().is_some_and(|a| {
            a.expose_values()
                .contains(&Attribute::Class(pkcs11_client::ObjectClass::DATA))
        })));
        for (id, kind) in [(2, "private"), (3, "public"), (4, "secret-key")] {
            let key = object_reference(
                format!("pkcs11:token=cmac;id=%{id:02X};type={kind}")
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            let result = session.export_public(&key);
            assert!(
                matches!(result, Err(Error::UnsupportedExport)),
                "{id}: {result:?}"
            );
            session.state().unwrap();
        }
        let opaque = object_reference("pkcs11:token=cmac;id=%01".parse().unwrap()).unwrap();
        assert_eq!(
            session.export_public(&opaque).unwrap_err().kind(),
            ErrorKind::Selection
        );
        // Raw public certificate/data export does not interpret an algorithm.
        for (id, expected) in [
            (5, b"opaque-certificate".as_slice()),
            (6, b"public-data".as_slice()),
        ] {
            let key = object_reference(format!("pkcs11:token=cmac;id=%{id:02X}").parse().unwrap())
                .unwrap();
            assert_eq!(session.export_public(&key).unwrap(), expected);
        }
        session.state().unwrap();
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}
