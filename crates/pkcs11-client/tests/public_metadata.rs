// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public metadata backports, status preservation and bounded native reads.
#![cfg(unix)]
#[path = "../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
mod metadata_module;
use metadata_module::MetadataModule;
use pkcs11_client::{
    Attribute, AttributeInfo, AttributeType as A, Authentication, Error,
    PUBLIC_METADATA_MAX_ATTRIBUTE, Provider, SessionMode, object_locator,
};

#[test]
fn legacy_public_metadata_retains_statuses_profiles_and_validation_fields() {
    for fault in [0, 1, 2, 3, 4, 14] {
        let fixture = MetadataModule::from_source("public_metadata.c", fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let token = "pkcs11:token=cmac".parse().unwrap();
        let mut session = provider
            .management(&token, SessionMode::ReadOnly, Authentication::None)
            .unwrap();
        let objects = session
            .public_object_metadata()
            .unwrap_or_else(|error| panic!("fault {fault}: {error:?}"));
        assert_eq!(objects.len(), 8);
        let unique = objects[5].iter().find(|r| r.kind == A::UniqueId).unwrap();
        match fault {
            2 => assert!(matches!(unique.status, AttributeInfo::Sensitive)),
            3 => assert!(matches!(unique.status, AttributeInfo::TypeInvalid)),
            4 => assert!(matches!(unique.status, AttributeInfo::Unavailable)),
            _ => {
                let expected = if fault == 1 {
                    0
                } else if fault == 14 {
                    PUBLIC_METADATA_MAX_ATTRIBUTE
                } else {
                    9
                };
                assert!(matches!(unique.status, AttributeInfo::Available(n) if n == expected));
                assert!(
                    matches!(unique.values.as_ref().unwrap().expose_values(), [Attribute::UniqueId(v)] if v.len() == expected)
                );
            }
        }
        assert!(object_locator(&token, &objects[6]).unwrap().is_none());
        assert!(object_locator(&token, &objects[7]).unwrap().is_none());
        assert!(objects[7].iter().any(|r| r.kind == A::ProfileId));
        assert!(objects[6].iter().any(|r| r.kind == A::ValidationVendorUri));
        if fault == 0 {
            let validation = objects[6]
                .iter()
                .find(|r| r.kind == A::ValidationFlag)
                .unwrap();
            assert!(
                matches!(validation.values.as_ref().unwrap().expose_values(), [Attribute::ValidationFlag(bits)] if **bits == 0x80000001)
            );
            let reference = pkcs11_client::object_reference(
                "pkcs11:token=cmac;id=%03;type=public".parse().unwrap(),
            )
            .unwrap();
            assert!(
                session
                    .public_metadata(&reference)
                    .unwrap()
                    .iter()
                    .any(|r| r.kind == A::PublicKeyInfo)
            );
            assert!(matches!(
                session.export_public(&reference),
                Err(Error::UnsupportedExport)
            ));
        }
        session.state().unwrap();
        session.close().unwrap();
        provider.finalize().unwrap();
    }
    // The original metadata fixture has no optional values and remains usable.
    let fixture = MetadataModule::new(0);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    assert_eq!(session.public_object_metadata().unwrap().len(), 8);
    session.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
fn malformed_metadata_and_length_changes_fail_without_retries() {
    for fault in [5, 6, 7, 8, 9, 10, 11, 12] {
        let fixture = MetadataModule::from_source("public_metadata.c", fault);
        let provider = Provider::load(fixture.path()).unwrap();
        let mut session = provider
            .management(
                &"pkcs11:token=cmac".parse().unwrap(),
                SessionMode::ReadOnly,
                Authentication::None,
            )
            .unwrap();
        assert!(
            session.public_object_metadata().is_err(),
            "accepted fault {fault}"
        );
        if fault == 11 {
            session.state().unwrap();
        } else {
            assert!(session.state().is_err());
        }
        session.close().unwrap();
        provider.finalize().unwrap();
    }
}

#[test]
fn client_validation_query_retains_same_session_operation_flags() {
    // Native unsigned long can be 32 or 64 bits.
    #[allow(clippy::useless_conversion)]
    let maximum: u64 = std::os::raw::c_ulong::MAX.into();
    let fixture = MetadataModule::from_source("session_validation.c", 5);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    assert_eq!(session.session_validation_flags().unwrap(), Some(0));
    let key = pkcs11_client::object_reference(
        "pkcs11:token=cmac;id=%01;type=secret-key".parse().unwrap(),
    )
    .unwrap();
    session.mac_aes_cmac(&key, b"message").unwrap();
    assert_eq!(session.session_validation_flags().unwrap(), Some(maximum));
    session.close().unwrap();
    provider.finalize().unwrap();
}

#[test]
fn summaries_defer_optional_key_metadata_but_include_unaddressable_snapshots() {
    // Optional reads on ordinary objects are fatal in this fixture.
    let fixture = MetadataModule::from_source("public_metadata.c", 15);
    let provider = Provider::load(fixture.path()).unwrap();
    let mut session = provider
        .management(
            &"pkcs11:token=cmac".parse().unwrap(),
            SessionMode::ReadOnly,
            Authentication::None,
        )
        .unwrap();
    let rows = session.public_object_summaries().unwrap();
    assert_eq!(rows.len(), 8);
    for row in &rows[..6] {
        assert_eq!(
            row.iter().map(|read| read.kind).collect::<Vec<_>>(),
            [A::Class, A::Label, A::Id]
        );
    }
    assert!(
        rows[6]
            .iter()
            .any(|read| read.kind == A::ValidationFlag && read.values.is_some())
    );
    assert!(
        rows[7]
            .iter()
            .any(|read| read.kind == A::ProfileId && read.values.is_some())
    );
    session.state().unwrap();
    // Explicit full inspection still attempts optional attributes and reports errors.
    assert!(session.public_object_metadata().is_err());
    session.close().unwrap();
    provider.finalize().unwrap();
}
