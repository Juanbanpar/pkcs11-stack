// SPDX-License-Identifier: MIT OR Apache-2.0
#[path = "../../../pkcs11-runtime/tests/fixtures/metadata_module.rs"]
mod metadata_module;
use super::{BackendError, Registry};
use metadata_module::MetadataModule;
use pkcs11_client::ObjectClass;

#[test]
fn opaque_metadata_survives_desktop_browsing_and_details() {
    for fault in 0..=2 {
        let fixture = MetadataModule::new(fault);
        let raw = match fault {
            0 => 0x7fff0001,
            1 => 0x80000001,
            _ => std::os::raw::c_ulong::MAX,
        };
        let mut registry = Registry::default();
        let module = registry.load(fixture.path()).unwrap();
        let token = registry.modules[0].entry.tokens[0].id;
        let objects = registry.objects(module, token).unwrap();
        assert_eq!(objects.len(), 8);
        assert_eq!(objects[0].class_name(), format!("unknown ({raw:08x})"));
        assert!(objects[0].matches(&format!("{raw:08x}")));
        assert!(objects[0].uri.is_none());
        assert!(matches!(
            registry.reference(module, token, objects[0].id),
            Err(BackendError::UnknownObject)
        ));
        assert_eq!(objects[5].class, Some(ObjectClass::DATA));
        assert!(objects[5].uri.is_some());
        for object in &objects[1..5] {
            let details = registry.inspect(module, token, object.id).unwrap();
            let name = if object.class == Some(ObjectClass::CERTIFICATE) {
                "Certificate type"
            } else {
                assert_eq!(*details.key_type.unwrap(), raw);
                "Key type"
            };
            let field = details.fields.iter().find(|f| f.name == name).unwrap();
            assert_eq!(field.status, "available");
            assert_eq!(
                field.value.as_deref(),
                Some(format!("unknown ({raw:08x})").as_str())
            );
        }
        // The catalog remains usable after inspecting unfamiliar key types.
        assert_eq!(registry.objects(module, token).unwrap().len(), 8);
        registry.close().unwrap();
    }
}
