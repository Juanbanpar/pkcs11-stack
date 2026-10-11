// SPDX-License-Identifier: MIT OR Apache-2.0
//! Generated cases supplement the fixed RFC and boundary regressions.
use pkcs11_locator::{ObjectIdentity, Pkcs11Uri, ResourceIdentity};
use proptest::prelude::*;
use secrecy::{ExposeSecret, SecretString};

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..128).prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #[test]
    fn binary_selectors_round_trip_and_never_widen(id in prop::collection::vec(any::<u8>(), 0..256)) {
        let uri = Pkcs11Uri::builder().path_attribute("id", &id).unwrap().build().unwrap();
        let encoded = uri.to_string();
        let again: Pkcs11Uri = encoded.parse().unwrap();
        prop_assert_eq!(again.path_attribute("id"), Some(id.as_slice()));
        prop_assert_eq!(again.to_string(), encoded);
        let mut object = ObjectIdentity::default();
        prop_assert!(!again.object_selector().matches(&object));
        object.id = Some(&id);
        prop_assert!(again.object_selector().matches(&object));
        let mut different = id.clone();
        different.push(0);
        object.id = Some(&different);
        prop_assert!(!again.object_selector().matches(&object));
    }

    #[test]
    fn unicode_labels_are_exact_including_empty_and_trailing_space(label in text()) {
        let uri = Pkcs11Uri::builder().path_attribute("object", label.as_bytes()).unwrap().build().unwrap();
        let again: Pkcs11Uri = uri.to_string().parse().unwrap();
        prop_assert_eq!(again.path_attribute("object"), Some(label.as_bytes()));
        let mut object = ObjectIdentity::default();
        prop_assert!(!again.object_selector().matches(&object));
        object.label = Some(&label);
        prop_assert!(again.object_selector().matches(&object));
        let different = format!("{label} ");
        object.label = Some(&different);
        prop_assert!(!again.object_selector().matches(&object));
    }

    #[test]
    fn secret_queries_round_trip_only_through_explicit_secret_output(value in text(), source in any::<bool>()) {
        // The canary cannot occur elsewhere: this URI has only a secret query.
        let value = format!("pin-canary-{value}");
        let name = if source { "pin-source" } else { "pin-value" };
        let builder = Pkcs11Uri::builder().query_attribute(name, SecretString::from(value.as_str())).unwrap();
        let debug = format!("{builder:?}");
        prop_assert!(!debug.contains("pin-canary-"));
        let uri = builder.build().unwrap();
        for output in [uri.to_string(), format!("{uri:?}"), format!("{:?}", uri.module_selector()),
            format!("{:?}", uri.slot_selector()), format!("{:?}", uri.token_selector()),
            format!("{:?}", uri.object_selector()), format!("{:?}", uri.to_secret_uri())] {
            prop_assert!(!output.contains("pin-canary-"));
        }
        let secret = uri.to_secret_uri();
        let again: Pkcs11Uri = secret.expose_secret().parse().unwrap();
        prop_assert_eq!(again.query_values(name).next().unwrap().expose_secret(), value.as_str());
        let again_secret = again.to_secret_uri();
        prop_assert_eq!(again_secret.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn accepted_untrusted_text_has_lossless_canonical_serialization(
        body in prop::collection::vec(prop_oneof![any::<char>(), prop::sample::select(vec!['%', ';', '?', '&', '=', '0', 'F'])], 0..256),
        prefix in prop::sample::select(vec!["", "pkcs11:", "pkcs11:object=", "pkcs11:id=", "pkcs11:?pin-value="])
    ) {
        let input = format!("{prefix}{}", body.into_iter().collect::<String>());
        if let Ok(uri) = input.parse::<Pkcs11Uri>() {
            let canonical = uri.to_secret_uri();
            let again: Pkcs11Uri = canonical.expose_secret().parse().unwrap();
            let again_secret = again.to_secret_uri();
            prop_assert_eq!(again_secret.expose_secret(), canonical.expose_secret());
            prop_assert_eq!(uri.path_attributes().collect::<Vec<_>>(), again.path_attributes().collect::<Vec<_>>());
            prop_assert_eq!(uri.to_string(), again.to_string());
        }
    }

    #[test]
    fn unknown_path_criteria_never_match_known_identity(value in text()) {
        let uri = Pkcs11Uri::builder().path_attribute("vendor-extra", value.as_bytes()).unwrap().build().unwrap();
        let again: Pkcs11Uri = uri.to_string().parse().unwrap();
        prop_assert_eq!(again.path_attribute("vendor-extra"), Some(value.as_bytes()));
        prop_assert!(again.has_unknown_path_attributes());
        prop_assert!(!again.matches(&ResourceIdentity::default()));
    }
}
