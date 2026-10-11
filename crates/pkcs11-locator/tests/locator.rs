// SPDX-License-Identifier: MIT OR Apache-2.0
// Original tests of RFC 7512 syntax and semantics; the two short opening URI
// examples are from RFC 7512 section 3 (https://www.rfc-editor.org/rfc/rfc7512).
//! Public API tests without a PKCS#11 implementation.
#![forbid(unsafe_code)]

use pkcs11_locator::{
    Error, ObjectIdentity, ObjectType, Pkcs11Uri, ResourceIdentity, TokenIdentity,
};
use secrecy::{ExposeSecret, SecretString};

fn parse(s: &str) -> Pkcs11Uri {
    s.parse().unwrap()
}

#[test]
fn rfc_empty_and_public_key_examples() {
    let empty = parse("pkcs11:");
    assert!(empty.matches(&ResourceIdentity::default()));
    let key = parse("pkcs11:object=my-pubkey;type=public");
    let mut object = ObjectIdentity::default();
    object.label = Some("my-pubkey");
    object.object_type = Some(ObjectType::Public);
    assert!(key.object_selector().matches(&object));
    object.object_type = Some(ObjectType::Private);
    assert!(!key.object_selector().matches(&object));
}

#[test]
fn binary_id_round_trips_every_octet() {
    let bytes: Vec<u8> = (0..=255).collect();
    let uri = Pkcs11Uri::builder()
        .path_attribute("id", &bytes)
        .unwrap()
        .build()
        .unwrap();
    let encoded = uri.to_string();
    assert_eq!(encoded.len(), "pkcs11:id=".len() + 256 * 3);
    assert!(encoded.contains("%00%01"));
    assert!(encoded.ends_with("%FE%FF"));
    assert_eq!(parse(&encoded).path_attribute("id"), Some(bytes.as_slice()));
    let mut actual = ObjectIdentity::default();
    actual.id = Some(&bytes);
    assert!(uri.object_selector().matches(&actual));
    actual.id = Some(&bytes[1..]);
    assert!(!uri.object_selector().matches(&actual));
}

#[test]
fn binary_ids_do_not_require_utf8_and_decode_once() {
    assert_eq!(
        parse("pkcs11:id=%ff%00%2541").path_attribute("id"),
        Some(&b"\xff\x00%41"[..])
    );
    assert_eq!(parse("pkcs11:id=A").to_string(), "pkcs11:id=%41");
}

#[test]
fn unicode_is_encoded_and_matched_exactly() {
    let uri = parse("pkcs11:token=caf%C3%A9;object=%E9%8D%B5");
    assert_eq!(uri.path_attribute("object"), Some("鍵".as_bytes()));
    let mut token = TokenIdentity::default();
    token.label = Some("café");
    assert!(uri.token_selector().matches(&token));
    token.label = Some("cafe\u{301}");
    assert!(!uri.token_selector().matches(&token));
    assert!("pkcs11:token=café".parse::<Pkcs11Uri>().is_err());
}

#[test]
fn delimiters_and_plus_are_not_form_urlencoding() {
    let uri = parse("pkcs11:object=a%3Bb%3Fc%23d%2Fe+f&g=h");
    assert_eq!(uri.path_attribute("object"), Some(&b"a;b?c#d/e+f&g=h"[..]));
    assert_eq!(
        parse(&uri.to_string()).path_attribute("object"),
        uri.path_attribute("object")
    );
    let query = parse("pkcs11:?custom=one/two?x=3|four%26five%3Bsix");
    assert_eq!(
        query.query_values("custom").next().unwrap().expose_secret(),
        "one/two?x=3|four&five;six"
    );
}

#[test]
fn malformed_percent_encoding_has_typed_secret_free_errors() {
    for value in ["%", "%0", "%GG", "%0z", "%z0", "%%00"] {
        for prefix in ["pkcs11:id=", "pkcs11:token=", "pkcs11:?pin-value="] {
            assert_eq!(
                format!("{prefix}{value}").parse::<Pkcs11Uri>().unwrap_err(),
                Error::PercentEncoding
            );
        }
    }
}

#[test]
fn forbidden_syntax_is_rejected() {
    for uri in [
        "https:token=a",
        "pkcs11",
        "pkcs11://host",
        "pkcs11:token",
        "pkcs11:=a",
        "pkcs11:token=a;",
        "pkcs11:;token=a",
        "pkcs11:token=a;;id=1",
        "pkcs11:?custom=a&",
        "pkcs11:?&custom=a",
        "pkcs11:?custom",
        "pkcs11:token=a b",
        "pkcs11:token=a/b",
        "pkcs11:token=a#b",
        "pkcs11:?custom=a;b",
        "pkcs11:?custom=a#b",
        "pkcs11:tok%65n=a",
        "pkcs11:token=\n",
        "pkcs11:token=\\",
        "pkcs11:<name>=a",
        "pkcs11:pin-value=secret",
        "pkcs11:?token=a",
    ] {
        assert!(uri.parse::<Pkcs11Uri>().is_err(), "{uri}");
    }
    assert_eq!(parse("PKCS11:?").to_string(), "pkcs11:");
}

#[test]
fn empty_values_are_constraints_not_wildcards() {
    let uri = parse("pkcs11:token=;id=;object=;serial=");
    let mut actual = ResourceIdentity::default();
    assert!(!uri.matches(&actual));
    actual.token.label = Some("    ");
    actual.token.serial = Some("");
    actual.object.id = Some(&[]);
    actual.object.label = Some("");
    assert!(uri.matches(&actual));
    actual.object.label = Some(" ");
    assert!(!uri.matches(&actual));
    assert_eq!(
        parse("pkcs11:?pin-value=")
            .query_values("pin-value")
            .next()
            .unwrap()
            .expose_secret(),
        ""
    );
}

#[test]
fn duplicates_are_rejected_for_path_and_standard_query_names() {
    for name in ["token", "id", "vendor"] {
        assert_eq!(
            format!("pkcs11:{name}=a;{}=b", name.to_uppercase())
                .parse::<Pkcs11Uri>()
                .unwrap_err(),
            Error::Duplicate
        );
    }
    for (name, value) in [
        ("pin-value", ""),
        ("pin-source", "file:/x"),
        ("module-name", "x"),
    ] {
        assert_eq!(
            format!("pkcs11:?{name}={value}&{}={value}", name.to_uppercase())
                .parse::<Pkcs11Uri>()
                .unwrap_err(),
            Error::Duplicate
        );
    }
    let path = std::env::current_dir().unwrap();
    let builder = Pkcs11Uri::builder()
        .query_attribute("module-path", path.to_string_lossy().as_ref().into())
        .unwrap();
    assert_eq!(
        builder
            .query_attribute("module-path", path.to_string_lossy().as_ref().into())
            .unwrap_err(),
        Error::Duplicate
    );
}

#[test]
fn unknown_attributes_round_trip_with_conservative_matching() {
    let uri = parse("pkcs11:vendor-mode=strict?extra=b&extra=a&another=1");
    assert!(uri.has_unknown_path_attributes());
    assert!(!uri.matches(&ResourceIdentity::default()));
    assert!(!uri.token_selector().matches(&TokenIdentity::default()));
    assert_eq!(
        uri.to_string(),
        "pkcs11:vendor-mode=strict?another=1&extra=b&extra=a"
    );
    let values: Vec<_> = uri
        .query_values("extra")
        .map(ExposeSecret::expose_secret)
        .collect();
    assert_eq!(values, ["b", "a"]);
    assert!(parse("pkcs11:?vendor=yes").matches(&ResourceIdentity::default()));
}

#[test]
fn every_standard_object_type_is_supported_and_unknown_types_fail() {
    for (s, kind) in [
        ("public", ObjectType::Public),
        ("private", ObjectType::Private),
        ("cert", ObjectType::Certificate),
        ("secret-key", ObjectType::SecretKey),
        ("data", ObjectType::Data),
    ] {
        let uri = parse(&format!("pkcs11:TYPE={}", s.to_uppercase()));
        let mut object = ObjectIdentity::default();
        object.object_type = Some(kind);
        assert!(uri.object_selector().matches(&object));
        assert_eq!(uri.to_string(), format!("pkcs11:type={s}"));
    }
    for s in ["", "certificate", "mechanism", "vendor-key", "%70rivate"] {
        assert_eq!(
            format!("pkcs11:type={s}").parse::<Pkcs11Uri>().unwrap_err(),
            Error::ObjectType
        );
    }
}

#[test]
fn numeric_attributes_are_bounded_and_canonical() {
    let uri = parse("pkcs11:library-version=0003;slot-id=00042");
    assert_eq!(uri.to_string(), "pkcs11:library-version=3.0;slot-id=42");
    assert!(
        parse("pkcs11:library-version=255.255;slot-id=18446744073709551615")
            .path_attribute("slot-id")
            .is_some()
    );
    for pair in [
        "library-version=",
        "library-version=1.",
        "library-version=.1",
        "library-version=1.2.3",
        "library-version=256",
        "library-version=0.256",
        "library-version=+1",
        "library-version=%31",
        "slot-id=",
        "slot-id=-1",
        "slot-id=1.0",
        "slot-id=18446744073709551616",
        "slot-id=%31",
    ] {
        assert_eq!(
            format!("pkcs11:{pair}").parse::<Pkcs11Uri>().unwrap_err(),
            Error::Number
        );
    }
}

#[test]
fn text_validation_distinguishes_binary_ids_and_metadata_limits() {
    for name in ["object", "token", "vendor"] {
        assert_eq!(
            format!("pkcs11:{name}=%FF")
                .parse::<Pkcs11Uri>()
                .unwrap_err(),
            Error::Utf8
        );
    }
    assert_eq!(
        "pkcs11:?pin-value=%FF".parse::<Pkcs11Uri>().unwrap_err(),
        Error::Utf8
    );
    for (name, limit) in [
        ("token", 32),
        ("model", 16),
        ("serial", 16),
        ("manufacturer", 32),
        ("slot-description", 64),
        ("slot-manufacturer", 32),
        ("library-description", 32),
        ("library-manufacturer", 32),
    ] {
        assert!(
            Pkcs11Uri::builder()
                .path_attribute(name, &vec![b'a'; limit])
                .is_ok()
        );
        assert_eq!(
            Pkcs11Uri::builder()
                .path_attribute(name, &vec![b'a'; limit + 1])
                .unwrap_err(),
            Error::Metadata
        );
        assert_eq!(
            Pkcs11Uri::builder()
                .path_attribute(name, b"\0")
                .unwrap_err(),
            Error::Metadata
        );
    }
    assert_eq!(
        "pkcs11:serial=%C3%A9".parse::<Pkcs11Uri>().unwrap_err(),
        Error::Metadata
    );
    assert_eq!(
        Pkcs11Uri::builder()
            .path_attribute("token", "é".repeat(17).as_bytes())
            .unwrap_err(),
        Error::Metadata
    );
}

#[test]
fn matching_enforces_every_level_without_first_match_shortcuts() {
    let mut uri = Pkcs11Uri::builder();
    for (name, value) in [
        ("library-manufacturer", "vendor"),
        ("library-description", "library"),
        ("library-version", "1.2"),
        ("slot-manufacturer", "reader-vendor"),
        ("slot-description", "reader"),
        ("slot-id", "7"),
        ("token", "prod"),
        ("manufacturer", "hsm-vendor"),
        ("model", "model-a"),
        ("serial", "123"),
        ("object", "key "),
        ("id", "a"),
        ("type", "private"),
    ] {
        uri = uri.path_attribute(name, value.as_bytes()).unwrap();
    }
    let uri = uri
        .query_attribute("module-name", "test-module".into())
        .unwrap()
        .build()
        .unwrap();
    let mut identity = ResourceIdentity::default();
    identity.module.manufacturer = Some("vendor ");
    identity.module.description = Some("library ");
    identity.module.version = Some((1, 2));
    identity.module.name = Some("TEST-MODULE");
    identity.slot.manufacturer = Some("reader-vendor ");
    identity.slot.description = Some("reader ");
    identity.slot.id = Some(7);
    identity.token.label = Some("prod ");
    identity.token.manufacturer = Some("hsm-vendor ");
    identity.token.model = Some("model-a ");
    identity.token.serial = Some("123 ");
    identity.object.label = Some("key ");
    identity.object.id = Some(b"a");
    identity.object.object_type = Some(ObjectType::Private);
    assert!(uri.matches(&identity));
    let mut wrong = identity;
    wrong.module.name = None;
    assert!(!uri.matches(&wrong));
    wrong = identity;
    wrong.slot.id = Some(8);
    assert!(!uri.matches(&wrong));
    wrong = identity;
    wrong.token.serial = Some("456");
    assert!(!uri.matches(&wrong));
    wrong = identity;
    wrong.object.label = Some("key");
    assert!(!uri.matches(&wrong));
    // The token-only view is explicitly partial; it cannot establish object match.
    assert!(uri.token_selector().matches(&wrong.token));
}

#[test]
fn module_path_is_platform_absolute_and_never_resolved_or_loaded() {
    for value in ["", "relative/module.so", "../module.so", "\0"] {
        assert_eq!(
            Pkcs11Uri::builder()
                .query_attribute("module-path", value.into())
                .unwrap_err(),
            Error::ModulePath
        );
    }
    let path = std::env::current_dir()
        .unwrap()
        .join("nonexistent-pkcs11-module.so");
    let path = path.to_str().unwrap();
    let uri = Pkcs11Uri::builder()
        .query_attribute("module-path", path.into())
        .unwrap()
        .query_attribute("module-name", "test".into())
        .unwrap()
        .build()
        .unwrap();
    let mut identity = ResourceIdentity::default();
    identity.module.path = Some(path);
    assert!(!uri.matches(&identity));
    identity.module.name = Some("test");
    assert!(uri.matches(&identity));
    assert!(parse(uri.to_secret_uri().expose_secret()).matches(&identity));
}

#[test]
fn secret_serialization_and_all_debug_paths_redact_pins() {
    for name in ["pin-value", "PIN-VALUE", "pin-source"] {
        let secret = "canary-秘密;&=%/";
        let builder = Pkcs11Uri::builder()
            .query_attribute(name, SecretString::from(secret))
            .unwrap();
        assert!(!format!("{builder:?}").contains("canary"));
        let uri = builder.build().unwrap();
        for output in [
            uri.to_string(),
            format!("{uri:#?}"),
            format!("{:?}", uri.token_selector()),
            format!("{:?}", uri.object_selector()),
            format!("{:?}", uri.module_selector()),
            format!("{:?}", uri.slot_selector()),
            format!("{:?}", uri.to_secret_uri()),
        ] {
            assert!(!output.contains("canary"));
            assert!(!output.contains("秘密"));
        }
        let serialized = uri.to_secret_uri();
        assert!(serialized.expose_secret().contains("canary"));
        let again = parse(serialized.expose_secret());
        assert_eq!(
            again.query_values(name).next().unwrap().expose_secret(),
            secret
        );
    }
}

#[test]
fn malformed_pin_input_never_appears_in_errors() {
    for uri in [
        "pkcs11:?pin-value=canary%",
        "pkcs11:?pin-value=canary%FF",
        "pkcs11:?pin-value=canary&pin-value=second",
        "pkcs11:?pin-value=canary&pin-source=file:/secret",
    ] {
        let error = uri.parse::<Pkcs11Uri>().unwrap_err();
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
    for uri in [
        "pkcs11:?pin-value=&pin-source=",
        "pkcs11:?pin-source=file:/missing&pin-value=123",
    ] {
        assert_eq!(uri.parse::<Pkcs11Uri>().unwrap_err(), Error::PinConflict);
    }
}

#[test]
fn serialization_is_deterministic_and_builder_matches_parser() {
    let uri = Pkcs11Uri::builder()
        .path_attribute("TOKEN", b"prod")
        .unwrap()
        .path_attribute("id", b"\x00\xff")
        .unwrap()
        .path_attribute("object", b"key;one")
        .unwrap()
        .query_attribute("z", "two".into())
        .unwrap()
        .query_attribute("a", "one".into())
        .unwrap()
        .build()
        .unwrap();
    let expected = "pkcs11:id=%00%FF;object=key%3Bone;token=prod?a=one&z=two";
    assert_eq!(uri.to_string(), expected);
    assert_eq!(
        parse("PKCS11:token=prod;object=key%3bone;id=%00%ff?z=two&a=one").to_string(),
        expected
    );
    assert_eq!(
        uri.path_attributes().map(|(n, _)| n).collect::<Vec<_>>(),
        ["id", "object", "token"]
    );
    assert_eq!(uri.query_names().collect::<Vec<_>>(), ["a", "z"]);
}

#[test]
fn exhaustive_short_untrusted_inputs_do_not_panic() {
    // A bounded grammar-oriented sweep includes delimiter, NUL, UTF-8 and escape
    // boundaries without introducing a property-testing dependency.
    let alphabet = ["%", "0", "F", "G", ";", "&", "?", "=", "#", "\0", "é", "a"];
    for a in alphabet {
        for b in alphabet {
            for c in alphabet {
                let input = format!("pkcs11:object={a}{b}{c}");
                if let Ok(uri) = input.parse::<Pkcs11Uri>() {
                    let encoded = uri.to_secret_uri();
                    let reparsed = parse(encoded.expose_secret());
                    assert_eq!(
                        uri.path_attribute("object"),
                        reparsed.path_attribute("object")
                    );
                }
            }
        }
    }
}

#[test]
fn individual_metadata_constraints_require_known_matching_values() {
    let mut actual = ResourceIdentity::default();
    actual.module.manufacturer = Some("m");
    actual.module.description = Some("d");
    actual.module.version = Some((2, 4));
    actual.slot.manufacturer = Some("m");
    actual.slot.description = Some("d");
    actual.slot.id = Some(9);
    actual.token.label = Some("t");
    actual.token.manufacturer = Some("m");
    actual.token.model = Some("model");
    actual.token.serial = Some("serial");
    actual.object.label = Some("o");
    actual.object.id = Some(b"i");
    actual.object.object_type = Some(ObjectType::Data);
    for (name, value, wrong) in [
        ("library-manufacturer", "m", "M"),
        ("library-description", "d", "D"),
        ("library-version", "2.4", "2.5"),
        ("slot-manufacturer", "m", "M"),
        ("slot-description", "d", "D"),
        ("slot-id", "9", "8"),
        ("token", "t", "T"),
        ("manufacturer", "m", "M"),
        ("model", "model", "other"),
        ("serial", "serial", "other"),
        ("object", "o", "O"),
        ("id", "i", "I"),
        ("type", "data", "private"),
    ] {
        let uri = parse(&format!("pkcs11:{name}={value}"));
        assert!(uri.matches(&actual), "{name}");
        assert!(!uri.matches(&ResourceIdentity::default()), "{name}");
        assert!(
            !parse(&format!("pkcs11:{name}={wrong}")).matches(&actual),
            "{name}"
        );
    }
}

#[test]
fn parser_and_builder_share_validation_and_secret_conflicts() {
    assert_eq!(
        Pkcs11Uri::builder()
            .path_attribute("pin-value", b"canary")
            .unwrap_err(),
        Error::Component
    );
    assert_eq!(
        Pkcs11Uri::builder()
            .query_attribute("token", "prod".into())
            .unwrap_err(),
        Error::Component
    );
    assert_eq!(
        Pkcs11Uri::builder()
            .path_attribute("bad%name", b"x")
            .unwrap_err(),
        Error::Attribute
    );
    assert_eq!(
        Pkcs11Uri::builder()
            .path_attribute("token", b"a")
            .unwrap()
            .path_attribute("TOKEN", b"b")
            .unwrap_err(),
        Error::Duplicate
    );
    let builder = Pkcs11Uri::builder()
        .query_attribute("pin-source", "|/nonexistent-command".into())
        .unwrap()
        .query_attribute("pin-value", "canary".into())
        .unwrap();
    assert!(!format!("{builder:?}").contains("canary"));
    assert_eq!(builder.build().unwrap_err(), Error::PinConflict);
}

#[test]
fn bounded_query_round_trips_cover_secret_and_vendor_values() {
    let alphabet = ["%", "0", "F", "G", "&", "?", "=", "#", "é", "|", "/", "a"];
    for a in alphabet {
        for b in alphabet {
            for name in ["pin-value", "pin-source", "vendor"] {
                let input = format!("pkcs11:?{name}={a}{b}");
                if let Ok(uri) = input.parse::<Pkcs11Uri>() {
                    let serialized = uri.to_secret_uri();
                    let again = parse(serialized.expose_secret());
                    assert_eq!(
                        uri.query_values(name).next().unwrap().expose_secret(),
                        again.query_values(name).next().unwrap().expose_secret()
                    );
                }
            }
        }
    }
}
