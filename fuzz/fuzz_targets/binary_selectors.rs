// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use pkcs11_locator::{ObjectIdentity, Pkcs11Uri};
use secrecy::{ExposeSecret, SecretString};

fuzz_target!(|data: &[u8]| {
    let secret = format!("pin-canary-{}", String::from_utf8_lossy(data));
    let uri = Pkcs11Uri::builder()
        .path_attribute("id", data)
        .unwrap()
        .query_attribute("pin-value", SecretString::from(secret.as_str()))
        .unwrap()
        .build()
        .unwrap();
    // The only public value is a fully hex-encoded ID, so the canary cannot collide.
    assert!(!uri.to_string().contains("pin-canary-"));
    assert!(!format!("{uri:?}").contains("pin-canary-"));
    let encoded = uri.to_secret_uri();
    let again: Pkcs11Uri = encoded.expose_secret().parse().unwrap();
    assert_eq!(again.path_attribute("id"), Some(data));
    assert_eq!(
        again
            .query_values("pin-value")
            .next()
            .unwrap()
            .expose_secret(),
        secret
    );
    let mut object = ObjectIdentity::default();
    assert!(!again.object_selector().matches(&object));
    object.id = Some(data);
    assert!(again.object_selector().matches(&object));
    let mut different = data.to_vec();
    different.push(0);
    object.id = Some(&different);
    assert!(!again.object_selector().matches(&object));
});
