// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use pkcs11_locator::Pkcs11Uri;
use secrecy::ExposeSecret;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(uri) = input.parse::<Pkcs11Uri>() {
            let canonical = uri.to_secret_uri();
            let again: Pkcs11Uri = canonical.expose_secret().parse().unwrap();
            assert_eq!(
                again.to_secret_uri().expose_secret(),
                canonical.expose_secret()
            );
            assert_eq!(again.to_string(), uri.to_string());
            assert_eq!(
                again.path_attributes().collect::<Vec<_>>(),
                uri.path_attributes().collect::<Vec<_>>()
            );
        }
    }
});
