// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use der::{Decode, Encode, Sequence, asn1::UintRef};
use libfuzzer_sys::fuzz_target;
use pkcs11_runtime::{KeyKind, NamedCurve};
use pkcs11_rustls_adapter::Error;

// Compile the actual private encoder without exposing a public fuzz-only API.
#[path = "../../crates/pkcs11-rustls-adapter/src/encoding.rs"]
mod encoding;

#[derive(Sequence)]
struct Integers<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fuzz_target!(|data: &[u8]| {
    let Some((&index, raw)) = data.split_first() else {
        return;
    };
    let curve = [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521][usize::from(index % 3)];
    let width = curve.bits().div_ceil(8);
    let output = encoding::format_signature(KeyKind::Ec(curve), raw.to_vec());
    if raw.len() != width * 2 {
        assert!(matches!(output, Err(Error::InvalidSignature)));
        return;
    }
    let (r, s) = raw.split_at(width);
    if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
        assert!(matches!(output, Err(Error::InvalidSignature)));
        return;
    }
    let encoded = output.unwrap();
    let decoded = Integers::from_der(&encoded).unwrap();
    assert_eq!(decoded.to_der().unwrap(), encoded);
    assert_eq!(
        decoded.r.as_bytes(),
        &r[r.iter().position(|b| *b != 0).unwrap()..]
    );
    assert_eq!(
        decoded.s.as_bytes(),
        &s[s.iter().position(|b| *b != 0).unwrap()..]
    );
});
