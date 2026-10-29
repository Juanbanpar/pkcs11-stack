// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 7748 points, canonicalization aliases and explicit KDF/output contracts.
#[path = "fixtures/x448_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_runtime::{AesKeySize, X448Derivation, X448Kdf, X448Output, X448PublicKey};

#[test]
fn public_inputs_accept_rfc_encodings_and_reject_small_order_aliases() {
    for bytes in [
        vectors::hex(vectors::ALICE_PUBLIC),
        vectors::hex(vectors::BOB_PUBLIC),
        vec![255; 56],
    ] {
        assert_eq!(
            X448PublicKey::from_bytes(&bytes)
                .unwrap()
                .as_bytes()
                .as_slice(),
            bytes
        );
    }
    let mut p = [255; 56];
    p[28] = 254;
    let mut one = [0; 56];
    one[0] = 1;
    let mut minus_one = p;
    minus_one[0] -= 1;
    let mut plus_one = [255; 56];
    plus_one[..28].fill(0);
    for low in [[0; 56], one, minus_one, p, plus_one] {
        assert!(X448PublicKey::from_bytes(&low).is_err());
    }
    let mut p_plus_five = plus_one;
    p_plus_five[0] = 4;
    assert_eq!(
        X448PublicKey::from_bytes(&p_plus_five).unwrap().as_bytes(),
        &p_plus_five
    );
    let mut high = [0; 56];
    high[55] = 128;
    assert!(X448PublicKey::from_bytes(&high).is_ok());
    for size in [0, 32, 55, 57, 128] {
        assert!(X448PublicKey::from_bytes(&vec![5; size]).is_err());
    }
}

#[test]
fn output_contract_preserves_raw_width_and_requires_explicit_sha512() {
    let peer = X448PublicKey::from_bytes(&vectors::hex(vectors::BOB_PUBLIC)).unwrap();
    let raw = X448Derivation {
        peer: &peer,
        kdf: X448Kdf::Null,
        shared_info: &[],
        output: X448Output::RawSecret,
        id: b"id",
        label: b"label",
    };
    raw.validate().unwrap();
    assert_eq!(raw.output.length(), 56);
    for kdf in [X448Kdf::Null, X448Kdf::X963Sha512, X448Kdf::Sp80056aSha512] {
        for output in [
            X448Output::RawSecret,
            X448Output::DerivationSecret,
            X448Output::Aes(AesKeySize::Bits128),
            X448Output::Aes(AesKeySize::Bits192),
            X448Output::Aes(AesKeySize::Bits256),
        ] {
            assert_eq!(
                X448Derivation { kdf, output, ..raw }.validate().is_ok(),
                (kdf == X448Kdf::Null) == (output == X448Output::RawSecret)
            );
        }
    }
    assert!(
        X448Derivation {
            shared_info: b"context",
            ..raw
        }
        .validate()
        .is_err()
    );
    for (id, label) in [
        (&[][..], &b"label"[..]),
        (&[1; 129][..], &b"label"[..]),
        (&b"id"[..], &[][..]),
        (&b"id"[..], &[1; 129][..]),
    ] {
        assert!(X448Derivation { id, label, ..raw }.validate().is_err());
    }
    let hashed = X448Derivation {
        kdf: X448Kdf::X963Sha512,
        output: X448Output::DerivationSecret,
        ..raw
    };
    X448Derivation {
        shared_info: &[1; 4096],
        ..hashed
    }
    .validate()
    .unwrap();
    assert!(
        X448Derivation {
            shared_info: &[1; 4097],
            ..hashed
        }
        .validate()
        .is_err()
    );
    assert_eq!(X448Output::DerivationSecret.length(), 64);
    assert_eq!(format!("{peer:?}"), "X448PublicKey([REDACTED])");
}
