// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public-input checks also run without native provider fixture support.
#[path = "fixtures/x25519_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_runtime::{X25519Derivation, X25519PublicKey};
#[test]
fn rfc7748_public_inputs_and_permitted_encoding_aliases_are_preserved() {
    for value in [vectors::ALICE_PUBLIC, vectors::BOB_PUBLIC] {
        let bytes = vectors::hex(value);
        assert_eq!(
            X25519PublicKey::from_bytes(&bytes)
                .unwrap()
                .as_bytes()
                .as_slice(),
            bytes
        );
    }
    for first in [2, 9] {
        let mut bytes = [0; 32];
        bytes[0] = first;
        X25519PublicKey::from_bytes(&bytes).unwrap();
        bytes[31] |= 128;
        assert_eq!(
            X25519PublicKey::from_bytes(&bytes).unwrap().as_bytes(),
            &bytes
        );
    }
    let mut p_plus_nine = [0xff; 32];
    p_plus_nine[0] = 0xf6;
    p_plus_nine[31] = 0x7f;
    X25519PublicKey::from_bytes(&p_plus_nine).unwrap();
}
#[test]
fn independent_small_order_inputs_and_their_high_bit_aliases_are_rejected() {
    // The seven public encodings checked by libsodium's X25519 implementation.
    for value in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut bytes = vectors::hex(value);
        assert!(X25519PublicKey::from_bytes(&bytes).is_err(), "{value}");
        bytes[31] |= 128;
        assert!(
            X25519PublicKey::from_bytes(&bytes).is_err(),
            "{value} alias"
        );
    }
    for length in [0, 31, 33] {
        assert!(X25519PublicKey::from_bytes(&vec![9; length]).is_err());
    }
}
#[test]
fn identities_are_bounded_and_diagnostics_redact_input() {
    let peer = X25519PublicKey::from_bytes(&vectors::hex(vectors::BOB_PUBLIC)).unwrap();
    for (id, label) in [
        (vec![], vec![1]),
        (vec![1], vec![]),
        (vec![1; 129], vec![1]),
        (vec![1], vec![1; 129]),
    ] {
        assert!(
            X25519Derivation {
                peer: &peer,
                id: &id,
                label: &label
            }
            .validate()
            .is_err()
        );
    }
    let request = X25519Derivation {
        peer: &peer,
        id: b"canary",
        label: b"canary",
    };
    request.validate().unwrap();
    assert!(!format!("{request:?}").contains("canary"));
}
