// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared public test cases; private seeds below are published RFC 7748 vectors.
use super::{AesKeySize, DigestAlgorithm as D, EcdhKdf, MontgomeryOutput as O};
#[path = "x25519_vectors.rs"]
mod c255;
#[path = "x448_vectors.rs"]
mod c448;
pub fn profile(curve: usize) -> (&'static [u8], Vec<u8>, Vec<u8>, Vec<u8>) {
    let (params, private, peer, shared) = match curve {
        0 => (
            b"\x06\x03\x2b\x65\x6e".as_slice(),
            c255::ALICE_PRIVATE,
            c255::BOB_PUBLIC,
            c255::SHARED,
        ),
        1 => (
            b"\x06\x03\x2b\x65\x6f".as_slice(),
            c448::ALICE_PRIVATE,
            c448::BOB_PUBLIC,
            c448::SHARED,
        ),
        2 => (
            b"\x13\x0acurve25519".as_slice(),
            c255::ALICE_PRIVATE,
            c255::BOB_PUBLIC,
            c255::SHARED,
        ),
        _ => (
            b"\x13\x08curve448".as_slice(),
            c448::ALICE_PRIVATE,
            c448::BOB_PUBLIC,
            c448::SHARED,
        ),
    };
    (
        params,
        c255::hex(private),
        c255::hex(peer),
        c255::hex(shared),
    )
}
pub fn peer_input(curve: usize) -> Vec<u8> {
    let raw = profile(curve).2;
    match curve {
        0 => c255::spki(&raw),
        1 => c448::spki(&raw),
        _ => raw,
    }
}
pub fn kdf(index: usize) -> EcdhKdf {
    let digest = [D::Sha224, D::Sha256, D::Sha384, D::Sha512][index % 4];
    if index < 4 {
        EcdhKdf::X963(digest)
    } else {
        EcdhKdf::Sp80056a(digest)
    }
}
pub fn kdf_name(index: usize) -> &'static str {
    [
        "x963-sha224",
        "x963-sha256",
        "x963-sha384",
        "x963-sha512",
        "nist-sha224",
        "nist-sha256",
        "nist-sha384",
        "nist-sha512",
    ][index]
}
pub fn output(index: usize) -> O {
    [
        O::DerivationSecret { length: 16 },
        O::DerivationSecret { length: 64 },
        O::DerivationSecret { length: 4096 },
        O::Aes(AesKeySize::Bits128),
        O::Aes(AesKeySize::Bits192),
        O::Aes(AesKeySize::Bits256),
    ][index]
}
pub fn info(index: usize) -> &'static [u8] {
    match index {
        1 => b"",
        2 => &[b'c'; 4096],
        _ => b"context\0",
    }
}
pub fn uri(group: u8, curve: usize, id: u8, kind: &str) -> String {
    format!("pkcs11:token=kdf-test;id=%D9%{group:02X}%{curve:02X}%{id:02X};type={kind}")
}
pub fn cipher_name(curve: usize, kdf: usize, output: usize) -> String {
    format!("montgomery-kdf-{curve}-{kdf}-{output}.cipher")
}
