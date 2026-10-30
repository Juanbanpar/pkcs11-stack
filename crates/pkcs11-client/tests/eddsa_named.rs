// SPDX-License-Identifier: MIT OR Apache-2.0
//! Raw RFC 8032 point validation without SPKI conversion or provider access.
#[path = "../../pkcs11-runtime/tests/fixtures/eddsa_named_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::EdDsaNamedScheme;
use pkcs11_client::{EdDsaCurve, EdDsaNamedPublicKey};
#[test]
fn named_public_input_checks_canonical_prime_subgroup_points_and_raw_encoding() {
    for vector in vectors::VECTORS {
        let curve = vector.scheme.curve();
        let bytes = vectors::hex(vector.public);
        let key = EdDsaNamedPublicKey::from_bytes(curve, &bytes).unwrap();
        assert_eq!(key.curve(), curve);
        assert_eq!(key.as_bytes(), bytes);
        for invalid in [
            vec![],
            vec![0; bytes.len()],
            bytes[..bytes.len() - 1].to_vec(),
            {
                let mut wrapped = vec![4, bytes.len() as u8];
                wrapped.extend(&bytes);
                wrapped
            },
        ] {
            assert!(EdDsaNamedPublicKey::from_bytes(curve, &invalid).is_err());
        }
        let other = if curve == EdDsaCurve::Ed25519 {
            EdDsaCurve::Ed448
        } else {
            EdDsaCurve::Ed25519
        };
        assert!(EdDsaNamedPublicKey::from_bytes(other, &bytes).is_err());
    }
}
