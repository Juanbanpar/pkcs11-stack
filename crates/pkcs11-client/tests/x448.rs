// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict RFC 8410 peer-key parsing without provider access.
#[path = "../../pkcs11-runtime/tests/fixtures/x448_vectors.rs"]
#[allow(dead_code)]
mod vectors;
use pkcs11_client::X448Peer;
#[test]
fn strict_rfc8410_spki_round_trips_and_rejects_other_profiles() {
    let der = vectors::spki(&vectors::hex(vectors::ALICE_PUBLIC));
    assert_eq!(
        X448Peer::from_spki_der(&der)
            .unwrap()
            .to_spki_der()
            .unwrap(),
        der
    );
    let mut invalid = vec![vec![], vec![0; 129]];
    let mut appended = der.clone();
    appended.push(0);
    invalid.push(appended);
    for oid in [110, 112, 113] {
        let mut wrong = der.clone();
        wrong[8] = oid;
        invalid.push(wrong);
    }
    let mut unused = der.clone();
    unused[10] = 1;
    invalid.push(unused);
    let mut null = vectors::hex("3044300706032b656f0500033900");
    null.extend(vectors::hex(vectors::ALICE_PUBLIC));
    invalid.push(null);
    invalid.push(vectors::spki(&[0; 56]));
    for der in invalid {
        assert!(X448Peer::from_spki_der(&der).is_err());
    }
}
