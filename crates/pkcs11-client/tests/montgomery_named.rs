// SPDX-License-Identifier: MIT OR Apache-2.0
//! Raw curveName inputs and application request validation.
use pkcs11_client::{
    Error, ErrorKind, MontgomeryNamedCurve as Curve, MontgomeryNamedKeyPairRequest as Pair,
    MontgomeryNamedPeer as Peer, MontgomeryNamedRequest as Request, SecretKeyIdentity,
};
#[test]
fn raw_named_peers_do_not_accept_spki_or_other_curve_widths() {
    for (curve, length, base) in [(Curve::Curve25519, 32, 9), (Curve::Curve448, 56, 5)] {
        let mut raw = vec![0; length];
        raw[0] = base;
        let peer = Peer::from_bytes(curve, &raw).unwrap();
        assert_eq!(peer.curve(), curve);
        assert_eq!(peer.as_bytes(), raw);
        assert!(!format!("{peer:?}").contains(&format!("{raw:?}")));
        for bad in [
            vec![],
            vec![0; length],
            vec![9; length - 1],
            vec![9; length + 1],
            {
                let mut spki = vec![0x30, 0x2a, 0x30, 5, 6, 3, 43, 101, 110, 3, 33, 0];
                spki.extend(&raw);
                spki
            },
        ] {
            assert!(matches!(
                Peer::from_bytes(curve, &bad),
                Err(Error::InvalidPublicKey)
            ));
        }
        let mut alias = raw.clone();
        if length == 32 {
            alias[31] |= 0x80;
        }
        assert_eq!(Peer::from_bytes(curve, &alias).unwrap().as_bytes(), alias);
    }
}
#[test]
fn requests_validate_identity_bounds_and_redact_payloads() {
    let mut raw = [0; 32];
    raw[0] = 9;
    let peer = Peer::from_bytes(Curve::Curve25519, &raw).unwrap();
    for (id, label, valid) in [
        (&[][..], b"label".as_slice(), false),
        (&[1][..], &[][..], false),
        (&[1; 129][..], b"label".as_slice(), false),
        (&[1][..], &[1; 129][..], false),
        (&[1; 128][..], &[1; 128][..], true),
    ] {
        let pair = Pair {
            curve: Curve::Curve25519,
            id,
            label,
        };
        let request = Request {
            peer: &peer,
            identity: SecretKeyIdentity { id, label },
        };
        assert_eq!(pair.validate().is_ok(), valid);
        assert_eq!(request.validate().is_ok(), valid);
        if !valid {
            assert_eq!(request.validate().unwrap_err().kind(), ErrorKind::Input);
        }
        assert_eq!(
            format!("{pair:?}"),
            "MontgomeryNamedKeyPairRequest([REDACTED])"
        );
        assert_eq!(format!("{request:?}"), "MontgomeryNamedRequest([REDACTED])");
    }
}
