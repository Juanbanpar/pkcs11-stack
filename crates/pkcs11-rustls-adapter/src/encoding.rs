// SPDX-License-Identifier: MIT OR Apache-2.0
//! PKCS#11 raw ECDSA to TLS DER; no provider or session access.
use crate::Error;
use pkcs11_runtime::KeyKind;

pub(crate) fn format_signature(key: KeyKind, signature: Vec<u8>) -> Result<Vec<u8>, Error> {
    let KeyKind::Ec(curve) = key else {
        return Ok(signature);
    };
    let width = curve.bits().div_ceil(8);
    if signature.len() != width * 2 {
        return Err(Error::InvalidSignature);
    }
    fn integer(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .ok_or(Error::InvalidSignature)?;
        let bytes = &bytes[start..];
        let padding = usize::from(bytes[0] & 0x80 != 0);
        out.extend([2, (bytes.len() + padding) as u8]);
        if padding != 0 {
            out.push(0);
        }
        out.extend_from_slice(bytes);
        Ok(())
    }
    let mut values = Vec::new();
    integer(&signature[..width], &mut values)?;
    integer(&signature[width..], &mut values)?;
    let mut der = vec![0x30];
    if values.len() < 128 {
        der.push(values.len() as u8);
    } else {
        der.extend([0x81, values.len() as u8]);
    }
    der.extend(values);
    Ok(der)
}

#[cfg(test)]
mod properties {
    use super::*;
    use der::{Decode, Encode, Sequence, asn1::UintRef};
    use pkcs11_runtime::NamedCurve;
    use proptest::prelude::*;

    // Independent DER decoding checks tags, signs, lengths and minimal encoding.
    #[derive(Sequence)]
    struct Integers<'a> {
        r: UintRef<'a>,
        s: UintRef<'a>,
    }

    fn curve(index: usize) -> NamedCurve {
        [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521][index]
    }

    proptest! {
        #[test]
        fn raw_scalars_preserve_values_in_canonical_der(
            index in 0usize..3,
            bytes in prop::collection::vec(any::<u8>(), 132),
            leading_r in 0usize..67,
            leading_s in 0usize..67,
        ) {
            let curve = curve(index);
            let width = curve.bits().div_ceil(8);
            let mut raw = bytes[..2 * width].to_vec();
            raw[..leading_r.min(width)].fill(0);
            raw[width..width + leading_s.min(width)].fill(0);
            let (r, s) = raw.split_at(width);
            let output = format_signature(KeyKind::Ec(curve), raw.clone());
            if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
                prop_assert!(matches!(output, Err(Error::InvalidSignature)));
            } else {
                let encoded = output.unwrap();
                let decoded = Integers::from_der(&encoded).unwrap();
                prop_assert_eq!(decoded.to_der().unwrap(), encoded.clone());
                let normalized_r = &r[r.iter().position(|b| *b != 0).unwrap()..];
                let normalized_s = &s[s.iter().position(|b| *b != 0).unwrap()..];
                prop_assert_eq!(decoded.r.as_bytes(), normalized_r);
                prop_assert_eq!(decoded.s.as_bytes(), normalized_s);
                let mut trailing = encoded.clone();
                trailing.push(0);
                prop_assert!(Integers::from_der(&trailing).is_err());
            }
        }

        #[test]
        fn incorrect_raw_width_is_rejected(index in 0usize..3, bytes in prop::collection::vec(any::<u8>(), 0..160)) {
            let curve = curve(index);
            let expected = curve.bits().div_ceil(8) * 2;
            if bytes.len() != expected {
                prop_assert!(matches!(format_signature(KeyKind::Ec(curve), bytes), Err(Error::InvalidSignature)));
            }
        }

        #[test]
        fn rsa_representation_is_unchanged(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            // RSA validity/width checks belong to signing and verification, not DER formatting.
            prop_assert_eq!(format_signature(KeyKind::Rsa { bits: 2048 }, bytes.clone()).unwrap(), bytes);
        }
    }
}
