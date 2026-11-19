// SPDX-License-Identifier: MIT OR Apache-2.0
use x509_cert::{
    der::{Decode, Encode, Tagged, asn1::Any},
    spki::SubjectPublicKeyInfoOwned,
};

pub(crate) fn replace_spki(der: &[u8], spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let mut certificate = Vec::<Any>::from_der(der).unwrap();
    let mut tbs = certificate[0].decode_as::<Vec<Any>>().unwrap();
    // TBSCertificate's explicit version field may be omitted.
    let spki_index = 5 + usize::from(tbs[0].tag().is_context_specific());
    tbs[spki_index] = Any::encode_from(spki).unwrap();
    certificate[0] = Any::encode_from(&tbs).unwrap();
    certificate.to_der().unwrap()
}
