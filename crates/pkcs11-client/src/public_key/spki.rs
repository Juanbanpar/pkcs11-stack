// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

pub(crate) fn encode_raw_spki(oid: ObjectIdentifier, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?,
    }
    .to_der()
    .map_err(|_| Error::InvalidPublicKey)
}

pub(crate) fn decode_canonical_spki(der: &[u8]) -> Result<SubjectPublicKeyInfoOwned, Error> {
    let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| Error::InvalidPublicKey)?;
    if spki.to_der().map_err(|_| Error::InvalidPublicKey)? != der {
        return Err(Error::InvalidPublicKey);
    }
    Ok(spki)
}

pub(crate) fn raw_key_bytes(spki: &SubjectPublicKeyInfoOwned) -> Result<&[u8], Error> {
    if spki.algorithm.parameters.is_some() {
        return Err(Error::InvalidPublicKey);
    }
    spki.subject_public_key
        .as_bytes()
        .ok_or(Error::InvalidPublicKey)
}
