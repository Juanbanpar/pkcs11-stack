// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, ManagementSession, MlKemCapabilities, MlKemOperation, MlKemParameterSet, MlKemRequest,
    ObjectRef, Pkcs11Uri, PrivateKeyRef, Provider, PublicKeyRef,
};

use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

fn oid(parameter: MlKemParameterSet) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match parameter {
        MlKemParameterSet::MlKem512 => "2.16.840.1.101.3.4.4.1",
        MlKemParameterSet::MlKem768 => "2.16.840.1.101.3.4.4.2",
        MlKemParameterSet::MlKem1024 => "2.16.840.1.101.3.4.4.3",
    })
}

/// Validated public ML-KEM encapsulation key, with RFC 9935 SPKI conversion.
/// Validation does not authenticate its owner or prove private-key possession.
#[derive(Clone, Debug)]
pub struct MlKemPublicKey(pkcs11_runtime::MlKemPublicKey);
impl MlKemPublicKey {
    /// Validate raw FIPS 203 public-key length and canonical coefficient encoding.
    pub fn from_bytes(parameter: MlKemParameterSet, bytes: Vec<u8>) -> Result<Self, Error> {
        pkcs11_runtime::MlKemPublicKey::from_bytes(parameter, bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }
    /// Decode bounded RFC 9935 DER with absent parameters and a byte-aligned raw key.
    /// Rejects unsupported algorithms, trailing data and noncanonical coefficients.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() > 2048 {
            return Err(Error::InvalidPublicKey);
        }
        let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| Error::InvalidPublicKey)?;
        let parameter = [
            MlKemParameterSet::MlKem512,
            MlKemParameterSet::MlKem768,
            MlKemParameterSet::MlKem1024,
        ]
        .into_iter()
        .find(|parameter| oid(*parameter) == spki.algorithm.oid)
        .ok_or(Error::InvalidPublicKey)?;
        if spki.algorithm.parameters.is_some() {
            return Err(Error::InvalidPublicKey);
        }
        Self::from_bytes(
            parameter,
            spki.subject_public_key
                .as_bytes()
                .ok_or(Error::InvalidPublicKey)?
                .to_vec(),
        )
    }
    /// Encode RFC 9935 SubjectPublicKeyInfo DER, without algorithm parameters.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: oid(self.parameter_set()),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(self.as_bytes())
                .map_err(|_| Error::InvalidPublicKey)?,
        }
        .to_der()
        .map_err(|_| Error::InvalidPublicKey)
    }
    /// FIPS 203 parameter set.
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.0.parameter_set()
    }
    /// Validated raw encapsulation-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Provider {
    /// Advertised ML-KEM generation parameters; template acceptance remains provider-specific.
    pub fn ml_kem_generation_options(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<Vec<MlKemParameterSet>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .ml_kem_generation_options()?)
    }
}
impl ManagementSession<'_> {
    /// Generate a persistent ML-KEM pair in an RW session. The private key stays
    /// sensitive and nonextractable; no private value or seed is read or imported.
    /// Explicit ID/label selection follows the signing-key generation contract.
    pub fn generate_ml_kem_key_pair(
        &mut self,
        parameter: MlKemParameterSet,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session
            .generate_ml_kem_key_pair(parameter, id, label)?;
        Ok(())
    }
    /// Export a uniquely selected, non-private ML-KEM public object as RFC 9935 DER.
    /// Does not require encapsulation permission or read private key material.
    pub fn export_ml_kem_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        MlKemPublicKey(self.session.ml_kem_public_key(key)?).to_spki_der()
    }
    /// Import a validated public encapsulation key in an RW session.
    /// Duplicate IDs remain possible; existing objects are not overwritten.
    /// Authenticate the peer through the application protocol before using its key.
    pub fn import_ml_kem_public_key(
        &mut self,
        key: &MlKemPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session.import_ml_kem_public_key(&key.0, id, label)?;
        Ok(())
    }
    /// Read current parameters and validate the chosen direction's permissions,
    /// mechanism flags and entry point. Does not encapsulate or decapsulate.
    pub fn ml_kem_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MlKemOperation,
    ) -> Result<MlKemCapabilities, Error> {
        Ok(self.session.ml_kem_capabilities(key, operation)?)
    }
    /// Return public ciphertext and retain the raw shared secret on the token under
    /// the request's ID/label. The new private generic secret permits only derivation;
    /// it is sensitive, nonextractable and 32 bytes long. Requires RW mode.
    /// Apply a protocol KDF and authenticate the peer before use. No retry or rollback;
    /// close this session before releasing ciphertext when checked cleanup is required.
    pub fn encapsulate_ml_kem(
        &mut self,
        key: &PublicKeyRef,
        request: &MlKemRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.encapsulate_ml_kem(key, request)?)
    }
    /// Retain a decapsulated raw secret with the same restrictions as encapsulation.
    /// Exact ciphertext length is checked before crypto. Same-length altered ciphertexts
    /// may succeed with a different secret through ML-KEM implicit rejection.
    /// No shared-secret bytes leave the token; no authentication is inferred.
    pub fn decapsulate_ml_kem(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlKemRequest<'_>,
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.decapsulate_ml_kem(key, request, ciphertext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::asn1::{Any, OctetString};

    const FIXTURES: &[(MlKemParameterSet, &[u8])] = &[
        (
            MlKemParameterSet::MlKem512,
            include_bytes!("../tests/fixtures/mlkem512.spki.der"),
        ),
        (
            MlKemParameterSet::MlKem768,
            include_bytes!("../tests/fixtures/mlkem768.spki.der"),
        ),
        (
            MlKemParameterSet::MlKem1024,
            include_bytes!("../tests/fixtures/mlkem1024.spki.der"),
        ),
    ];
    #[test]
    fn openssl_public_keys_roundtrip_without_changing_encoding() {
        for &(parameter, der) in FIXTURES {
            let key = MlKemPublicKey::from_spki_der(der).unwrap();
            assert_eq!(key.parameter_set(), parameter);
            assert_eq!(key.as_bytes().len(), parameter.public_key_length());
            assert_eq!(key.to_spki_der().unwrap(), der);
        }
    }
    #[test]
    fn malformed_or_noncanonical_public_keys_are_rejected() {
        for &(_, der) in FIXTURES {
            let original = SubjectPublicKeyInfoOwned::from_der(der).unwrap();
            let mut cases = vec![vec![], vec![0; 2049], der[..der.len() - 1].to_vec()];
            let mut trailing = der.to_vec();
            trailing.push(0);
            cases.push(trailing);
            let mut spki = original.clone();
            spki.algorithm.parameters = Some(Any::null());
            cases.push(spki.to_der().unwrap());
            spki = original.clone();
            spki.algorithm.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.4");
            cases.push(spki.to_der().unwrap());
            spki = original.clone();
            let raw = spki.subject_public_key.as_bytes().unwrap().to_vec();
            spki.subject_public_key = BitString::from_bytes(&raw[..raw.len() - 1]).unwrap();
            cases.push(spki.to_der().unwrap());
            let mut noncanonical = raw.clone();
            noncanonical[..3].fill(0xFF);
            spki.subject_public_key = BitString::from_bytes(&noncanonical).unwrap();
            cases.push(spki.to_der().unwrap());
            let mut unaligned = raw.clone();
            *unaligned.last_mut().unwrap() &= 0xFE;
            spki.subject_public_key = BitString::new(1, unaligned).unwrap();
            cases.push(spki.to_der().unwrap());
            spki.subject_public_key =
                BitString::from_bytes(&OctetString::new(raw).unwrap().to_der().unwrap()).unwrap();
            cases.push(spki.to_der().unwrap());
            for bytes in cases {
                assert!(matches!(
                    MlKemPublicKey::from_spki_der(&bytes),
                    Err(Error::InvalidPublicKey)
                ));
            }
        }
    }
}
