// SPDX-License-Identifier: MIT OR Apache-2.0
//! Application wrappers for X25519/X448 generation, import, export and derivation.

use crate::{Error, ManagementSession, ObjectRef, Pkcs11Uri, Provider, PublicKeyRef};
use pkcs11_runtime::{
    MontgomeryCapabilities, MontgomeryCurve, MontgomeryDerivation, MontgomeryPublicKey,
};
use x509_cert::{
    der::{
        Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

fn oid(curve: MontgomeryCurve) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match curve {
        MontgomeryCurve::X25519 => "1.3.101.110",
        MontgomeryCurve::X448 => "1.3.101.111",
    })
}

fn spki(key: &MontgomeryPublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oid(key.curve()),
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(key.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?,
    }
    .to_der()
    .map_err(|_| Error::InvalidPublicKey)
}

impl Provider {
    /// Inspect advertised Montgomery generation/derivation choices.
    pub fn montgomery_capabilities(
        &self,
        token: &Pkcs11Uri,
    ) -> Result<Vec<MontgomeryCapabilities>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .montgomery_capabilities()?)
    }
}

impl ManagementSession<'_> {
    /// Generate a persistent X25519/X448 pair.
    pub fn generate_montgomery_key_pair(
        &mut self,
        curve: MontgomeryCurve,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session
            .generate_montgomery_key_pair(curve, id, label)?;
        Ok(())
    }

    /// Read the private key's Montgomery curve without reading key bytes.
    pub fn montgomery_private_curve(
        &mut self,
        key: &crate::PrivateKeyRef,
    ) -> Result<MontgomeryCurve, Error> {
        Ok(self.session.montgomery_private_curve(key)?)
    }

    /// Read a public Montgomery key as raw RFC 7748 bytes.
    pub fn montgomery_public_key(
        &mut self,
        key: &PublicKeyRef,
    ) -> Result<MontgomeryPublicKey, Error> {
        Ok(self.session.montgomery_public_key(key)?)
    }

    /// Export a public Montgomery key as RFC 8410 SPKI.
    pub fn export_montgomery_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        spki(&self.session.montgomery_public_key(key)?)
    }

    /// Import a checked public Montgomery key for derivation only.
    pub fn import_montgomery_public_key(
        &mut self,
        key: &MontgomeryPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session.import_montgomery_public_key(key, id, label)?;
        Ok(())
    }

    /// Derive one persistent key from a Montgomery private key.
    pub fn derive_montgomery(
        &mut self,
        base: &ObjectRef,
        request: &MontgomeryDerivation<'_>,
    ) -> Result<(), Error> {
        self.session.derive_montgomery(base, request)?;
        Ok(())
    }
}
