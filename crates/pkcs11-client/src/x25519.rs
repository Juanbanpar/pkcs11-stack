// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, ObjectRef, SecretKeyIdentity, X25519PublicKey};
use pkcs11_runtime::X25519Derivation;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

/// Public RFC 8410 id-X25519 SPKI with absent algorithm parameters.
/// Parsing checks noncontributory inputs but does not authenticate a peer.
#[derive(Clone, Debug)]
pub struct X25519Peer(X25519PublicKey);
/// X25519 agreement with a peer decoded from strict RFC 8410 SPKI DER.
pub struct X25519Request<'a> {
    /// Checked peer public key. The caller must authenticate its ownership.
    pub peer: &'a X25519Peer,
    /// New private, sensitive, nonextractable token secret identity.
    pub identity: SecretKeyIdentity<'a>,
}
impl X25519Request<'_> {
    fn runtime_request(&self) -> X25519Derivation<'_> {
        X25519Derivation {
            peer: self.peer.public_key(),
            id: self.identity.id,
            label: self.identity.label,
        }
    }
    /// Validate output identity bounds without provider calls.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(self.runtime_request().validate()?)
    }
}
impl std::fmt::Debug for X25519Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519Request([REDACTED])")
    }
}
impl X25519Peer {
    /// Decode exactly one canonical DER SPKI, at most 128 bytes. Edwards keys,
    /// X448, explicit/NULL parameters, unused bits and invalid input are rejected.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 128 {
            return Err(Error::InvalidPublicKey);
        }
        let spki =
            SubjectPublicKeyInfoOwned::from_der(bytes).map_err(|_| Error::InvalidPublicKey)?;
        if spki.to_der().map_err(|_| Error::InvalidPublicKey)? != bytes
            || spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.3.101.110")
            || spki.algorithm.parameters.is_some()
        {
            return Err(Error::InvalidPublicKey);
        }
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidPublicKey)?;
        Ok(Self(
            X25519PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?,
        ))
    }
    /// Public bytes suitable for the runtime's checked derivation request.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.0
    }
    /// Encode an RFC 8410 SPKI, preserving RFC 7748 public input encodings.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        encode(&self.0)
    }
}
fn encode(key: &X25519PublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.3.101.110"),
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(key.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?,
    }
    .to_der()
    .map_err(|_| Error::InvalidPublicKey)
}
impl ManagementSession<'_> {
    /// Generate a persistent RFC 8410 pair with a sensitive, nonextractable,
    /// derivation-only private key. Requires RW mode, bounded identity and no
    /// existing public/private ID. No retry/rollback; check session closure.
    pub fn generate_x25519_key_pair(
        &mut self,
        request: &crate::X25519KeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_x25519_key_pair(request)?;
        Ok(())
    }
    /// Import strict RFC 8410 public input as a public, untrusted X25519 object
    /// with operation permissions disabled. Requires RW mode, bounded identity
    /// and no existing public ID. Does not authenticate ownership or associate a
    /// private key. No retry/rollback; concurrent writers can race. Check closure.
    pub fn import_x25519_public_key(
        &mut self,
        key: &X25519Peer,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session
            .import_x25519_public_key(key.public_key(), id, label)?;
        Ok(())
    }
    /// Export one existing RFC 8410 X25519 public key as SPKI DER. Metadata and
    /// identity reads are bounded; private/secret values are never requested.
    pub fn export_x25519_public_key(&mut self, key: &ObjectRef) -> Result<Vec<u8>, Error> {
        encode(&self.session.x25519_public_key(key)?)
    }
    /// Derive once from an existing RFC 8410 X25519 private key, with CKD_NULL
    /// and a complete token-held 32-byte generic secret. Requires RW mode and
    /// checked peer input; private/secret bytes never cross the application API.
    /// Run HKDF-SHA256 separately on the result, with an authenticated protocol
    /// context. Failures may leave effects; no retry or rollback. Check closure.
    pub fn derive_x25519(
        &mut self,
        base: &ObjectRef,
        request: &X25519Request<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_x25519_secret(base, &request.runtime_request())?)
    }
}

impl ManagementSession<'_> {
    /// Derive once with explicit native KDF/output choices from a matching,
    /// protected private key in RW mode. Requires the exact peer profile; no
    /// OID/curveName conversion or KDF fallback occurs. Secret bytes stay on
    /// the token. Failures may leave objects; no retry/rollback. Authenticate
    /// peer ownership separately and check session closure on every result.
    pub fn derive_x25519_with_kdf(
        &mut self,
        base: &ObjectRef,
        peer: &X25519Peer,
        request: &crate::MontgomeryKdfRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.derive_x25519_with_kdf(
            base,
            peer.public_key(),
            &request.runtime_request(),
        )?)
    }
}
