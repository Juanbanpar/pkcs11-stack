// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, ObjectRef, SecretKeyIdentity, X448PublicKey};
use pkcs11_runtime::X448Derivation;
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{BitString, ObjectIdentifier},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

/// Public RFC 8410 id-X448 SPKI with absent algorithm parameters.
/// Parsing checks noncontributory inputs but does not authenticate a peer.
#[derive(Clone, Debug)]
pub struct X448Peer(X448PublicKey);
/// X448 agreement with a peer decoded from strict RFC 8410 SPKI DER.
pub struct X448Request<'a> {
    /// Checked peer public key. The caller must authenticate its ownership.
    pub peer: &'a X448Peer,
    /// Explicit null or SHA-512 KDF.
    pub kdf: crate::X448Kdf,
    /// Public protocol context, at most 4096 bytes; empty with the null KDF.
    pub shared_info: &'a [u8],
    /// Protected output purpose and length.
    pub output: crate::X448Output,
    /// New private, sensitive, nonextractable token secret identity.
    pub identity: SecretKeyIdentity<'a>,
}
impl X448Request<'_> {
    fn runtime_request(&self) -> X448Derivation<'_> {
        X448Derivation {
            kdf: self.kdf,
            output: self.output,
            shared_info: self.shared_info,
            peer: self.peer.public_key(),
            id: self.identity.id,
            label: self.identity.label,
        }
    }
    /// Validate identity, context bounds and KDF/output compatibility without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(self.runtime_request().validate()?)
    }
}
impl std::fmt::Debug for X448Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X448Request([REDACTED])")
    }
}
impl X448Peer {
    /// Decode exactly one canonical DER SPKI, at most 128 bytes. Edwards keys,
    /// X25519, explicit/NULL parameters, unused bits and invalid input are rejected.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 128 {
            return Err(Error::InvalidPublicKey);
        }
        let spki =
            SubjectPublicKeyInfoOwned::from_der(bytes).map_err(|_| Error::InvalidPublicKey)?;
        if spki.to_der().map_err(|_| Error::InvalidPublicKey)? != bytes
            || spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.3.101.111")
            || spki.algorithm.parameters.is_some()
        {
            return Err(Error::InvalidPublicKey);
        }
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidPublicKey)?;
        Ok(Self(
            X448PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?,
        ))
    }
    /// Public bytes suitable for the runtime's checked derivation request.
    pub fn public_key(&self) -> &X448PublicKey {
        &self.0
    }
    /// Encode an RFC 8410 SPKI, preserving RFC 7748 public input encodings.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        encode(&self.0)
    }
}
fn encode(key: &X448PublicKey) -> Result<Vec<u8>, Error> {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.3.101.111"),
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
    pub fn generate_x448_key_pair(
        &mut self,
        request: &crate::X448KeyPairRequest<'_>,
    ) -> Result<(), Error> {
        self.session.generate_x448_key_pair(request)?;
        Ok(())
    }
    /// Import strict RFC 8410 public input as a public, untrusted X448 object
    /// with operation permissions disabled. Requires RW mode, bounded identity
    /// and no existing public ID. Does not authenticate ownership or associate a
    /// private key. No retry/rollback; concurrent writers can race. Check closure.
    pub fn import_x448_public_key(
        &mut self,
        key: &X448Peer,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session
            .import_x448_public_key(key.public_key(), id, label)?;
        Ok(())
    }

    /// Export one existing RFC 8410 X448 public key as SPKI DER, using bounded
    /// metadata/identity reads. No private or secret values are requested.
    pub fn export_x448_public_key(&mut self, key: &ObjectRef) -> Result<Vec<u8>, Error> {
        encode(&self.session.x448_public_key(key)?)
    }
    /// Derive once with explicit KDF/output choices from an existing RFC 8410
    /// X448 private key. Requires RW mode and protected derivation permission.
    /// Outputs stay on the token. Raw 56-byte output cannot feed this app's HKDF
    /// profile; choose a SHA-512 KDF and 64-byte derivation output for HKDF-SHA512.
    /// Failures may leave objects; no retry/rollback. Authenticate the peer and
    /// check session closure before releasing results.
    pub fn derive_x448(
        &mut self,
        base: &ObjectRef,
        request: &X448Request<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_x448_key(base, &request.runtime_request())?)
    }
}

impl ManagementSession<'_> {
    /// Derive once with explicit native KDF/output choices from a matching,
    /// protected private key in RW mode. Requires the exact peer profile; no
    /// OID/curveName conversion or KDF fallback occurs. Secret bytes stay on
    /// the token. Failures may leave objects; no retry/rollback. Authenticate
    /// peer ownership separately and check session closure on every result.
    pub fn derive_x448_with_kdf(
        &mut self,
        base: &ObjectRef,
        peer: &X448Peer,
        request: &crate::MontgomeryKdfRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.derive_x448_with_kdf(
            base,
            peer.public_key(),
            &request.runtime_request(),
        )?)
    }
}
