// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, ManagementSession, NamedCurve, ObjectRef};
use p256::elliptic_curve::sec1::ToEncodedPoint;
pub use pkcs11_runtime::{
    AesKeyWrapAlgorithm, AesKeyWrapCapabilities, EcdhKdf, EcdhOutput, KeyOperation,
    KeyOperationProfile,
};
use x509_cert::{
    der::{Decode, Encode, asn1::ObjectIdentifier},
    spki::SubjectPublicKeyInfoOwned,
};

/// Validated, uncompressed peer point from a named-curve EC SPKI DER document.
/// Does not authenticate the peer or prove possession of its private key.
#[derive(Clone)]
pub struct EcdhPeer {
    curve: NamedCurve,
    point: Vec<u8>,
}
impl std::fmt::Debug for EcdhPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdhPeer([REDACTED])")
    }
}
impl EcdhPeer {
    /// Parse one canonical EC SPKI DER public key; validate its point on P-256/384/521.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1024 {
            return Err(Error::InvalidPublicKey);
        }
        let spki =
            SubjectPublicKeyInfoOwned::from_der(bytes).map_err(|_| Error::InvalidPublicKey)?;
        if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
            || spki.to_der().map_err(|_| Error::InvalidPublicKey)? != bytes
        {
            return Err(Error::InvalidPublicKey);
        }
        let params = spki.algorithm.parameters.ok_or(Error::InvalidPublicKey)?;
        let oid: ObjectIdentifier = params.decode_as().map_err(|_| Error::InvalidPublicKey)?;
        let encoded = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidPublicKey)?;
        let (curve, point) = match oid.to_string().as_str() {
            "1.2.840.10045.3.1.7" => {
                let key = p256::PublicKey::from_sec1_bytes(encoded)
                    .map_err(|_| Error::InvalidPublicKey)?;
                (
                    NamedCurve::P256,
                    key.to_encoded_point(false).as_bytes().to_vec(),
                )
            }
            "1.3.132.0.34" => {
                let key = p384::PublicKey::from_sec1_bytes(encoded)
                    .map_err(|_| Error::InvalidPublicKey)?;
                (
                    NamedCurve::P384,
                    key.to_encoded_point(false).as_bytes().to_vec(),
                )
            }
            "1.3.132.0.35" => {
                let key = p521::PublicKey::from_sec1_bytes(encoded)
                    .map_err(|_| Error::InvalidPublicKey)?;
                (
                    NamedCurve::P521,
                    key.to_encoded_point(false).as_bytes().to_vec(),
                )
            }
            _ => return Err(Error::InvalidPublicKey),
        };
        Ok(Self { curve, point })
    }
    pub(crate) fn point(&self) -> &[u8] {
        &self.point
    }
    /// Named curve that the base key must also use.
    pub fn curve(&self) -> NamedCurve {
        self.curve
    }
}
/// Persistent identity for a newly created secret key; bounded to 128 bytes per field.
#[derive(Clone, Copy)]
pub struct SecretKeyIdentity<'a> {
    /// Nonempty CKA_ID; an existing secret key with this ID is rejected.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL.
    pub label: &'a [u8],
}
/// Raw ECDH with an explicit null KDF; result is a token-held generic secret.
pub struct DeriveRequest<'a> {
    /// Validated peer public key, on the same curve as the selected base key.
    pub peer: &'a EcdhPeer,
    /// New sensitive, nonextractable private secret key identity.
    pub identity: SecretKeyIdentity<'a>,
}
/// ECDH with an explicit KDF and purpose-restricted persistent output.
/// Public points are validated during EcdhPeer construction.
pub struct EcdhRequest<'a> {
    /// Validated peer; its curve must match the selected base key.
    pub peer: &'a EcdhPeer,
    /// Explicit null, ANSI X9.63 or NIST SP 800-56A SHA-2 KDF.
    pub kdf: EcdhKdf,
    /// Public shared info, bounded to 4096 bytes; empty for the null KDF.
    pub shared_info: &'a [u8],
    /// Output type, length and permissions.
    pub output: EcdhOutput,
    /// New sensitive, nonextractable secret identity.
    pub identity: SecretKeyIdentity<'a>,
}
impl EcdhRequest<'_> {
    fn runtime_request(&self) -> pkcs11_runtime::EcdhKeyRequest<'_> {
        pkcs11_runtime::EcdhKeyRequest {
            curve: self.peer.curve,
            peer: &self.peer.point,
            kdf: self.kdf,
            shared_info: self.shared_info,
            output: self.output,
            id: self.identity.id,
            label: self.identity.label,
        }
    }
    /// Validate all non-provider parameters without opening a session.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(self.runtime_request().validate()?)
    }
}
/// AES wrap request; the selected target must be an extractable AES key.
pub struct WrapRequest<'a> {
    /// Freshly resolved persistent target; no key value is read by the client.
    pub target: &'a ObjectRef,
}
/// AES KW/KWP unwrap request; ciphertext contains key bytes only, without metadata.
pub struct UnwrapRequest<'a> {
    /// Exactly 24/32/40 bytes for AES-128/192/256 respectively.
    pub wrapped: &'a [u8],
    /// New sensitive, nonextractable private secret key identity.
    pub identity: SecretKeyIdentity<'a>,
}
macro_rules! redacted { ($($name:ident),+) => { $(impl std::fmt::Debug for $name<'_> { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) } })+ }; }
redacted!(
    SecretKeyIdentity,
    DeriveRequest,
    EcdhRequest,
    WrapRequest,
    UnwrapRequest
);
impl ManagementSession<'_> {
    /// Advisory KW/KWP choices for Wrap or Unwrap; does not perform crypto or
    /// inspect a future target. Execution resolves and checks permissions again.
    pub fn aes_key_wrap_options(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<AesKeyWrapCapabilities, Error> {
        Ok(self.session.aes_key_wrap_capabilities(key, operation)?)
    }
    /// Wrap once with explicit KW or KWP, preserving trust and extractability
    /// policy. Default IV only; no metadata, downgrade or algorithm retry.
    pub fn wrap_with_algorithm(
        &mut self,
        wrapping: &ObjectRef,
        request: &WrapRequest<'_>,
        algorithm: AesKeyWrapAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .session
            .wrap_aes_key_with_algorithm(wrapping, request.target, algorithm)?)
    }
    /// Unwrap once into a sensitive, nonextractable AES encryption/decryption key.
    /// Only 128/192/256-bit AES outputs are supported. Requires RW access.
    /// Provider failures may have effects; no retry or rollback is performed.
    pub fn unwrap_with_algorithm(
        &mut self,
        unwrapping: &ObjectRef,
        request: &UnwrapRequest<'_>,
        algorithm: AesKeyWrapAlgorithm,
    ) -> Result<(), Error> {
        Ok(self.session.unwrap_aes_key_with_algorithm(
            unwrapping,
            request.wrapped,
            request.identity.id,
            request.identity.label,
            algorithm,
        )?)
    }
    /// Advisory profile after current key, permission and provider checks, with no mutation.
    pub fn key_operation_options(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<KeyOperationProfile, Error> {
        Ok(self.session.key_operation_profile(key, operation)?)
    }
    /// Derive raw ECDH material on the token. Only further derivation is permitted.
    /// It is not an encryption key; raw shared secrets never leave the provider.
    /// Peer authentication and the subsequent KDF are the caller's responsibility.
    pub fn derive(&mut self, base: &ObjectRef, request: &DeriveRequest<'_>) -> Result<(), Error> {
        Ok(self.session.derive_ecdh_secret(
            base,
            &pkcs11_runtime::EcdhDerivation {
                curve: request.peer.curve,
                peer: &request.peer.point,
                id: request.identity.id,
                label: request.identity.label,
            },
        )?)
    }
    /// Derive once on the token with explicit KDF, context and output permissions.
    /// Requires RW access. Provider KDF support is not implied by the mechanism
    /// flag. No downgrade, retry or software fallback occurs after rejection.
    pub fn derive_ecdh(
        &mut self,
        base: &ObjectRef,
        request: &EcdhRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .session
            .derive_ecdh_key(base, &request.runtime_request())?)
    }
    /// Wrap an AES key once with RFC 3394; no template override or extractability change.
    pub fn wrap(
        &mut self,
        wrapping: &ObjectRef,
        request: &WrapRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.wrap_aes_key(wrapping, request.target)?)
    }
    /// Unwrap once into a persistent private AES encryption/decryption key.
    /// No automatic retry or rollback; even a reported failure can have token effects.
    pub fn unwrap(
        &mut self,
        unwrapping: &ObjectRef,
        request: &UnwrapRequest<'_>,
    ) -> Result<(), Error> {
        Ok(self.session.unwrap_aes_key(
            unwrapping,
            request.wrapped,
            request.identity.id,
            request.identity.label,
        )?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_validation_and_requests_reject_invalid_input_and_redact_payloads() {
        for (name, curve) in [
            ("p256", NamedCurve::P256),
            ("p384", NamedCurve::P384),
            ("p521", NamedCurve::P521),
        ] {
            let certificate = crate::Certificate::from_der(
                std::fs::read(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join(format!("tests/fixtures/{name}.der")),
                )
                .unwrap(),
            )
            .unwrap();
            let peer = EcdhPeer::from_spki_der(certificate.spki_der()).unwrap();
            assert_eq!(peer.curve(), curve);
            assert_eq!(peer.point[0], 4);
            let request = DeriveRequest {
                peer: &peer,
                identity: SecretKeyIdentity {
                    id: b"id-canary",
                    label: b"label-canary",
                },
            };
            assert!(!format!("{request:?}").contains("canary"));
            let mut bad = certificate.spki_der().to_vec();
            let len = bad.len();
            bad[len - 1] ^= 1;
            assert!(EcdhPeer::from_spki_der(&bad).is_err());
            let mut extra = certificate.spki_der().to_vec();
            extra.push(0);
            assert!(EcdhPeer::from_spki_der(&extra).is_err());
        }
        assert!(EcdhPeer::from_spki_der(b"invalid").is_err());
        let request = UnwrapRequest {
            wrapped: b"wrapped-canary",
            identity: SecretKeyIdentity {
                id: b"id",
                label: b"label",
            },
        };
        assert!(!format!("{request:?}").contains("canary"));
    }
}
