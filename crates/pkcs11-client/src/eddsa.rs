// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, Authentication, Client, EdDsaCapabilities, EdDsaCurve, EdDsaRequest, Error, KeyType,
    ManagementSession, MechanismType, ObjectClass, ObjectRef, Pin, Pkcs11Uri, PrivateKeyRef,
    Provider, PublicKeyRef,
};
use x509_cert::{
    der::{
        Decode, Encode,
        asn1::{BitString, ObjectIdentifier, OctetString},
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

enum VerificationKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    Ed448(Box<ed448_goldilocks_plus::VerifyingKey>),
}

/// Strictly decoded pure EdDSA public key; contains no token handle or private material.
pub struct EdDsaVerifyingKey {
    key: VerificationKey,
    bytes: Vec<u8>,
}
impl std::fmt::Debug for EdDsaVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDsaVerifyingKey")
            .field("curve", &self.curve())
            .finish_non_exhaustive()
    }
}
fn oid(curve: EdDsaCurve) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(match curve {
        EdDsaCurve::Ed25519 => "1.3.101.112",
        EdDsaCurve::Ed448 => "1.3.101.113",
    })
}
impl EdDsaVerifyingKey {
    /// Decode a canonical, nonidentity, prime-subgroup RFC 8032 public key.
    /// Parsing does not establish ownership or certificate trust.
    pub fn from_bytes(curve: EdDsaCurve, bytes: &[u8]) -> Result<Self, Error> {
        let key = match curve {
            EdDsaCurve::Ed25519 => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(
                    bytes.try_into().map_err(|_| Error::InvalidPublicKey)?,
                )
                .map_err(|_| Error::InvalidPublicKey)?;
                let point = key.to_edwards();
                if key.is_weak() || !point.is_torsion_free() || point.compress().as_bytes() != bytes
                {
                    return Err(Error::InvalidPublicKey);
                }
                VerificationKey::Ed25519(key)
            }
            EdDsaCurve::Ed448 => {
                let key = ed448_goldilocks_plus::VerifyingKey::from_bytes(
                    bytes.try_into().map_err(|_| Error::InvalidPublicKey)?,
                )
                .map_err(|_| Error::InvalidPublicKey)?;
                // The library decoder rejects identity and non-prime-subgroup points.
                if key.to_edwards().compress().as_bytes() != bytes {
                    return Err(Error::InvalidPublicKey);
                }
                VerificationKey::Ed448(Box::new(key))
            }
        };
        Ok(Self {
            key,
            bytes: bytes.to_vec(),
        })
    }
    /// Decode exactly one RFC 8410 SPKI. Algorithm parameters must be absent and
    /// the BIT STRING must contain the raw, byte-aligned public key.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        if der.len() > 4096 {
            return Err(Error::InvalidPublicKey);
        }
        let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| Error::InvalidPublicKey)?;
        if spki.to_der().map_err(|_| Error::InvalidPublicKey)? != der {
            return Err(Error::InvalidPublicKey);
        }
        let curve = [EdDsaCurve::Ed25519, EdDsaCurve::Ed448]
            .into_iter()
            .find(|&curve| oid(curve) == spki.algorithm.oid)
            .ok_or(Error::UnsupportedCertificateKey)?;
        if spki.algorithm.parameters.is_some() {
            return Err(Error::InvalidPublicKey);
        }
        Self::from_bytes(
            curve,
            spki.subject_public_key
                .as_bytes()
                .ok_or(Error::InvalidPublicKey)?,
        )
    }
    /// Public-key curve.
    pub fn curve(&self) -> EdDsaCurve {
        match &self.key {
            VerificationKey::Ed25519(_) => EdDsaCurve::Ed25519,
            VerificationKey::Ed448(_) => EdDsaCurve::Ed448,
        }
    }
    /// Raw canonical RFC 8032 public-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Encode an RFC 8410 SPKI with absent parameters.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: oid(self.curve()),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(self.as_bytes())
                .map_err(|_| Error::InvalidPublicKey)?,
        }
        .to_der()
        .map_err(|_| Error::InvalidPublicKey)
    }
    /// Check the explicit request curve without authentication or token access.
    pub fn validate_request(&self, request: &EdDsaRequest<'_>) -> Result<(), Error> {
        if self.curve() != request.curve {
            return Err(Error::UnsupportedVerification);
        }
        Ok(())
    }
    /// Verify an original message in software using pure RFC 8032 EdDSA.
    /// Malformed and nonmatching signatures return `SignatureMismatch`.
    pub fn verify_signature(
        &self,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.validate_request(request)?;
        let mismatch = |_| Error::SignatureMismatch;
        match &self.key {
            VerificationKey::Ed25519(key) => key
                .verify_strict(
                    request.message,
                    &ed25519_dalek::Signature::from_slice(signature).map_err(mismatch)?,
                )
                .map_err(mismatch),
            VerificationKey::Ed448(key) => {
                let signature = ed448_goldilocks_plus::Signature::try_from(signature)
                    .map_err(|_| Error::SignatureMismatch)?;
                // Recompression also rejects unused high bits and noncanonical R encodings.
                let r = signature.r();
                let point = Option::<ed448_goldilocks_plus::EdwardsPoint>::from(r.decompress())
                    .ok_or(Error::SignatureMismatch)?;
                if point.compress() != r {
                    return Err(Error::SignatureMismatch);
                }
                key.verify_raw(&signature, request.message)
                    .map_err(mismatch)
            }
        }
    }
}
fn verification_error(error: pkcs11_runtime::Error) -> Error {
    match error {
        pkcs11_runtime::Error::SignatureMismatch => Error::SignatureMismatch,
        other => other.into(),
    }
}
fn export(key: pkcs11_runtime::EdDsaPublicKey) -> Result<Vec<u8>, Error> {
    EdDsaVerifyingKey::from_bytes(key.curve(), key.as_bytes())?.to_spki_der()
}
impl Provider {
    /// Advertised Edwards generation choices; does not prove template acceptance.
    pub fn eddsa_generation_options(&self, token: &Pkcs11Uri) -> Result<Vec<EdDsaCurve>, Error> {
        Ok(self
            .module
            .resolve_token_uri(token)?
            .eddsa_generation_options()?)
    }
}
impl ManagementSession<'_> {
    /// Generate one sensitive, nonextractable, persistent EdDSA signing pair.
    /// Requires RW mode; bounded IDs/labels and existing pair IDs are checked.
    /// No retry or rollback; check session closure before releasing results.
    pub fn generate_eddsa_key_pair(
        &mut self,
        curve: EdDsaCurve,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(), Error> {
        self.session
            .generate_eddsa_key_pair(curve, id, label, always_authenticate)?;
        Ok(())
    }
    /// Rediscover the selected public/private Edwards key's permissions and curve.
    pub fn eddsa_capabilities(&mut self, key: &ObjectRef) -> Result<EdDsaCapabilities, Error> {
        Ok(self.session.eddsa_capabilities(key)?)
    }
    /// Sign once with pure native EdDSA. The classical digest policy does not apply.
    pub fn sign_eddsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &EdDsaRequest<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.sign_eddsa(key, request, context_pin)?)
    }
    /// Verify once on the token; a mismatch leaves the session reusable.
    pub fn verify_eddsa(
        &mut self,
        key: &PublicKeyRef,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_eddsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a public, non-private Edwards object as strictly validated RFC 8410 SPKI.
    pub fn export_eddsa_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        export(self.session.eddsa_public_key(key)?)
    }
    /// Import a validated Edwards public key for verification only. Requires RW
    /// mode and bounded nonempty ID/label; duplicate public IDs are rejected.
    /// Concurrent writers may race. No retry/rollback or private-key association.
    pub fn import_eddsa_public_key(
        &mut self,
        key: &EdDsaVerifyingKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        if id.is_empty() || label.is_empty() || id.len() > 128 || label.len() > 128 {
            return Err(pkcs11_runtime::Error::InvalidParameters("public key identity").into());
        }
        if !self.session.info()?.read_write() {
            return Err(pkcs11_runtime::Error::ReadWriteRequired.into());
        }
        if !self
            .session
            .find_objects(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Token(true),
                Attribute::Id(id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(
                pkcs11_runtime::Error::InvalidParameters("public key ID already exists").into(),
            );
        }
        let point = OctetString::new(key.as_bytes())
            .and_then(|point| point.to_der())
            .map_err(|_| Error::InvalidPublicKey)?;
        self.session.create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Verify(true),
            Attribute::Derive(false),
            Attribute::Trusted(false),
            Attribute::EcParams(key.curve().ec_params().to_vec()),
            Attribute::EcPoint(point),
            Attribute::AllowedMechanisms(vec![MechanismType::EDDSA]),
        ])?;
        Ok(())
    }
}
impl Client<'_> {
    /// Read current capabilities for a uniquely selected Edwards public/private key.
    pub fn eddsa_capabilities(
        &self,
        key: &ObjectRef,
        authentication: Authentication<'_>,
    ) -> Result<EdDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .eddsa_capabilities(key)?)
    }
    /// Sign the original message once; never hashes externally, substitutes or retries.
    pub fn sign_eddsa(
        &self,
        key: &PrivateKeyRef,
        request: &EdDsaRequest<'_>,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_eddsa(key, request, context_pin)?)
    }
    /// Verify once using a public key on the token. Does not establish certificate trust.
    pub fn verify_eddsa(
        &self,
        key: &PublicKeyRef,
        request: &EdDsaRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        if signature.len() != request.curve.signature_length() {
            return Err(Error::SignatureMismatch);
        }
        self.pool()
            .try_acquire(authentication)?
            .session()
            .verify_eddsa(key, request, signature)
            .map_err(verification_error)
    }
    /// Export a strictly validated RFC 8410 SPKI from a public, non-private object.
    pub fn export_eddsa_public_key(
        &self,
        key: &PublicKeyRef,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        export(
            self.pool()
                .try_acquire(authentication)?
                .session()
                .eddsa_public_key(key)?,
        )
    }
}
