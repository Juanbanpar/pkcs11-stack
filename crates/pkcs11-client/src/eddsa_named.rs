// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, EdDsaCapabilities, EdDsaCurve, EdDsaNamedRequest, EdDsaVerifyingKey,
    Error, ManagementSession, ObjectRef, Pin, PrivateKeyRef, PublicKeyRef,
};
/// Validated raw RFC 8032 public key for a curveName token object.
/// Contains no token handle or private material and has no SPKI conversion API.
pub struct EdDsaNamedPublicKey(EdDsaVerifyingKey);
impl std::fmt::Debug for EdDsaNamedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDsaNamedPublicKey")
            .field("curve", &self.curve())
            .finish_non_exhaustive()
    }
}
impl EdDsaNamedPublicKey {
    /// Validate exact length, canonical encoding and a nonidentity prime-subgroup
    /// public point. Does not authenticate ownership or associate a private key.
    pub fn from_bytes(curve: EdDsaCurve, bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(EdDsaVerifyingKey::from_bytes(curve, bytes)?))
    }
    /// Edwards curve selected for the curveName profile.
    pub fn curve(&self) -> EdDsaCurve {
        self.0.curve()
    }
    /// Canonical raw public bytes, without ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl ManagementSession<'_> {
    /// Generate a protected RFC 8032 curveName signing pair. Requires RW mode,
    /// bounded nonempty ID/label and new public/private IDs. Concurrent writers
    /// can race. No retry/rollback; check closure before publishing results.
    pub fn generate_named_eddsa_key_pair(
        &mut self,
        curve: EdDsaCurve,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(), Error> {
        self.session
            .generate_named_eddsa_key_pair(curve, id, label, always_authenticate)?;
        Ok(())
    }
    /// Import validated raw public bytes for verification only. Requires RW mode,
    /// bounded identity and a new public ID. Does not establish trust or private
    /// key association. No retry/rollback; concurrent writers can race. Check closure.
    pub fn import_named_eddsa_public_key(
        &mut self,
        key: &EdDsaNamedPublicKey,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        let raw = pkcs11_runtime::EdDsaPublicKey::from_bytes(key.curve(), key.as_bytes().to_vec())?;
        self.session
            .import_named_eddsa_public_key(&raw, id, label)?;
        Ok(())
    }
    /// Export strictly validated raw public input from a public, non-private
    /// curveName object. Rejects OID keys; no private/secret values are read.
    pub fn export_named_eddsa_public_key(&mut self, key: &PublicKeyRef) -> Result<Vec<u8>, Error> {
        let raw = self.session.named_eddsa_public_key(key)?;
        Ok(
            EdDsaNamedPublicKey::from_bytes(raw.curve(), raw.as_bytes())?
                .as_bytes()
                .to_vec(),
        )
    }
    /// Read curveName metadata and advisory native signing/verification permissions.
    pub fn named_eddsa_capabilities(
        &mut self,
        key: &ObjectRef,
    ) -> Result<EdDsaCapabilities, Error> {
        Ok(self.session.named_eddsa_capabilities(key)?)
    }
    /// Sign original input with explicit RFC 8032 scheme/context. Prehashing for
    /// ph schemes runs on the token. No certificate binding, fallback or retry.
    /// Always-authenticate uses context login after init. Check session closure.
    pub fn sign_named_eddsa(
        &mut self,
        key: &PrivateKeyRef,
        request: &EdDsaNamedRequest<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.sign_named_eddsa(key, request, context_pin)?)
    }
    /// Verify original input on the token using an explicit curveName profile.
    /// Completed mismatches remain reusable; other native failures discard the
    /// session. Does not establish certificate trust. No fallback or retry.
    pub fn verify_named_eddsa(
        &mut self,
        key: &PublicKeyRef,
        request: &EdDsaNamedRequest<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_named_eddsa(key, request, signature)
            .map_err(crate::eddsa::verification_error)
    }
}
impl Client<'_> {
    /// Inspect advisory EdDSA permissions requiring a curveName object.
    pub fn named_eddsa_capabilities(
        &self,
        key: &ObjectRef,
        authentication: Authentication<'_>,
    ) -> Result<EdDsaCapabilities, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .named_eddsa_capabilities(key)?)
    }
    /// Sign original input with explicit RFC 8032 scheme/context through an
    /// exclusive pool lease. Context errors precede authentication. No certificate
    /// binding or software fallback. Check client closure before release.
    pub fn sign_named_eddsa(
        &self,
        key: &PrivateKeyRef,
        request: &EdDsaNamedRequest<'_>,
        authentication: Authentication<'_>,
        context_pin: Option<Pin<'_>>,
    ) -> Result<Vec<u8>, Error> {
        request.validate()?;
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .sign_named_eddsa(key, request, context_pin)?)
    }
    /// Verify on the token with an exclusive lease; context/length errors precede
    /// authentication. Completed mismatches permit reuse. Check client closure.
    pub fn verify_named_eddsa(
        &self,
        key: &PublicKeyRef,
        request: &EdDsaNamedRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        request.validate()?;
        if signature.len() != request.scheme.curve().signature_length() {
            return Err(Error::SignatureMismatch);
        }
        self.pool()
            .try_acquire(authentication)?
            .session()
            .verify_named_eddsa(key, request, signature)
            .map_err(crate::eddsa::verification_error)
    }
}
