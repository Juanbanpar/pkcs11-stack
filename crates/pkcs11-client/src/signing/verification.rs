// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, ManagementSession, VerifyRequest};

impl Client<'_> {
    /// Verify a token signature with a public key and explicit hashing policy.
    pub fn verify(
        &self,
        key: &crate::PublicKeyRef,
        request: &VerifyRequest<'_>,
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self.pool().try_acquire(authentication)?.session().verify(
            key,
            request,
            self.policy(),
        )?)
    }

    /// Verify a signature over a precomputed digest using the signature-first API.
    pub fn verify_signature(
        &self,
        key: &crate::PublicKeyRef,
        request: &pkcs11_runtime::SignRequest<'_>,
        signature: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_signature(key, request, signature)?)
    }
}

impl ManagementSession<'_> {
    /// Verify a classical RSA/ECDSA signature on the token.
    pub fn verify_token(
        &mut self,
        key: &crate::PublicKeyRef,
        request: &VerifyRequest<'_>,
        policy: &pkcs11_runtime::SigningPolicy,
    ) -> Result<(), Error> {
        self.session.verify(key, request, policy)?;
        Ok(())
    }
}
