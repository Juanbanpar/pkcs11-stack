// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Authentication, Client, Error, MacAlgorithm, MacKeyRequest, ManagementSession, ObjectRef,
};

impl Client<'_> {
    /// Compute one full-tag MAC with a selected secret key.
    pub fn mac(
        &self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .mac(key, algorithm, input)?)
    }

    /// Verify one full-tag MAC with a selected secret key.
    pub fn verify_mac(
        &self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        tag: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<(), Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .verify_mac(key, algorithm, input, tag)?)
    }
}

impl ManagementSession<'_> {
    /// Compute one full-tag MAC with a selected secret key.
    pub fn mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.mac(key, algorithm, input)?)
    }

    /// Stream a MAC over chunks.
    pub fn mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.mac_chunks(key, algorithm, chunks)?)
    }

    /// Verify one full-tag MAC with a selected secret key.
    pub fn verify_mac(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        Ok(self.session.verify_mac(key, algorithm, input, tag)?)
    }

    /// Verify a MAC over chunks.
    pub fn verify_mac_chunks<'a>(
        &mut self,
        key: &ObjectRef,
        algorithm: MacAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
        tag: &[u8],
    ) -> Result<(), Error> {
        Ok(self
            .session
            .verify_mac_chunks(key, algorithm, chunks, tag)?)
    }

    /// Generate a persistent HMAC or AES-CMAC key.
    pub fn generate_mac_key(&mut self, request: &MacKeyRequest<'_>) -> Result<(), Error> {
        self.session.generate_mac_key(request)?;
        Ok(())
    }
}
