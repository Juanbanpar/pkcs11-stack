// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Authentication, Client, Error, HashAlgorithm, ManagementSession};

impl Client<'_> {
    /// Digest one bounded buffer on the token.
    pub fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .digest(algorithm, input)?)
    }

    /// Stream chunks through a multipart token digest.
    pub fn digest_chunks<'a>(
        &self,
        algorithm: HashAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
        authentication: Authentication<'_>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .pool()
            .try_acquire(authentication)?
            .session()
            .digest_chunks(algorithm, chunks)?)
    }
}

impl ManagementSession<'_> {
    /// Digest one bounded buffer on this session's token.
    pub fn digest(&mut self, algorithm: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.session.digest(algorithm, input)?)
    }

    /// Stream chunks through a multipart token digest.
    pub fn digest_chunks<'a>(
        &mut self,
        algorithm: HashAlgorithm,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.session.digest_chunks(algorithm, chunks)?)
    }
}
