// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{DigestMode, Error, HashAlgorithm, ManagementSession};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::io::Read;

impl ManagementSession<'_> {
    /// Advisory fixed-output hash choices with CKF_DIGEST and required native
    /// function pointers. Does not authenticate, hash input or use software.
    pub fn digest_algorithms(&self, mode: DigestMode) -> Result<Vec<HashAlgorithm>, Error> {
        self.session.info()?;
        Ok(self.session.token().digest_algorithms(mode)?)
    }
    /// Hash a reader on the token using 64 KiB chunks and a zeroizing input
    /// buffer. Empty input is supported; Interrupted reads resume reading.
    /// Read/native failures discard the initialized operation and session.
    /// No whole-input buffering, key digests, state export or software fallback.
    /// Check session closure before publishing the digest.
    pub fn digest_reader(
        &mut self,
        algorithm: HashAlgorithm,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.session.start_digest(algorithm)?;
        let mut buffer = SecretBox::new(Box::new(vec![0; 64 * 1024]));
        loop {
            let length = match reader.read(buffer.expose_secret_mut()) {
                Ok(0) => break,
                Ok(length) => length,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::DigestInput),
            };
            operation.update(&buffer.expose_secret()[..length])?;
        }
        Ok(operation.finish()?)
    }
}
