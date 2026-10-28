// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{DigestMode, Error, HashAlgorithm, ManagementSession};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::io::Read;

/// Exclusively borrowed token digest. Chunks and credentials are not retained.
/// Dropping without finish or confirmed explicit cancellation discards the session.
#[derive(Debug)]
pub struct DigestOperation<'a>(pkcs11_runtime::DigestOperation<'a>);
impl DigestOperation<'_> {
    /// Process a chunk, including empty input. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete the digest once. Check session closure before publishing output.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.0.finish()?)
    }
    /// Cancel the active digest once; only confirmed native termination permits
    /// session reuse. Unsupported or failed cancellation requires closure.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl ManagementSession<'_> {
    /// Begin an exclusively borrowed digest with caller-controlled chunking and
    /// optional explicit cancellation. No implicit cancellation or retry on drop.
    ///
    /// The guard retains exclusive access until finish, cancellation or drop:
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{CancelFlags, Error, HashAlgorithm, ManagementSession};
    /// fn overlapping(session: &mut ManagementSession<'_>) -> Result<(), Error> {
    ///     let mut digest = session.start_digest(HashAlgorithm::Sha256)?;
    ///     session.cancel_operations(CancelFlags::DIGEST)?;
    ///     digest.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_digest(&mut self, algorithm: HashAlgorithm) -> Result<DigestOperation<'_>, Error> {
        Ok(DigestOperation(self.session.start_digest(algorithm)?))
    }
    /// Cancel selected operation classes in this owned session once. Empty flags
    /// leave native state unchanged. Any failed attempt requires session closure;
    /// success confirms only the requested classes and never repairs prior failure.
    pub fn cancel_operations(&mut self, flags: crate::CancelFlags) -> Result<(), Error> {
        Ok(self.session.cancel_operations(flags)?)
    }

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
