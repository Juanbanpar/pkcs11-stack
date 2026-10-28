// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::input::read_chunks;
use crate::{AesCmacProfile, Error, HmacAlgorithm, HmacTagProfile, ManagementSession, ObjectRef};
use std::io::Read;

/// Exclusively borrowed native MAC generator. Drop discards incomplete sessions.
#[derive(Debug)]
pub struct MacGeneration<'a>(pkcs11_runtime::MacGeneration<'a>);
/// Exclusively borrowed native MAC verifier. Drop discards incomplete sessions.
#[derive(Debug)]
pub struct MacVerification<'a>(pkcs11_runtime::MacVerification<'a>);
impl MacGeneration<'_> {
    /// Process a chunk, including empty input. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete once into fixed-size storage. Check closure before releasing output.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.0.finish()?)
    }
    /// Explicitly cancel once. Only confirmed native termination restores reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl MacVerification<'_> {
    /// Process a chunk, including empty input. Native failure prevents further use.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Ok(self.0.update(bytes)?)
    }
    /// Complete once. Completed length/content mismatches return MacMismatch and
    /// permit session reuse; other native failures require closure.
    pub fn finish(self, tag: &[u8]) -> Result<(), Error> {
        match self.0.finish(tag) {
            Err(pkcs11_runtime::Error::MacMismatch) => Err(Error::MacMismatch),
            result => Ok(result?),
        }
    }
    /// Explicitly cancel once. Only confirmed native termination restores reuse.
    pub fn cancel(self) -> Result<(), Error> {
        Ok(self.0.cancel()?)
    }
}
impl ManagementSession<'_> {
    /// Begin exclusive native HMAC generation with an explicit full/general tag
    /// profile. No software fallback, buffering or total input limit is imposed;
    /// callers enforce their budget. Drop discards incomplete sessions.
    ///
    /// ```compile_fail,E0499
    /// use pkcs11_client::{Error, HmacAlgorithm, HmacTagProfile, ManagementSession, ObjectRef};
    /// fn overlapping(session: &mut ManagementSession<'_>, key: &ObjectRef) -> Result<(), Error> {
    ///     let mut mac = session.start_hmac(key, HmacAlgorithm::Sha256, HmacTagProfile::Full)?;
    ///     session.start_hmac(key, HmacAlgorithm::Sha256, HmacTagProfile::Full)?;
    ///     mac.update(b"message")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn start_hmac(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        profile: HmacTagProfile,
    ) -> Result<MacGeneration<'_>, Error> {
        Ok(MacGeneration(
            self.session.start_hmac(key, algorithm, profile)?,
        ))
    }
    /// Begin exclusive native HMAC verification with independently checked
    /// verification permission. The same input/lifecycle bounds as start_hmac apply.
    pub fn start_hmac_verification(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        profile: HmacTagProfile,
    ) -> Result<MacVerification<'_>, Error> {
        Ok(MacVerification(
            self.session
                .start_hmac_verification(key, algorithm, profile)?,
        ))
    }
    /// Begin exclusive native AES-CMAC generation with an explicit full/general
    /// profile. Callers enforce their input budget; incomplete sessions are discarded.
    pub fn start_aes_cmac(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
    ) -> Result<MacGeneration<'_>, Error> {
        Ok(MacGeneration(self.session.start_aes_cmac(key, profile)?))
    }
    /// Begin exclusive native AES-CMAC verification with independent verification
    /// permission. Callers enforce their input budget; drop discards incomplete sessions.
    pub fn start_aes_cmac_verification(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
    ) -> Result<MacVerification<'_>, Error> {
        Ok(MacVerification(
            self.session.start_aes_cmac_verification(key, profile)?,
        ))
    }
    /// Generate a native HMAC using a zeroizing 64 KiB reader buffer. Empty input
    /// and Interrupted reads are supported. No total input bound is imposed; callers
    /// enforce their budget. Read/native errors discard the initialized session.
    /// No fallback or retry; check closure before releasing the tag.
    pub fn hmac_reader(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        profile: HmacTagProfile,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_hmac(key, algorithm, profile)?;
        read_chunks(reader, |bytes| operation.update(bytes), Error::MacInput)?;
        operation.finish()
    }
    /// Verify a reader natively with the agreed HMAC profile, using a zeroizing
    /// 64 KiB buffer and no total input limit. Completed mismatches permit reuse;
    /// read/update/final failures discard the session. Interrupted reads resume.
    pub fn verify_hmac_reader(
        &mut self,
        key: &ObjectRef,
        algorithm: HmacAlgorithm,
        profile: HmacTagProfile,
        reader: &mut impl Read,
        tag: &[u8],
    ) -> Result<(), Error> {
        let mut operation = self.start_hmac_verification(key, algorithm, profile)?;
        read_chunks(reader, |bytes| operation.update(bytes), Error::MacInput)?;
        operation.finish(tag)
    }
    /// Generate a native AES-CMAC using a zeroizing 64 KiB reader buffer. Empty
    /// input and Interrupted reads are supported. Callers enforce their input budget;
    /// read/native errors discard the session. Check closure before releasing the tag.
    pub fn aes_cmac_reader(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
        reader: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let mut operation = self.start_aes_cmac(key, profile)?;
        read_chunks(reader, |bytes| operation.update(bytes), Error::MacInput)?;
        operation.finish()
    }
    /// Verify a reader natively with the agreed AES-CMAC profile, using a zeroizing
    /// 64 KiB buffer and no total input limit. Completed mismatches permit reuse;
    /// read/update/final failures discard the session. Interrupted reads resume.
    pub fn verify_aes_cmac_reader(
        &mut self,
        key: &ObjectRef,
        profile: AesCmacProfile,
        reader: &mut impl Read,
        tag: &[u8],
    ) -> Result<(), Error> {
        let mut operation = self.start_aes_cmac_verification(key, profile)?;
        read_chunks(reader, |bytes| operation.update(bytes), Error::MacInput)?;
        operation.finish(tag)
    }
}
