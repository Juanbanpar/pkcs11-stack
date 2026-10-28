// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Object, error::backend};
use cryptoki::{
    context::Function,
    error::{Error as NativeError, RvError},
    mechanism::Mechanism,
};

pub(crate) fn generate_into(
    object: &Object<'_, '_>,
    mechanism: &Mechanism<'_>,
    message: &[u8],
    tag: &mut [u8],
) -> Result<(), Error> {
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    raw.sign_init(mechanism, object.handle)
        .map_err(|e| backend("MAC init", e))?;
    let written = raw
        .sign_initialized_into(message, tag)
        .map_err(|e| backend("MAC", e))?;
    if written != tag.len() {
        return Err(Error::InvalidKeyOutput);
    }
    object.session.healthy.set(true);
    Ok(())
}
pub(crate) fn verify(
    object: &Object<'_, '_>,
    mechanism: &Mechanism<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), Error> {
    let raw = object.session.raw()?;
    object.session.healthy.set(false);
    match raw.verify(mechanism, object.handle, message, tag) {
        Ok(()) => {
            object.session.healthy.set(true);
            Ok(())
        }
        Err(NativeError::Pkcs11(
            RvError::SignatureInvalid | RvError::SignatureLenRange,
            Function::Verify,
        )) => {
            object.session.healthy.set(true);
            Err(Error::MacMismatch)
        }
        Err(error) => Err(backend("MAC verify", error)),
    }
}

/// Exclusively borrowed native MAC generator. No input or credentials are retained.
/// Dropping before successful finish or explicit cancellation discards the session.
#[derive(Debug)]
pub struct MacGeneration<'a>(Stream<'a>);
/// Exclusively borrowed native MAC verifier, using CKA_VERIFY independently.
/// Dropping before completion or explicit cancellation discards the session.
#[derive(Debug)]
pub struct MacVerification<'a>(Stream<'a>);

struct Stream<'a> {
    raw: &'a cryptoki::session::Session,
    healthy: &'a std::cell::Cell<bool>,
    direction: crate::MacOperation,
    length: usize,
    active: bool,
    cancellation_supported: bool,
}
impl std::fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOperation")
            .field("direction", &self.direction)
            .field("tag_length", &self.length)
            .finish_non_exhaustive()
    }
}
impl Drop for Stream<'_> {
    fn drop(&mut self) {
        if self.active {
            self.healthy.set(false);
        }
    }
}
impl<'a> Stream<'a> {
    fn start(
        object: &Object<'a, '_>,
        mechanism: &Mechanism<'_>,
        length: usize,
        direction: crate::MacOperation,
    ) -> Result<Self, Error> {
        let raw = object.session.raw()?;
        object.session.healthy.set(false);
        match direction {
            crate::MacOperation::Generate => raw.sign_init(mechanism, object.handle),
            crate::MacOperation::Verify => raw.verify_init(mechanism, object.handle),
        }
        .map_err(|e| backend("initialize multipart MAC", e))?;
        Ok(Self {
            raw,
            healthy: &object.session.healthy,
            direction,
            length,
            active: true,
            cancellation_supported: object
                .session
                .token()
                .module
                .supports_function(Function::SessionCancel),
        })
    }
    fn check_active(&self) -> Result<(), Error> {
        if self.active {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }
    fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.check_active()?;
        let result = match self.direction {
            crate::MacOperation::Generate => self.raw.sign_update(bytes),
            crate::MacOperation::Verify => self.raw.verify_update(bytes),
        };
        if let Err(error) = result {
            self.active = false;
            return Err(backend("update MAC", error));
        }
        Ok(())
    }
    fn cancel(mut self) -> Result<(), Error> {
        self.check_active()?;
        let flags = match self.direction {
            crate::MacOperation::Generate => crate::CancelFlags::SIGN,
            crate::MacOperation::Verify => crate::CancelFlags::VERIFY,
        };
        crate::cancellation::cancel(self.raw, self.cancellation_supported, flags)?;
        self.active = false;
        self.healthy.set(true);
        Ok(())
    }
}
impl<'a> MacGeneration<'a> {
    pub(crate) fn start(
        object: &Object<'a, '_>,
        mechanism: &Mechanism<'_>,
        length: usize,
    ) -> Result<Self, Error> {
        Ok(Self(Stream::start(
            object,
            mechanism,
            length,
            crate::MacOperation::Generate,
        )?))
    }
    /// Process a chunk, including empty input. Native failure prevents further use.
    /// Streaming has no total message limit; callers enforce their input budget.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes)
    }
    /// Cancel this signing operation once. Only confirmed termination restores
    /// reuse; cancellation is unavailable on legacy tables. No implicit retry.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
    /// Finish once into at most 64 bytes, without native length queries or retries.
    /// Output must have exactly the agreed length. Check session closure before
    /// publishing the tag. Native failures and malformed lengths discard the session.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        self.0.check_active()?;
        let mut tag = [0; 64];
        let tag = &mut tag[..self.0.length];
        let written = self
            .0
            .raw
            .sign_final_into(tag)
            .map_err(|e| backend("finish MAC", e))?;
        if written != tag.len() {
            return Err(Error::InvalidKeyOutput);
        }
        self.0.active = false;
        self.0.healthy.set(true);
        Ok(tag.to_vec())
    }
}
impl<'a> MacVerification<'a> {
    pub(crate) fn start(
        object: &Object<'a, '_>,
        mechanism: &Mechanism<'_>,
        length: usize,
    ) -> Result<Self, Error> {
        Ok(Self(Stream::start(
            object,
            mechanism,
            length,
            crate::MacOperation::Verify,
        )?))
    }
    /// Process a chunk, including empty input. Native failure prevents further use.
    /// Streaming has no total message limit; callers enforce their input budget.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.update(bytes)
    }
    /// Cancel this verification operation once. Only confirmed termination restores
    /// reuse; cancellation is unavailable on legacy tables. No implicit retry.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
    /// Complete native verification once. Completed length/content mismatches
    /// return MacMismatch and restore reuse; all other native errors discard the
    /// session. Length is also checked locally even if the provider accepts it.
    pub fn finish(mut self, tag: &[u8]) -> Result<(), Error> {
        self.0.check_active()?;
        let result = match self.0.raw.verify_final(tag) {
            Ok(()) if tag.len() == self.0.length => Ok(()),
            Ok(())
            | Err(NativeError::Pkcs11(
                RvError::SignatureInvalid | RvError::SignatureLenRange,
                Function::VerifyFinal,
            )) => Err(Error::MacMismatch),
            Err(error) => return Err(backend("finish MAC verification", error)),
        };
        self.0.active = false;
        self.0.healthy.set(true);
        result
    }
}
