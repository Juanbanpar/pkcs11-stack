// SPDX-License-Identifier: MIT OR Apache-2.0
use std::fmt;

use crate::{Error, SessionInfo, Token, error::backend};

/// Session access mode. No pool or hidden worker is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// Read-only session.
    ReadOnly,
    /// Read-write session.
    ReadWrite,
}
/// Exclusive session retaining its module through its token identity.
/// The owner is borrowed for direct sessions or shared for owned-pool sessions.
///
/// Authentication and close require exclusive access. No raw handle is public.
/// Failed operations that invalidate the session make subsequent session/object
/// calls return `Error::Closed`. Explicit close remains available for cleanup.
/// Drop closes but never explicitly logs out the token. Closing the last session
/// may nevertheless reset token-wide authentication under PKCS#11 semantics.
pub struct Session<'m> {
    raw: Option<cryptoki::session::Session>,
    token: Token<'m>,
    pub(crate) mode: SessionMode,
    pub(crate) healthy: std::cell::Cell<bool>,
}
impl fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("slot", &self.token.slot)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl<'m> Session<'m> {
    pub(crate) fn open(token: &Token<'m>, mode: SessionMode) -> Result<Self, Error> {
        token.validate()?;
        let raw = match mode {
            SessionMode::ReadOnly => token.module.raw()?.open_ro_session(token.slot),
            SessionMode::ReadWrite => token.module.raw()?.open_rw_session(token.slot),
        }
        .map_err(|e| backend("open session", e))?;
        let session = Self {
            raw: Some(raw),
            token: Token {
                module: token.module.clone(),
                slot: token.slot,
                info: token.info.clone(),
            },
            mode,
            healthy: std::cell::Cell::new(true),
        };
        session.token.validate()?;
        Ok(session)
    }
    pub(crate) fn raw(&self) -> Result<&cryptoki::session::Session, Error> {
        if !self.healthy.get() {
            return Err(Error::Closed);
        }
        self.raw.as_ref().ok_or(Error::Closed)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.raw()?;
        self.token
            .validate()
            .inspect_err(|_| self.healthy.set(false))
    }
    pub(crate) fn failed(&self, operation: &'static str, source: cryptoki::error::Error) -> Error {
        self.healthy.set(false);
        backend(operation, source)
    }
    /// Snapshot token metadata bound to this session.
    pub fn token(&self) -> &Token<'m> {
        &self.token
    }
    /// Inspect actual session state rather than assuming a cached login state.
    pub fn info(&self) -> Result<SessionInfo, Error> {
        self.validate()?;
        self.raw()?
            .get_session_info()
            .map_err(|e| self.failed("session info", e))
    }
    /// Fill a nonempty caller buffer using the token's advertised RNG, once.
    /// No software fallback or retry is performed. Discard the buffer on failure.
    pub fn generate_random(&mut self, output: &mut [u8]) -> Result<(), Error> {
        if output.is_empty() {
            return Err(Error::InvalidParameters("empty random output"));
        }
        self.validate()?;
        let current = self
            .token
            .module
            .token(self.token.slot)
            .inspect_err(|_| self.healthy.set(false))?;
        if !crate::module::same_token(self.token.info(), current.info()) {
            self.healthy.set(false);
            return Err(Error::TokenChanged);
        }
        if !current.info().rng() {
            return Err(Error::RandomUnavailable);
        }
        let raw = self.begin_operation()?;
        let result = raw
            .generate_random_slice(output)
            .map_err(|e| backend("generate random", e));
        if result.is_ok() {
            self.healthy.set(true);
        }
        result
    }
    /// Close the session and report closure failures. No automatic logout call.
    pub fn close(mut self) -> Result<(), Error> {
        self.raw
            .take()
            .ok_or(Error::Closed)?
            .close()
            .map_err(|e| backend("close session", e))
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // An explicit Drop implementation also makes Rust's drop checking retain
        // the module borrow through session destruction, even after the last use.
        // Owned sessions likewise retain their Arc until after raw closure.
        // cryptoki closes the taken session; it does not issue C_Logout here.
        drop(self.raw.take());
    }
}
