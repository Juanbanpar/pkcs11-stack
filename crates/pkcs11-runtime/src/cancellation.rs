// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{CancelFlags, Error, Function, Session, error::backend};

pub(crate) fn cancel(
    raw: &cryptoki::session::Session,
    supported: bool,
    flags: CancelFlags,
) -> Result<(), Error> {
    if !supported {
        return Err(Error::CancellationUnavailable);
    }
    raw.cancel_operations(flags)
        .map_err(|error| backend("cancel session operations", error))
}

impl Session<'_> {
    /// Cancel explicitly selected operation classes in this owned session.
    ///
    /// Requires a healthy session and a C_SessionCancel pointer in the selected
    /// interface. Empty flags are a native no-op; inactive classes are ignored.
    /// Only CKR_OK confirms the requested termination. Any failed attempt,
    /// including unavailable support, leaves the session unusable until closure.
    /// No retry, global teardown, logout or legacy cancellation occurs.
    ///
    /// This cannot repair a session invalidated by an earlier failure. Use an
    /// active operation guard's cancel method to terminate its borrowed operation.
    /// Success does not assert that unselected operation classes are idle.
    pub fn cancel_operations(&mut self, flags: CancelFlags) -> Result<(), Error> {
        if !CancelFlags::all().contains(flags) {
            return Err(Error::InvalidParameters("unsupported cancellation flags"));
        }
        self.validate()?;
        let raw = self.raw()?;
        let supported = self
            .token()
            .module
            .supports_function(Function::SessionCancel);
        self.healthy.set(false);
        cancel(raw, supported, flags)?;
        self.healthy.set(true);
        Ok(())
    }
}
