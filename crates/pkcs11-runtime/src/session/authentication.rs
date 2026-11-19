// SPDX-License-Identifier: MIT OR Apache-2.0
use cryptoki::{session::UserType, types::AuthPin};

use crate::{Error, SecretText, Session, SessionMode, error::backend};

/// Explicit PIN input, borrowed only for the login call.
#[derive(Debug)]
#[non_exhaustive]
pub enum Pin<'a> {
    /// Host-supplied PIN held in redacted, zeroizing storage.
    Value(&'a SecretText),
    /// Token-provided protected authentication path, checked before login.
    ProtectedPath,
}

pub(crate) fn login_with_pin(
    session: &cryptoki::session::Session,
    user: UserType,
    pin: Option<&SecretText>,
) -> Result<(), cryptoki::error::Error> {
    // Cryptoki takes its own zeroizing PIN type. Keep the copy local to this call.
    let pin = pin.map(|pin| AuthPin::from(pin.expose_secret()));
    session.login(user, pin.as_ref())
}

/// Explicit login policy; this does not cache credentials or implicit login state.
///
/// Context-specific authentication belongs to `Session::sign`, after operation init.
#[derive(Debug)]
#[non_exhaustive]
pub enum Authentication<'a> {
    /// Do not change token authentication state (not an implicit logout).
    None,
    /// Login as the normal USER.
    User(Pin<'a>),
    /// Login as SO, requiring an RW session and no conflicting RO sessions.
    SecurityOfficer(Pin<'a>),
}

impl<'m> Session<'m> {
    /// Validate current protected-path capability using the same identity check
    /// for ordinary and context-specific authentication.
    fn login_pin<'a>(&self, pin: Pin<'a>) -> Result<Option<&'a SecretText>, Error> {
        self.validate()?;
        match pin {
            Pin::Value(secret) => Ok(Some(secret)),
            Pin::ProtectedPath => {
                let current = self
                    .token()
                    .module
                    .token(self.token().slot)
                    .inspect_err(|_| self.healthy.set(false))?;
                if !crate::module::same_token(self.token().info(), current.info()) {
                    self.healthy.set(false);
                    return Err(Error::TokenChanged);
                }
                if !current.info().protected_authentication_path() {
                    return Err(Error::ProtectedPathUnavailable);
                }
                Ok(None)
            }
        }
    }

    pub(crate) fn prepare_context_pin<'a>(
        &self,
        required: bool,
        pin: Option<Pin<'a>>,
    ) -> Result<Option<&'a SecretText>, Error> {
        match (required, pin) {
            (true, Some(pin)) => self.login_pin(pin),
            (true, None) => Err(Error::ContextAuthenticationRequired),
            (false, Some(_)) => Err(Error::InvalidParameters(
                "context PIN for a key without always-authenticate",
            )),
            (false, None) => Ok(None),
        }
    }

    /// Apply an explicit authentication policy without storing PINs or retrying.
    ///
    /// USER/SO login state is shared by this application's sessions on the token.
    /// Already-logged-in and conflicting-user states retain their PKCS#11 errors.
    pub fn authenticate(&mut self, policy: Authentication<'_>) -> Result<(), Error> {
        self.validate()?;
        let (user, pin) = match policy {
            Authentication::None => return Ok(()),
            Authentication::User(pin) => (UserType::User, pin),
            Authentication::SecurityOfficer(pin) => {
                if self.mode != SessionMode::ReadWrite {
                    return Err(Error::ReadWriteRequired);
                }
                (UserType::So, pin)
            }
        };
        let pin = self.login_pin(pin)?;
        login_with_pin(self.raw()?, user, pin).map_err(|e| backend("login", e))
    }
    /// Explicit token-wide logout; it can invalidate private handles in other sessions.
    pub fn logout(&mut self) -> Result<(), Error> {
        self.validate()?;
        self.raw()?.logout().map_err(|e| backend("logout", e))
    }
    /// Initialize/reset the USER PIN. Requires an RW session logged in as SO.
    /// Uses a host PIN; the upstream API does not support a null/protected-path PIN.
    pub fn initialize_pin(&mut self, pin: &SecretText) -> Result<(), Error> {
        self.write_operation("initialize user PIN", |raw| {
            raw.init_pin(&AuthPin::from(pin.expose_secret()))
        })
    }
    /// Change the current role's PIN once. No credentials are retained or retried.
    /// Host PINs are required by the upstream safe mutation API.
    pub fn change_pin(&mut self, old: &SecretText, new: &SecretText) -> Result<(), Error> {
        self.write_operation("change PIN", |raw| {
            raw.set_pin(
                &AuthPin::from(old.expose_secret()),
                &AuthPin::from(new.expose_secret()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_debug_does_not_expose_pin() {
        let pin = SecretText::from("canary");
        assert!(!format!("{:?}", Authentication::User(Pin::Value(&pin))).contains("canary"));
    }
}
