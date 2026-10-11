// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use pkcs11_runtime::{Authentication, Pin};
use secrecy::SecretString;

/// Owned per-operation PIN input, dropped after authentication/signing completes.
#[derive(Debug)]
pub enum PinInput {
    /// Host-provided PIN in redacted, zeroizing storage.
    Value(SecretString),
    /// Use the token's protected authentication path.
    ProtectedPath,
}
impl PinInput {
    fn borrow(&self) -> Pin<'_> {
        match self {
            Self::Value(value) => Pin::Value(value),
            Self::ProtectedPath => Pin::ProtectedPath,
        }
    }
}
/// Authentication material for one binding/signing operation, never cached by adapter.
#[derive(Debug, Default)]
pub struct Credentials {
    /// Ensure USER login, or leave token-wide authentication unchanged when None.
    pub user: Option<PinInput>,
    /// Separate context authentication for an always-authenticate signing key.
    pub context: Option<PinInput>,
}
impl Credentials {
    pub(crate) fn authentication(&self) -> Authentication<'_> {
        self.user.as_ref().map_or(Authentication::None, |pin| {
            Authentication::User(pin.borrow())
        })
    }
    pub(crate) fn context_pin(&self) -> Option<Pin<'_>> {
        self.context.as_ref().map(PinInput::borrow)
    }
}
/// Application-owned credential acquisition. Called once per binding/sign operation.
///
/// Scheme choice and resolver filtering never invoke this callback. No implicit
/// prompts or retries are added. Implementations must be safe for concurrent calls.
/// Returning CredentialsUnavailable avoids exposing secret-source error text to TLS.
pub trait CredentialSource: Send + Sync {
    /// Obtain short-lived USER/context credentials for the current operation.
    fn credentials(&self) -> Result<Credentials, Error>;
}
impl<F> CredentialSource for F
where
    F: Fn() -> Result<Credentials, Error> + Send + Sync,
{
    fn credentials(&self) -> Result<Credentials, Error> {
        self()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_debug_redacts_both_secrets() {
        let credentials = Credentials {
            user: Some(PinInput::Value(SecretString::from("user-secret"))),
            context: Some(PinInput::Value(SecretString::from("context-secret"))),
        };
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("user-secret"));
        assert!(!debug.contains("context-secret"));
        assert!(matches!(
            credentials.authentication(),
            Authentication::User(_)
        ));
        assert!(credentials.context_pin().is_some());
    }
}
