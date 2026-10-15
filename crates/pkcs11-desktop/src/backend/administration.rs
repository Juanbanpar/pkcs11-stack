// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, BackendResult, LoginState, Registry, ResourceId, TokenEntry};
use pkcs11_client::{Authentication, SessionMode, SessionState, TokenInitializationTarget};
use secrecy::{ExposeSecret, SecretString};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdministrationKind {
    InitializeToken,
    InitializeUserPin,
    ChangePin,
}
impl TokenEntry {
    pub fn can_administer(&self, kind: AdministrationKind) -> bool {
        !self.write_protected
            && !self.protected_path
            && self.login != LoginState::Unknown
            && match kind {
                // An uninitialized token has no existing SO credential to unlock.
                AdministrationKind::InitializeToken => !self.initialized || !self.so_pin_locked,
                AdministrationKind::InitializeUserPin => {
                    self.initialized
                        && self.uri.is_some()
                        && self.login == LoginState::SecurityOfficer
                        && !self.so_pin_locked
                }
                AdministrationKind::ChangePin => {
                    self.initialized
                        && self.uri.is_some()
                        && match self.login {
                            LoginState::User => !self.user_pin_locked,
                            LoginState::SecurityOfficer => !self.so_pin_locked,
                            _ => false,
                        }
                }
            }
    }
}
// Owned one-shot credentials; no Debug or Clone and no payload in results.
pub enum AdministrationAction {
    InitializeToken {
        so_pin: SecretString,
        label: String,
    },
    InitializeUserPin {
        new_pin: SecretString,
    },
    ChangePin {
        old_pin: SecretString,
        new_pin: SecretString,
    },
}
impl AdministrationAction {
    fn kind(&self) -> AdministrationKind {
        match self {
            Self::InitializeToken { .. } => AdministrationKind::InitializeToken,
            Self::InitializeUserPin { .. } => AdministrationKind::InitializeUserPin,
            Self::ChangePin { .. } => AdministrationKind::ChangePin,
        }
    }
}
impl Registry {
    fn administer_action(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        expected: &TokenInitializationTarget,
        role: LoginState,
        action: AdministrationAction,
    ) -> Result<(), BackendError> {
        let index = self
            .modules
            .iter()
            .position(|entry| entry.entry.id == module)
            .ok_or(BackendError::UnknownModule)?;
        self.discover(index)?;
        let entry = self.modules[index]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .ok_or(BackendError::UnknownToken)?;
        if entry.initialization != *expected
            || entry.login != role
            || !entry.can_administer(action.kind())
        {
            return Err(BackendError::AdministrationUnavailable);
        }
        match &action {
            AdministrationAction::InitializeToken { so_pin, label } => {
                if label.trim().is_empty()
                    || label.len() > 32
                    || so_pin.expose_secret().is_empty()
                    || (!expected.initialized && !expected.accepts_new_pin(so_pin))
                {
                    return Err(BackendError::AdministrationInput);
                }
            }
            AdministrationAction::InitializeUserPin { new_pin }
            | AdministrationAction::ChangePin { new_pin, .. } => {
                if !expected.accepts_new_pin(new_pin) {
                    return Err(BackendError::AdministrationInput);
                }
            }
        }
        if matches!(&action, AdministrationAction::ChangePin { old_pin, .. } if old_pin.expose_secret().is_empty())
        {
            return Err(BackendError::AdministrationInput);
        }
        if let AdministrationAction::InitializeToken { so_pin, label } = action {
            // C_InitToken requires no live sessions. Closing all module anchors also
            // releases the Arc consumers needed by the client's exclusive-owner check.
            self.modules[index]
                .close_authentication()
                .map_err(|_| BackendError::AdministrationCleanup)?;
            return self.modules[index]
                .provider
                .initialize_token_checked(expected, &so_pin, &label)
                .map_err(|_| BackendError::AdministrationFailed);
        }
        let uri = entry
            .uri
            .as_ref()
            .ok_or(BackendError::AdministrationUnavailable)?
            .parse()
            .map_err(|_| BackendError::AdministrationUnavailable)?;
        let result = (|| {
            let mut session = self.modules[index]
                .provider
                .management(&uri, SessionMode::ReadWrite, Authentication::None)
                .map_err(|e| BackendError::from(&e))?;
            let result = (|| {
                let state = session.state().map_err(|e| BackendError::from(&e))?;
                if !matches!(
                    (role, state),
                    (LoginState::User, SessionState::RwUser)
                        | (LoginState::SecurityOfficer, SessionState::RwSecurityOfficer)
                ) {
                    return Err(BackendError::AdministrationUnavailable);
                }
                match action {
                    AdministrationAction::InitializeUserPin { new_pin } => {
                        session.initialize_pin(&new_pin)
                    }
                    AdministrationAction::ChangePin { old_pin, new_pin } => {
                        session.change_pin(&old_pin, &new_pin)
                    }
                    AdministrationAction::InitializeToken { .. } => unreachable!(),
                }
                .map_err(|_| BackendError::AdministrationFailed)
            })();
            let closed = session
                .close()
                .map_err(|_| BackendError::AdministrationCleanup);
            closed.and(result)
        })();
        // End this token's local authenticated lifetime after any PIN attempt.
        let mut cleanup = Ok(());
        if let Some(position) = self.modules[index]
            .authentication
            .iter()
            .position(|(id, _)| *id == token)
        {
            let (_, session) = self.modules[index].authentication.remove(position);
            cleanup = session
                .close()
                .map_err(|_| BackendError::AdministrationCleanup);
        }
        cleanup.and(result)
    }
    pub(super) fn administer(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        expected: TokenInitializationTarget,
        role: LoginState,
        action: AdministrationAction,
    ) -> BackendResult {
        let operation = self.administer_action(module, token, &expected, role, action);
        if operation == Err(BackendError::AdministrationCleanup)
            && let Some(entry) = self
                .modules
                .iter_mut()
                .find(|entry| entry.entry.id == module)
        {
            entry.administration_cleanup_failed = true;
        }
        let refreshed = self
            .modules
            .iter()
            .position(|entry| entry.entry.id == module)
            .ok_or(BackendError::UnknownModule)
            .and_then(|index| self.discover(index));
        BackendResult::Modules {
            modules: self
                .modules
                .iter()
                .map(|entry| entry.entry.clone())
                .collect(),
            loaded: None,
            error: operation.err().or_else(|| {
                refreshed
                    .err()
                    .map(|_| BackendError::RefreshAfterManagement)
            }),
        }
    }
}
#[cfg(test)]
#[path = "administration_tests.rs"]
mod tests;
