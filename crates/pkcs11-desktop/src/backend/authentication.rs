// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, LoadedModule, Registry, ResourceId};
use pkcs11_client::{Authentication, Pin, SessionMode, SessionState};
use secrecy::SecretString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginRole {
    User,
    SecurityOfficer,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LoginState {
    #[default]
    Public,
    User,
    SecurityOfficer,
    Unknown,
}
impl LoginState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "Logged out",
            Self::User => "USER logged in",
            Self::SecurityOfficer => "SO logged in",
            Self::Unknown => "Authentication status unavailable",
        }
    }
    fn from_session(state: SessionState) -> Self {
        match state {
            SessionState::RoPublic | SessionState::RwPublic => Self::Public,
            SessionState::RoUser | SessionState::RwUser => Self::User,
            SessionState::RwSecurityOfficer => Self::SecurityOfficer,
        }
    }
}
// Never formatted or cloned into backend results. SecretString zeroizes on drop.
pub enum SecretInput {
    Value(SecretString),
    ProtectedPath,
}
impl LoadedModule {
    pub(super) fn read_mode(&self, token: ResourceId) -> Result<SessionMode, BackendError> {
        let state = self
            .authentication
            .iter()
            .find(|(id, _)| *id == token)
            .map(|(_, session)| session.state().map_err(|e| BackendError::from(&e)))
            .transpose()?;
        Ok(if state == Some(SessionState::RwSecurityOfficer) {
            SessionMode::ReadWrite
        } else {
            SessionMode::ReadOnly
        })
    }
    pub(super) fn close_authentication(&mut self) -> Result<(), BackendError> {
        let mut error = None;
        for (_, session) in self.authentication.drain(..) {
            if let Err(failure) = session.close() {
                error.get_or_insert(BackendError::from(&failure));
            }
        }
        error.map_or(Ok(()), Err)
    }
    pub(super) fn refresh_authentication(&mut self) -> Result<(), BackendError> {
        let mut retained = Vec::new();
        let mut error = None;
        for (id, session) in self.authentication.drain(..) {
            if let Some(token) = self.entry.tokens.iter_mut().find(|token| token.id == id) {
                match session.state() {
                    Ok(state) => {
                        token.login = LoginState::from_session(state);
                        if token.login == LoginState::Public {
                            if let Err(failure) = session.close() {
                                error.get_or_insert(BackendError::from(&failure));
                            }
                            continue;
                        }
                    }
                    Err(failure) => {
                        token.login = LoginState::Unknown;
                        error.get_or_insert(BackendError::from(&failure));
                    }
                }
                // Keep the anchor available for explicit logout/close after an error.
                retained.push((id, session));
            } else if let Err(failure) = session.close() {
                error.get_or_insert(BackendError::from(&failure));
            }
        }
        self.authentication = retained;
        error.map_or(Ok(()), Err)
    }
    pub(super) fn close(mut self) -> Result<(), BackendError> {
        let closed = self.close_authentication();
        let finalized = self.provider.finalize().map_err(|e| BackendError::from(&e));
        closed.and(finalized)
    }
}
impl Registry {
    pub(super) fn login(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        role: LoginRole,
        pin: SecretInput,
    ) -> Result<(), BackendError> {
        let (index, uri) = self.location(module, token)?;
        // Refresh flags before allowing a new PIN attempt; discovery never retries login.
        self.discover(index)?;
        let entry = self.modules[index]
            .entry
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .ok_or(BackendError::UnknownToken)?;
        if !entry.can_login(role)
            || self.modules[index]
                .authentication
                .iter()
                .any(|(id, _)| *id == token)
            || (matches!(pin, SecretInput::ProtectedPath) && !entry.protected_path)
        {
            return Err(BackendError::AuthenticationUnavailable);
        }
        let mode = match role {
            LoginRole::User => SessionMode::ReadOnly,
            LoginRole::SecurityOfficer => SessionMode::ReadWrite,
        };
        let mut session = self.modules[index]
            .provider
            .management_owned(&uri, mode, Authentication::None)
            .map_err(|e| BackendError::from(&e))?;
        let value = match &pin {
            SecretInput::Value(pin) => Pin::Value(pin),
            SecretInput::ProtectedPath => Pin::ProtectedPath,
        };
        let policy = match role {
            LoginRole::User => Authentication::User(value),
            LoginRole::SecurityOfficer => Authentication::SecurityOfficer(value),
        };
        let result = session
            .authenticate(policy)
            .map_err(|_| BackendError::AuthenticationFailed);
        drop(pin);
        // Preserve an actually authenticated session, even if login reported an error.
        let state = session.state().map(LoginState::from_session);
        let closed = if result.is_ok()
            || matches!(state, Ok(LoginState::User | LoginState::SecurityOfficer))
        {
            self.modules[index].authentication.push((token, session));
            Ok(())
        } else {
            session.close().map_err(|e| BackendError::from(&e))
        };
        let refreshed = self.discover(index);
        result.and(closed).and(refreshed)
    }
    pub(super) fn logout(
        &mut self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<(), BackendError> {
        let (index, _) = self.location(module, token)?;
        self.modules[index].catalogs.clear();
        let position = self.modules[index]
            .authentication
            .iter()
            .position(|(id, _)| *id == token)
            .ok_or(BackendError::AuthenticationUnavailable)?;
        let (_, mut session) = self.modules[index].authentication.remove(position);
        let logged_out = session.logout().map_err(|e| BackendError::from(&e));
        let closed = if logged_out.is_ok() {
            session.close().map_err(|e| BackendError::from(&e))
        } else {
            self.modules[index].authentication.push((token, session));
            Ok(())
        };
        let refreshed = self.discover(index);
        logged_out.and(closed).and(refreshed)
    }
}
