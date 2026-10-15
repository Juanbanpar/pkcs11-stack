// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{AdministrationAction, AdministrationKind};
use pkcs11_client::TokenInitializationTarget;
use secrecy::ExposeSecret;
#[derive(Clone, Copy)]
pub enum AdministrationPinField {
    Current,
    New,
    Confirm,
}
#[derive(Clone, Copy)]
pub enum AdministrationField {
    Label,
    Confirmation,
}
pub struct AdministrationForm {
    pub id: RequestId,
    pub module: ResourceId,
    pub token: ResourceId,
    pub expected: TokenInitializationTarget,
    pub role: LoginState,
    pub kind: AdministrationKind,
    pub old_pin: SecretString,
    pub new_pin: SecretString,
    pub confirm_pin: SecretString,
    pub label: String,
    pub confirmation: String,
    pub reviewing: bool,
}
impl AdministrationForm {
    fn valid(&self) -> bool {
        match self.kind {
            AdministrationKind::InitializeToken if self.expected.initialized => {
                !self.old_pin.expose_secret().is_empty()
                    && !self.label.trim().is_empty()
                    && self.label.len() <= 32
            }
            AdministrationKind::InitializeToken => {
                !self.label.trim().is_empty() && self.label.len() <= 32 && self.matching_new_pin()
            }
            AdministrationKind::InitializeUserPin => self.matching_new_pin(),
            AdministrationKind::ChangePin => {
                !self.old_pin.expose_secret().is_empty() && self.matching_new_pin()
            }
        }
    }
    fn matching_new_pin(&self) -> bool {
        self.expected.accepts_new_pin(&self.new_pin)
            && self.new_pin.expose_secret() == self.confirm_pin.expose_secret()
    }
    fn clear_secrets(&mut self) {
        self.old_pin = SecretString::default();
        self.new_pin = SecretString::default();
        self.confirm_pin = SecretString::default();
    }
}
impl UiState {
    pub fn can_administer(&self, kind: AdministrationKind) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Administration
            && self.token().is_some_and(|token| token.can_administer(kind))
    }
    pub fn open_administration(&mut self, kind: AdministrationKind) {
        if !self.can_administer(kind) {
            return;
        }
        self.cancel();
        self.clear_crypto_form();
        self.login_form = None;
        self.dialog = None;
        let Some(id) = self.request_id() else {
            return;
        };
        let Some(token) = self.token() else {
            return;
        };
        self.administration_form = Some(AdministrationForm {
            id,
            module: self.module().unwrap().id,
            token: token.id,
            expected: token.initialization.clone(),
            role: token.login,
            kind,
            old_pin: SecretString::default(),
            new_pin: SecretString::default(),
            confirm_pin: SecretString::default(),
            label: String::new(),
            confirmation: String::new(),
            reviewing: false,
        });
    }
    fn administration_in_scope(&self, id: RequestId) -> bool {
        self.administration_form.as_ref().is_some_and(|form| {
            form.id == id
                && self.can_administer(form.kind)
                && self.selected_module == Some(form.module)
                && self.selected_token == Some(form.token)
                && self.token().is_some_and(|token| {
                    token.initialization == form.expected && token.login == form.role
                })
        })
    }
    pub fn administration_pin(
        &mut self,
        id: RequestId,
        field: AdministrationPinField,
        pin: SecretString,
    ) {
        if !self.administration_in_scope(id) {
            return;
        }
        let form = self.administration_form.as_mut().unwrap();
        if form.reviewing {
            return;
        }
        match field {
            AdministrationPinField::Current => form.old_pin = pin,
            AdministrationPinField::New => form.new_pin = pin,
            AdministrationPinField::Confirm => form.confirm_pin = pin,
        }
    }
    pub fn administration_edit(
        &mut self,
        id: RequestId,
        field: AdministrationField,
        value: String,
    ) {
        if !self.administration_in_scope(id) {
            return;
        }
        let form = self.administration_form.as_mut().unwrap();
        match field {
            AdministrationField::Label if !form.reviewing => form.label = value,
            AdministrationField::Confirmation if form.reviewing => form.confirmation = value,
            _ => (),
        }
    }
    pub fn review_administration(&mut self, id: RequestId) {
        if !self.administration_in_scope(id) {
            return;
        }
        let form = self.administration_form.as_mut().unwrap();
        if !form.valid() {
            form.clear_secrets();
            self.notification = Some(Notification::Error(BackendError::AdministrationInput));
            return;
        }
        form.reviewing = true;
        form.confirmation.clear();
    }
    pub fn dismiss_administration(&mut self, id: RequestId) {
        if self
            .administration_form
            .as_ref()
            .is_some_and(|form| form.id == id)
        {
            self.administration_form = None;
        }
    }
    pub fn submit_administration(&mut self, id: RequestId) -> Option<BackendCommand> {
        if !self.administration_in_scope(id) {
            return None;
        }
        let form = self.administration_form.as_ref()?;
        if !form.reviewing
            || !form.valid()
            || form.confirmation
                != if form.kind == AdministrationKind::InitializeToken {
                    "ERASE"
                } else {
                    "CHANGE"
                }
        {
            return None;
        }
        let form = self.administration_form.take()?;
        let action = match form.kind {
            AdministrationKind::InitializeToken => AdministrationAction::InitializeToken {
                so_pin: if form.expected.initialized {
                    form.old_pin
                } else {
                    form.new_pin
                },
                label: form.label,
            },
            AdministrationKind::InitializeUserPin => AdministrationAction::InitializeUserPin {
                new_pin: form.new_pin,
            },
            AdministrationKind::ChangePin => AdministrationAction::ChangePin {
                old_pin: form.old_pin,
                new_pin: form.new_pin,
            },
        };
        let id = self.begin(OperationKind::Administer)?;
        self.reset_browser();
        Some(BackendCommand::Administer {
            id,
            module: form.module,
            token: form.token,
            expected: form.expected,
            role: form.role,
            action,
        })
    }
}
