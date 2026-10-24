// SPDX-License-Identifier: MIT OR Apache-2.0
#[cfg(test)]
use crate::backend::SyntheticOutcome;
use crate::backend::{
    BackendCommand, BackendError, BackendEvent, BackendResult, LoginRole, LoginState,
    MechanismEntry, MetadataField, ModuleEntry, ObjectEntry, RequestId, ResourceId, SecretInput,
    TokenEntry,
};
use pkcs11_client::MechanismType;
use secrecy::SecretString;
use std::path::PathBuf;
mod administration;
pub use administration::{AdministrationField, AdministrationForm, AdministrationPinField};
mod cipher;
mod key_operations;
pub use key_operations::{KeyField, KeyForm, WrapTarget};
mod crypto;
pub use cipher::{CipherChoice, CipherField, CipherForm};
mod management;
mod random;
pub use crypto::{CryptoField, CryptoForm, SignatureChoice};
pub use management::{FilePurpose, KeyChoice, ManagementField, ManagementUi};
pub use random::{RandomField, RandomUi};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Welcome,
    Modules,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialog {
    About,
    Delete(RequestId),
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenPage {
    #[default]
    Overview,
    Objects,
    Mechanisms,
    Operations,
    Administration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    RandomSaved(usize),
    SignatureVerified,
    Completed,
    Cancelled,
    Error(BackendError),
}
impl Notification {
    pub fn text(self) -> &'static str {
        match self {
            Self::RandomSaved(_) => "Token random bytes saved to the requested file.",
            Self::SignatureVerified => {
                "Signature verified against the selected certificate's public key. Certificate trust has not been checked."
            }
            Self::Completed => "Operation completed.",
            Self::Cancelled => {
                "Result cancelled; queued or running work will finish in the background."
            }
            Self::Error(error) => error.message(),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Administer,
    KeyOperation,
    Cipher,
    Random,
    CryptoOptions,
    Sign,
    Verify,
    Load,
    Unload,
    Login,
    Logout,
    Refresh,
    Objects,
    Mechanisms,
    Inspect,
    Capabilities,
    Manage,
    #[cfg(test)]
    Synthetic,
}

pub struct LoginForm {
    pub id: RequestId,
    pub module: ResourceId,
    pub token: ResourceId,
    pub role: LoginRole,
    pub protected_path: bool,
    pub pin: SecretString,
}

/// UI metadata and identifiers. Providers and live PKCS#11 resources stay on the worker.
#[derive(Default)]
pub struct UiState {
    pub presentation: crate::ui::Presentation,
    pub administration_form: Option<AdministrationForm>,
    pub screen: Screen,
    pub loaded_modules: Vec<ModuleEntry>,
    pub selected_module: Option<ResourceId>,
    pub selected_token: Option<ResourceId>,
    pub selected_object: Option<ResourceId>,
    pub current_operation: Option<RequestId>,
    pub dialog: Option<Dialog>,
    pub login_form: Option<LoginForm>,
    pub notification: Option<Notification>,
    pub worker_available: bool,
    pub shutdown_request: Option<RequestId>,
    pub module_path: String,
    pub picker_request: Option<RequestId>,
    pub token_page: TokenPage,
    pub objects: Vec<ObjectEntry>,
    pub mechanisms: Vec<MechanismEntry>,
    pub object_filter: String,
    pub mechanism_filter: String,
    pub object_details: Option<Vec<MetadataField>>,
    pub selected_mechanism: Option<MechanismType>,
    pub objects_loaded: bool,
    pub mechanisms_loaded: bool,
    pub management: ManagementUi,
    pub crypto_form: Option<CryptoForm>,
    pub cipher_form: Option<CipherForm>,
    pub key_form: Option<KeyForm>,
    pub random: RandomUi,
    picked_path: Option<PathBuf>,
    operation_kind: Option<OperationKind>,
    select_loaded: bool,
    next_request: u64,
}
impl UiState {
    fn request_id(&mut self) -> Option<RequestId> {
        if !self.worker_available || self.shutdown_request.is_some() {
            return None;
        }
        // Reserve the final ID for shutdown; cancelled IDs are never reused.
        if self.next_request >= u64::MAX - 1 {
            self.notification = Some(Notification::Error(BackendError::RequestExhausted));
            return None;
        }
        self.next_request += 1;
        Some(RequestId(self.next_request))
    }
    pub fn can_submit(&self) -> bool {
        self.worker_available
            && self.shutdown_request.is_none()
            && !matches!(
                self.operation_kind,
                Some(
                    OperationKind::Load
                        | OperationKind::Unload
                        | OperationKind::Login
                        | OperationKind::Logout
                        | OperationKind::Manage
                        | OperationKind::Sign
                        | OperationKind::Random
                        | OperationKind::Cipher
                        | OperationKind::KeyOperation
                        | OperationKind::Administer
                )
            )
    }
    fn begin(&mut self, kind: OperationKind) -> Option<RequestId> {
        if !self.can_submit() {
            return None;
        }
        let id = self.request_id()?;
        self.administration_form = None;
        self.random.picker = None;
        if let Some(form) = &mut self.key_form {
            form.picker = None;
        }
        if let Some(form) = &mut self.cipher_form {
            form.picker = None;
        }
        self.login_form = None;
        if let Some(form) = &mut self.crypto_form {
            form.pin = SecretString::default();
            form.picker = None;
        }
        self.management.file_request = None;
        self.management.confirmation = None;
        if matches!(self.dialog, Some(Dialog::Delete(_))) {
            self.dialog = None;
        }
        self.current_operation = Some(id);
        self.operation_kind = Some(kind);
        self.notification = None;
        Some(id)
    }
    pub fn open_login(&mut self, role: LoginRole) {
        if !self.can_submit() || !self.token().is_some_and(|token| token.can_login(role)) {
            return;
        }
        self.cancel();
        self.clear_crypto_form();
        self.administration_form = None;
        if let Some(id) = self.request_id() {
            self.dialog = None;
            self.login_form = Some(LoginForm {
                id,
                module: self.module().unwrap().id,
                token: self.token().unwrap().id,
                role,
                protected_path: self.token().unwrap().protected_path,
                pin: SecretString::default(),
            });
        }
    }
    pub fn edit_pin(&mut self, id: RequestId, pin: SecretString) {
        if let Some(form) = &mut self.login_form
            && form.id == id
            && !form.protected_path
        {
            form.pin = pin;
        }
    }
    pub fn use_protected_path(&mut self, id: RequestId, enabled: bool) {
        if enabled && !self.token().is_some_and(|token| token.protected_path) {
            return;
        }
        if let Some(form) = &mut self.login_form
            && form.id == id
        {
            form.pin = SecretString::default();
            form.protected_path = enabled;
        }
    }
    pub fn login(&mut self, form_id: RequestId) -> Option<BackendCommand> {
        if !self.can_submit()
            || !self
                .login_form
                .as_ref()
                .is_some_and(|form| form.id == form_id)
        {
            return None;
        }
        let form = self.login_form.take()?;
        if self.selected_module != Some(form.module)
            || self.selected_token != Some(form.token)
            || !self.token().is_some_and(|token| token.can_login(form.role))
        {
            return None;
        }
        let id = self.begin(OperationKind::Login)?;
        self.reset_browser();
        let pin = if form.protected_path {
            SecretInput::ProtectedPath
        } else {
            SecretInput::Value(form.pin)
        };
        Some(BackendCommand::Login {
            id,
            module: form.module,
            token: form.token,
            role: form.role,
            pin,
        })
    }
    pub fn logout(&mut self) -> Option<BackendCommand> {
        let module = self.module()?.id;
        let entry = self.token()?;
        if entry.login == LoginState::Public {
            return None;
        }
        let token = entry.id;
        let id = self.begin(OperationKind::Logout)?;
        self.reset_browser();
        Some(BackendCommand::Logout { id, module, token })
    }
    pub fn edit_path(&mut self, path: String) {
        self.module_path = path;
        self.picked_path = None;
        self.picker_request = None;
    }
    pub fn begin_picker(&mut self) -> Option<RequestId> {
        if !self.can_submit() || self.picker_request.is_some() {
            return None;
        }
        let id = self.request_id()?;
        self.picker_request = Some(id);
        Some(id)
    }
    pub fn picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        if self.shutdown_request.is_some() || self.picker_request != Some(id) {
            return;
        }
        self.picker_request = None;
        if let Some(path) = path {
            self.module_path = path.to_string_lossy().into_owned();
            self.picked_path = Some(path);
        }
    }
    pub fn load(&mut self) -> Option<BackendCommand> {
        if self.module_path.is_empty() {
            self.notification = Some(Notification::Error(BackendError::ModulePath));
            return None;
        }
        let id = self.begin(OperationKind::Load)?;
        self.picker_request = None;
        self.select_loaded = true;
        self.screen = Screen::Modules;
        let path = self
            .picked_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.module_path));
        Some(BackendCommand::Load { id, path })
    }
    pub fn unload(&mut self) -> Option<BackendCommand> {
        let module = self.module()?.id;
        let id = self.begin(OperationKind::Unload)?;
        Some(BackendCommand::Unload { id, module })
    }
    pub fn refresh(&mut self) -> Option<BackendCommand> {
        let module = self.module()?.id;
        let id = self.begin(OperationKind::Refresh)?;
        self.reset_browser();
        Some(BackendCommand::Refresh { id, module })
    }
    fn reset_browser(&mut self) {
        self.administration_form = None;
        self.random = RandomUi::default();
        self.clear_crypto_form();
        self.management = ManagementUi::default();
        if matches!(self.dialog, Some(Dialog::Delete(_))) {
            self.dialog = None;
        }
        self.login_form = None;
        self.token_page = TokenPage::Overview;
        self.objects.clear();
        self.mechanisms.clear();
        self.selected_object = None;
        self.selected_mechanism = None;
        self.object_details = None;
        self.object_filter.clear();
        self.mechanism_filter.clear();
        self.objects_loaded = false;
        self.mechanisms_loaded = false;
    }
    pub fn show_page(&mut self, page: TokenPage) -> Option<BackendCommand> {
        if self.token().is_none() || !self.can_submit() {
            return None;
        }
        self.cancel();
        self.administration_form = None;
        self.random = RandomUi::default();
        self.login_form = None;
        self.clear_crypto_form();
        self.management = ManagementUi::default();
        if matches!(self.dialog, Some(Dialog::Delete(_))) {
            self.dialog = None;
        }
        self.token_page = page;
        self.selected_object = None;
        self.object_details = None;
        self.selected_mechanism = None;
        match page {
            TokenPage::Overview | TokenPage::Administration => None,
            TokenPage::Objects => self.read_objects(),
            TokenPage::Mechanisms => self.read_mechanisms(),
            TokenPage::Operations => self.read_capabilities(),
        }
    }
    pub fn read_objects(&mut self) -> Option<BackendCommand> {
        if self.token_page != TokenPage::Objects {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.begin(OperationKind::Objects)?;
        self.objects.clear();
        self.objects_loaded = false;
        self.selected_object = None;
        self.object_details = None;
        Some(BackendCommand::Objects { id, module, token })
    }
    pub fn read_mechanisms(&mut self) -> Option<BackendCommand> {
        if self.token_page != TokenPage::Mechanisms {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.begin(OperationKind::Mechanisms)?;
        self.mechanisms.clear();
        self.mechanisms_loaded = false;
        self.selected_mechanism = None;
        Some(BackendCommand::Mechanisms { id, module, token })
    }
    pub fn select_object(&mut self, object: ResourceId) -> Option<BackendCommand> {
        if !self.can_submit() || self.token_page != TokenPage::Objects {
            return None;
        }
        let entry = self
            .objects
            .iter()
            .find(|entry| entry.id == object && entry.matches(&self.object_filter))?;
        let inspectable = entry.uri.is_some() && !entry.ambiguous;
        let module = self.module()?.id;
        let token = self.token()?.id;
        self.cancel();
        self.clear_crypto_form();
        self.management.confirmation = None;
        self.management.file_request = None;
        if matches!(self.dialog, Some(Dialog::Delete(_))) {
            self.dialog = None;
        }
        self.selected_object = Some(object);
        self.object_details = None;
        if !inspectable {
            return None;
        }
        let id = self.begin(OperationKind::Inspect)?;
        Some(BackendCommand::Inspect {
            id,
            module,
            token,
            object,
        })
    }
    pub fn object(&self) -> Option<&ObjectEntry> {
        self.objects
            .iter()
            .find(|entry| Some(entry.id) == self.selected_object)
    }
    pub fn edit_object_filter(&mut self, filter: String) {
        self.object_filter = filter;
        if self
            .object()
            .is_some_and(|entry| !entry.matches(&self.object_filter))
        {
            if matches!(
                self.operation_kind,
                Some(OperationKind::Inspect | OperationKind::CryptoOptions | OperationKind::Verify)
            ) {
                self.cancel();
            }
            self.selected_object = None;
            self.clear_crypto_form();
            self.object_details = None;
            self.management.confirmation = None;
            self.management.file_request = None;
            if matches!(self.dialog, Some(Dialog::Delete(_))) {
                self.dialog = None;
            }
        }
    }
    pub fn select_mechanism(&mut self, mechanism: MechanismType) {
        if self.token_page == TokenPage::Mechanisms
            && self
                .mechanisms
                .iter()
                .any(|entry| entry.id == mechanism && entry.matches(&self.mechanism_filter))
        {
            self.selected_mechanism = Some(mechanism);
        }
    }
    pub fn edit_mechanism_filter(&mut self, filter: String) {
        self.mechanism_filter = filter;
        if self
            .mechanisms
            .iter()
            .find(|entry| Some(entry.id) == self.selected_mechanism)
            .is_some_and(|entry| !entry.matches(&self.mechanism_filter))
        {
            self.selected_mechanism = None;
        }
    }
    #[cfg(test)]
    pub fn start(&mut self, outcome: SyntheticOutcome) -> Option<BackendCommand> {
        let id = self.begin(OperationKind::Synthetic)?;
        Some(BackendCommand::Synthetic { id, outcome })
    }
    pub fn can_cancel(&self) -> bool {
        self.current_operation.is_some()
            && !matches!(
                self.operation_kind,
                Some(
                    OperationKind::Load
                        | OperationKind::Unload
                        | OperationKind::Login
                        | OperationKind::Logout
                        | OperationKind::Manage
                        | OperationKind::Sign
                        | OperationKind::Random
                        | OperationKind::Cipher
                        | OperationKind::KeyOperation
                        | OperationKind::Administer
                )
            )
    }
    pub fn cancel(&mut self) {
        if self.can_cancel() {
            if let Some(form) = &mut self.crypto_form {
                form.pin = SecretString::default();
                form.picker = None;
            }
            self.current_operation = None;
            self.operation_kind = None;
            self.notification = Some(Notification::Cancelled);
        }
    }
    pub fn navigate(&mut self, screen: Screen) {
        self.presentation.task = None;
        self.presentation.show_detail = false;
        self.cancel();
        self.select_loaded = false;
        self.picker_request = None;
        self.screen = screen;
        self.selected_module = None;
        self.selected_token = None;
        self.selected_object = None;
        self.reset_browser();
    }
    pub fn select_module(&mut self, module: ResourceId) {
        self.presentation.task = None;
        self.presentation.show_detail = false;
        if !self.loaded_modules.iter().any(|m| m.id == module) {
            return;
        }
        self.cancel();
        self.reset_browser();
        self.select_loaded = false;
        self.screen = Screen::Modules;
        self.selected_module = Some(module);
        self.selected_token = None;
        self.selected_object = None;
    }
    pub fn select_token(&mut self, module: ResourceId, token: ResourceId) {
        if !self
            .loaded_modules
            .iter()
            .any(|m| m.id == module && m.tokens.iter().any(|t| t.id == token))
        {
            return;
        }
        self.select_module(module);
        self.selected_token = Some(token);
    }
    pub fn module(&self) -> Option<&ModuleEntry> {
        self.loaded_modules
            .iter()
            .find(|m| Some(m.id) == self.selected_module)
    }
    pub fn token(&self) -> Option<&TokenEntry> {
        self.module()?
            .tokens
            .iter()
            .find(|t| Some(t.id) == self.selected_token)
    }
    pub fn event(&mut self, event: BackendEvent) {
        // Cancellation discards read results, not a module's cleanup failure.
        // Merge only disabled modules; an old inventory must not restore other
        // modules, selections or forms belonging to a newer request.
        if self.shutdown_request.is_none()
            && let BackendEvent::Completed {
                id,
                result:
                    Ok(BackendResult::Modules {
                        modules,
                        error: Some(BackendError::SessionCleanup),
                        ..
                    }),
            } = &event
            && self.current_operation != Some(*id)
        {
            let mut invalidated = false;
            let mut selected_invalidated = false;
            for disabled in modules
                .iter()
                .filter(|module| module.discovery_error == Some(BackendError::SessionCleanup))
            {
                if let Some(module) = self
                    .loaded_modules
                    .iter_mut()
                    .find(|module| module.id == disabled.id)
                {
                    *module = disabled.clone();
                    selected_invalidated |= self.selected_module == Some(module.id);
                    invalidated = true;
                }
            }
            if selected_invalidated {
                self.cancel();
                self.selected_token = None;
                self.reset_browser();
            }
            if invalidated {
                self.notification = Some(Notification::Error(BackendError::SessionCleanup));
            }
            return;
        }
        match event {
            BackendEvent::Completed { id, result }
                if self.shutdown_request.is_none() && self.current_operation == Some(id) =>
            {
                let in_scope = match &result {
                    Ok(
                        BackendResult::CryptoOptions { scope, .. }
                        | BackendResult::Verified { scope },
                    ) => {
                        self.crypto_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(BackendResult::KeyOptions { scope, .. }) => {
                        self.key_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(BackendResult::CipherOptions { scope, .. }) => {
                        self.cipher_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(
                        BackendResult::Objects { module, token, .. }
                        | BackendResult::Capabilities { module, token, .. }
                        | BackendResult::Mechanisms { module, token, .. },
                    ) => {
                        self.selected_module == Some(*module) && self.selected_token == Some(*token)
                    }
                    Ok(BackendResult::ObjectDetails {
                        module,
                        token,
                        object,
                        ..
                    }) => {
                        self.selected_module == Some(*module)
                            && self.selected_token == Some(*token)
                            && self.selected_object == Some(*object)
                    }
                    _ => true,
                };
                if !in_scope {
                    return;
                }
                let reading_choices = self.operation_kind == Some(OperationKind::CryptoOptions);
                self.current_operation = None;
                self.operation_kind = None;
                let error = match result {
                    Ok(BackendResult::KeyOptions { profile, .. }) => {
                        if let Some(form) = &mut self.key_form {
                            form.profile = Some(profile);
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::CipherOptions { choices, .. }) => {
                        if let Some(form) = &mut self.cipher_form {
                            form.choices = choices.into_iter().map(CipherChoice).collect();
                            form.choice = form.choices.first().copied();
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::RandomWritten { length }) => {
                        self.notification = Some(Notification::RandomSaved(length));
                        return;
                    }
                    Ok(BackendResult::CryptoOptions {
                        options, context, ..
                    }) => {
                        if let Some(form) = &mut self.crypto_form {
                            form.options = options.into_iter().map(SignatureChoice).collect();
                            form.choice = form.options.first().copied();
                            form.context_required = context;
                            form.pin = SecretString::default();
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::Verified { .. }) => {
                        self.notification = Some(Notification::SignatureVerified);
                        return;
                    }
                    Ok(BackendResult::Capabilities { keys, .. }) => {
                        self.management.keys = keys.into_iter().map(KeyChoice).collect();
                        self.management.key = self.management.keys.first().copied();
                        self.management.capabilities_loaded = true;
                        None
                    }
                    Ok(BackendResult::Managed {
                        module,
                        token,
                        modules,
                        objects,
                        error,
                    }) => {
                        self.loaded_modules = modules;
                        if self.module().is_none() {
                            self.selected_module = None;
                            self.selected_token = None;
                        } else if self.token().is_none() {
                            self.selected_token = None;
                        }
                        self.reset_browser();
                        if self.selected_module == Some(module)
                            && self.selected_token == Some(token)
                        {
                            self.token_page = TokenPage::Objects;
                            if let Some(objects) = objects {
                                self.objects = objects;
                                self.objects_loaded = true;
                            }
                        }
                        error
                    }
                    Ok(BackendResult::Modules {
                        modules,
                        loaded,
                        error,
                    }) => {
                        self.loaded_modules = modules;
                        if self.select_loaded
                            && let Some(module) = loaded
                        {
                            self.selected_module = Some(module);
                            self.selected_token = None;
                            self.selected_object = None;
                        }
                        self.select_loaded = false;
                        if self.module().is_none() {
                            self.selected_module = None;
                            self.selected_token = None;
                            self.selected_object = None;
                        } else if self.token().is_none() {
                            self.selected_token = None;
                            self.selected_object = None;
                        }
                        self.reset_browser();
                        error
                    }
                    Ok(BackendResult::Objects { objects, .. }) => {
                        self.objects = objects;
                        self.objects_loaded = true;
                        None
                    }
                    Ok(BackendResult::Mechanisms { mechanisms, .. }) => {
                        self.mechanisms = mechanisms;
                        self.mechanisms_loaded = true;
                        None
                    }
                    Ok(BackendResult::ObjectDetails { fields, .. }) => {
                        self.object_details = Some(fields);
                        None
                    }
                    #[cfg(test)]
                    Ok(BackendResult::Synthetic) => None,
                    Err(error) => {
                        if reading_choices {
                            if let Some(form) = &mut self.key_form {
                                form.loaded = true;
                            }
                            if let Some(form) = &mut self.cipher_form {
                                form.loaded = true;
                            }
                            if let Some(form) = &mut self.crypto_form {
                                form.loaded = true;
                            }
                        }
                        Some(error)
                    }
                };
                self.select_loaded = false;
                self.notification =
                    Some(error.map_or(Notification::Completed, Notification::Error));
            }
            BackendEvent::Disconnected if self.shutdown_request.is_none() => {
                self.worker_available = false;
                self.current_operation = None;
                self.operation_kind = None;
                self.picker_request = None;
                // These snapshots no longer represent providers available for operations.
                self.loaded_modules.clear();
                self.selected_module = None;
                self.selected_token = None;
                self.selected_object = None;
                self.reset_browser();
                self.notification = Some(Notification::Error(BackendError::Disconnected));
            }
            BackendEvent::Stopped { id, result } if self.shutdown_request == Some(id) => {
                self.worker_available = false;
                if let Err(error) = result {
                    self.notification = Some(Notification::Error(error));
                }
            }
            _ => {} // Cancelled and superseded results cannot replace UI state.
        }
    }
    pub fn begin_shutdown(&mut self) -> Option<RequestId> {
        if self.shutdown_request.is_some() {
            return None;
        }
        self.next_request += 1;
        let id = RequestId(self.next_request);
        self.shutdown_request = Some(id);
        self.presentation.overlay = None;
        self.presentation.choice = None;
        self.administration_form = None;
        self.current_operation = None;
        self.operation_kind = None;
        self.picker_request = None;
        self.dialog = None;
        self.login_form = None;
        self.clear_crypto_form();
        self.management = ManagementUi::default();
        self.notification = None;
        self.random = RandomUi::default();
        Some(id)
    }
    pub fn status(&self) -> &'static str {
        if self.shutdown_request.is_some() {
            "Closing modules and stopping worker…"
        } else if !self.worker_available {
            "Background worker unavailable"
        } else {
            match self.operation_kind {
                Some(OperationKind::Administer) => "Applying token administration once…",
                Some(OperationKind::KeyOperation) => "Executing token key operation once…",
                Some(OperationKind::Cipher) => "Executing RSA OAEP once and saving output…",
                Some(OperationKind::Random) => "Generating token random bytes and saving them…",
                Some(OperationKind::CryptoOptions) => "Reading permitted crypto choices…",
                Some(OperationKind::Sign) => "Signing once and saving the signature…",
                Some(OperationKind::Verify) => "Verifying signature…",
                Some(OperationKind::Load) => "Loading module…",
                Some(OperationKind::Unload) => "Unloading module…",
                Some(OperationKind::Refresh) => "Refreshing slots and tokens…",
                Some(OperationKind::Objects) => "Reading visible object identities…",
                Some(OperationKind::Login) => "Authenticating once…",
                Some(OperationKind::Logout) => "Logging out…",
                Some(OperationKind::Mechanisms) => "Reading advertised mechanisms…",
                Some(OperationKind::Capabilities) => "Reading key-generation capabilities…",
                Some(OperationKind::Manage) => "Managing objects…",
                Some(OperationKind::Inspect) => "Reading selected object metadata…",
                #[cfg(test)]
                Some(OperationKind::Synthetic) => "Working in the background…",
                None => "Ready",
            }
        }
    }
}

#[cfg(test)]
mod tests;
