// SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(test)]
use crate::backend::SyntheticOutcome;
use crate::backend::{
    BackendCommand, BackendError, BackendEvent, BackendResult, MechanismEntry, MetadataField,
    ModuleEntry, ObjectEntry, RequestId, ResourceId, TokenEntry,
};
use pkcs11_client::MechanismType;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Welcome,
    Modules,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialog {
    About,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenPage {
    #[default]
    Overview,
    Objects,
    Mechanisms,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    Completed,
    Cancelled,
    Error(BackendError),
}
impl Notification {
    pub fn text(self) -> &'static str {
        match self {
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
    Load,
    Unload,
    Refresh,
    Objects,
    Mechanisms,
    Inspect,
    #[cfg(test)]
    Synthetic,
}

/// UI metadata and identifiers. Providers and live PKCS#11 resources stay on the worker.
#[derive(Default)]
pub struct UiState {
    pub screen: Screen,
    pub loaded_modules: Vec<ModuleEntry>,
    pub selected_module: Option<ResourceId>,
    pub selected_token: Option<ResourceId>,
    pub selected_object: Option<ResourceId>,
    pub current_operation: Option<RequestId>,
    pub dialog: Option<Dialog>,
    pub notification: Option<Notification>,
    pub dark_theme: bool,
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
                Some(OperationKind::Load | OperationKind::Unload)
            )
    }
    fn begin(&mut self, kind: OperationKind) -> Option<RequestId> {
        if !self.can_submit() {
            return None;
        }
        let id = self.request_id()?;
        self.current_operation = Some(id);
        self.operation_kind = Some(kind);
        self.notification = None;
        Some(id)
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
        self.token_page = page;
        self.selected_object = None;
        self.object_details = None;
        self.selected_mechanism = None;
        match page {
            TokenPage::Overview => None,
            TokenPage::Objects => self.read_objects(),
            TokenPage::Mechanisms => self.read_mechanisms(),
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
            if self.operation_kind == Some(OperationKind::Inspect) {
                self.cancel();
            }
            self.selected_object = None;
            self.object_details = None;
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
                Some(OperationKind::Load | OperationKind::Unload)
            )
    }
    pub fn cancel(&mut self) {
        if self.can_cancel() {
            self.current_operation = None;
            self.operation_kind = None;
            self.notification = Some(Notification::Cancelled);
        }
    }
    pub fn navigate(&mut self, screen: Screen) {
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
        match event {
            BackendEvent::Completed { id, result }
                if self.shutdown_request.is_none() && self.current_operation == Some(id) =>
            {
                let in_scope = match &result {
                    Ok(
                        BackendResult::Objects { module, token, .. }
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
                self.current_operation = None;
                self.operation_kind = None;
                let error = match result {
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
                    Err(error) => Some(error),
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
        self.current_operation = None;
        self.operation_kind = None;
        self.picker_request = None;
        self.dialog = None;
        self.notification = None;
        Some(id)
    }
    pub fn status(&self) -> &'static str {
        if self.shutdown_request.is_some() {
            "Closing modules and stopping worker…"
        } else if !self.worker_available {
            "Background worker unavailable"
        } else {
            match self.operation_kind {
                Some(OperationKind::Load) => "Loading module…",
                Some(OperationKind::Unload) => "Unloading module…",
                Some(OperationKind::Refresh) => "Refreshing slots and tokens…",
                Some(OperationKind::Objects) => "Reading public object identities…",
                Some(OperationKind::Mechanisms) => "Reading advertised mechanisms…",
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
