// SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(test)]
use crate::backend::SyntheticOutcome;
use crate::backend::{
    BackendCommand, BackendError, BackendEvent, BackendResult, ModuleEntry, RequestId, ResourceId,
    TokenEntry,
};
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
        Some(BackendCommand::Refresh { id, module })
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
    }
    pub fn select_module(&mut self, module: ResourceId) {
        if !self.loaded_modules.iter().any(|m| m.id == module) {
            return;
        }
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
                        error
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
                #[cfg(test)]
                Some(OperationKind::Synthetic) => "Working in the background…",
                None => "Ready",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> UiState {
        UiState {
            worker_available: true,
            ..UiState::default()
        }
    }
    fn request(state: &mut UiState) -> RequestId {
        match state.start(SyntheticOutcome::Success).unwrap() {
            BackendCommand::Synthetic { id, .. } => id,
            _ => unreachable!(),
        }
    }

    #[test]
    fn latest_request_wins_even_if_responses_arrive_out_of_order() {
        let mut state = ready();
        let a = request(&mut state);
        let b = request(&mut state);
        assert_ne!(a, b);
        state.event(BackendEvent::Completed {
            id: b,
            result: Ok(BackendResult::Synthetic),
        });
        state.event(BackendEvent::Completed {
            id: a,
            result: Err(BackendError::Synthetic),
        });
        assert_eq!(state.notification, Some(Notification::Completed));
        assert_eq!(state.current_operation, None);
    }

    #[test]
    fn stale_result_does_not_clear_an_active_request() {
        let mut state = ready();
        let a = request(&mut state);
        let b = request(&mut state);
        state.event(BackendEvent::Completed {
            id: a,
            result: Ok(BackendResult::Synthetic),
        });
        assert_eq!(state.current_operation, Some(b));
        assert_eq!(state.notification, None);
    }

    #[test]
    fn cancel_and_navigation_ignore_eventual_results() {
        let mut state = ready();
        let cancelled = request(&mut state);
        state.cancel();
        state.event(BackendEvent::Completed {
            id: cancelled,
            result: Ok(BackendResult::Synthetic),
        });
        assert_eq!(state.notification, Some(Notification::Cancelled));
        let navigated = request(&mut state);
        state.navigate(Screen::Modules);
        state.event(BackendEvent::Completed {
            id: navigated,
            result: Ok(BackendResult::Synthetic),
        });
        assert_eq!(state.screen, Screen::Modules);
        assert_eq!(state.current_operation, None);
        assert_eq!(state.notification, Some(Notification::Cancelled));
    }

    #[test]
    fn shutdown_is_idempotent_and_rejects_new_work_and_late_results() {
        let mut state = ready();
        let old = request(&mut state);
        let shutdown = state.begin_shutdown().unwrap();
        assert_ne!(shutdown, old);
        assert!(state.begin_shutdown().is_none());
        assert!(state.start(SyntheticOutcome::Success).is_none());
        state.event(BackendEvent::Completed {
            id: old,
            result: Ok(BackendResult::Synthetic),
        });
        state.event(BackendEvent::Stopped {
            id: old,
            result: Ok(()),
        });
        assert!(state.worker_available);
        state.event(BackendEvent::Stopped {
            id: shutdown,
            result: Ok(()),
        });
        assert!(!state.worker_available);
        assert_eq!(state.notification, None);
    }

    #[test]
    fn failures_and_disconnects_are_visible() {
        let mut state = ready();
        let id = request(&mut state);
        state.event(BackendEvent::Completed {
            id,
            result: Err(BackendError::Synthetic),
        });
        assert_eq!(
            state.notification,
            Some(Notification::Error(BackendError::Synthetic))
        );
        state.event(BackendEvent::Disconnected);
        assert!(!state.worker_available);
        assert!(state.start(SyntheticOutcome::Success).is_none());
    }

    #[test]
    fn request_ids_do_not_wrap_and_shutdown_keeps_its_reserved_id() {
        let mut state = ready();
        state.next_request = u64::MAX - 2;
        assert_eq!(request(&mut state), RequestId(u64::MAX - 1));
        state.cancel();
        assert!(state.start(SyntheticOutcome::Success).is_none());
        assert_eq!(state.begin_shutdown(), Some(RequestId(u64::MAX)));
    }
    fn token(id: u64, serial: &str) -> TokenEntry {
        TokenEntry {
            id: ResourceId(id),
            slot_id: 10,
            label: "Token".into(),
            manufacturer: "Maker".into(),
            model: "Model".into(),
            serial: serial.into(),
            uri: Some(format!("pkcs11:serial={serial}")),
            details: Vec::new(),
        }
    }
    fn module(id: u64, tokens: Vec<TokenEntry>) -> ModuleEntry {
        ModuleEntry {
            id: ResourceId(id),
            path: PathBuf::from("module.so"),
            description: "Module".into(),
            manufacturer: "Maker".into(),
            library_version: "1.0".into(),
            cryptoki_version: "2.40".into(),
            slots: Vec::new(),
            tokens,
            discovery_error: None,
        }
    }
    fn modules(
        id: RequestId,
        entries: Vec<ModuleEntry>,
        loaded: Option<ResourceId>,
        error: Option<BackendError>,
    ) -> BackendEvent {
        BackendEvent::Completed {
            id,
            result: Ok(BackendResult::Modules {
                modules: entries,
                loaded,
                error,
            }),
        }
    }
    #[test]
    fn loading_survives_navigation_and_cannot_be_cancelled_or_superseded() {
        let mut state = ready();
        state.edit_path("module.so".into());
        let id = state.load().unwrap().id();
        assert!(!state.can_cancel());
        state.cancel();
        state.navigate(Screen::Welcome);
        assert_eq!(state.current_operation, Some(id));
        assert!(state.load().is_none());
        state.event(modules(
            id,
            vec![module(1, vec![token(2, "1")])],
            Some(ResourceId(1)),
            None,
        ));
        assert_eq!(state.loaded_modules.len(), 1);
        assert_eq!(state.screen, Screen::Welcome);
        assert!(state.selected_module.is_none());
        assert!(state.can_submit());
    }
    #[test]
    fn load_selects_module_and_failure_keeps_existing_inventory() {
        let mut state = ready();
        state.edit_path("module.so".into());
        let id = state.load().unwrap().id();
        state.event(modules(
            id,
            vec![module(1, vec![token(2, "1")])],
            Some(ResourceId(1)),
            None,
        ));
        assert_eq!(state.selected_module, Some(ResourceId(1)));
        state.select_token(ResourceId(1), ResourceId(2));
        let id = state.load().unwrap().id();
        state.event(modules(
            id,
            state.loaded_modules.clone(),
            None,
            Some(BackendError::AlreadyLoaded),
        ));
        assert_eq!(state.selected_token, Some(ResourceId(2)));
        assert_eq!(
            state.notification,
            Some(Notification::Error(BackendError::AlreadyLoaded))
        );
    }
    #[test]
    fn refresh_preserves_live_selection_and_rejects_a_late_snapshot() {
        let mut state = ready();
        state.loaded_modules = vec![module(1, vec![token(2, "A"), token(3, "B")])];
        state.select_token(ResourceId(1), ResourceId(2));
        let a = state.refresh().unwrap().id();
        state.select_token(ResourceId(1), ResourceId(3));
        let b = state.refresh().unwrap().id();
        let mut latest = state.loaded_modules.clone();
        latest[0].tokens[1]
            .details
            .push(("Current".into(), "B".into()));
        state.event(modules(b, latest, None, None));
        state.event(modules(a, vec![module(1, vec![token(2, "A")])], None, None));
        assert_eq!(state.selected_token, Some(ResourceId(3)));
        assert_eq!(state.token().unwrap().serial, "B");
        assert_eq!(state.token().unwrap().details.len(), 1);
    }
    #[test]
    fn removal_replacement_and_unload_clear_only_invalid_selections() {
        let mut state = ready();
        state.loaded_modules = vec![module(1, vec![token(2, "A")])];
        state.select_token(ResourceId(1), ResourceId(2));
        state.selected_object = Some(ResourceId(99));
        let id = state.refresh().unwrap().id();
        state.event(modules(
            id,
            vec![module(1, vec![token(3, "B")])],
            None,
            None,
        ));
        assert_eq!(state.selected_module, Some(ResourceId(1)));
        assert!(state.selected_token.is_none());
        assert!(state.selected_object.is_none());
        state.select_token(ResourceId(1), ResourceId(3));
        let id = state.unload().unwrap().id();
        state.cancel();
        assert_eq!(state.current_operation, Some(id));
        state.event(modules(
            id,
            Vec::new(),
            None,
            Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
        ));
        assert!(state.selected_module.is_none());
        assert!(state.selected_token.is_none());
        assert!(state.loaded_modules.is_empty());
        assert!(matches!(state.notification, Some(Notification::Error(_))));
    }
    #[test]
    fn cancelled_refresh_and_invalid_selection_cannot_restore_stale_resources() {
        let mut state = ready();
        state.loaded_modules = vec![module(1, vec![token(2, "A")])];
        state.select_token(ResourceId(1), ResourceId(2));
        let id = state.refresh().unwrap().id();
        state.cancel();
        state.event(modules(id, Vec::new(), None, None));
        assert_eq!(state.token().unwrap().serial, "A");
        state.select_token(ResourceId(9), ResourceId(2));
        assert_eq!(state.selected_module, Some(ResourceId(1)));
        state.event(BackendEvent::Disconnected);
        assert!(state.loaded_modules.is_empty());
        assert!(state.refresh().is_none());
    }
    #[test]
    fn picker_cancellation_editing_navigation_and_shutdown_reject_late_paths() {
        let mut state = ready();
        state.edit_path("manual.so".into());
        let id = state.begin_picker().unwrap();
        state.picked(id, None);
        assert_eq!(state.module_path, "manual.so");
        let id = state.begin_picker().unwrap();
        state.edit_path("new.so".into());
        state.picked(id, Some(PathBuf::from("stale.so")));
        assert_eq!(state.module_path, "new.so");
        let id = state.begin_picker().unwrap();
        state.navigate(Screen::Modules);
        state.picked(id, Some(PathBuf::from("other-screen.so")));
        assert_eq!(state.module_path, "new.so");
        let id = state.begin_picker().unwrap();
        state.begin_shutdown();
        state.picked(id, Some(PathBuf::from("late.so")));
        assert_eq!(state.module_path, "new.so");
    }
    #[cfg(unix)]
    #[test]
    fn selected_non_utf8_path_survives_display_conversion() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"module-\xff.so".to_vec()));
        let mut state = ready();
        let id = state.begin_picker().unwrap();
        state.picked(id, Some(path.clone()));
        assert!(
            matches!(state.load(), Some(BackendCommand::Load { path: selected, .. }) if selected == path)
        );
    }
}
