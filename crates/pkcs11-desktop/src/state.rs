// SPDX-License-Identifier: GPL-3.0-or-later
use crate::backend::{BackendCommand, BackendError, BackendEvent, RequestId, SyntheticOutcome};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Welcome,
    Modules,
}

/// Desktop-local identity, not a PKCS#11 handle or slot ID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResourceId(pub u64);

pub struct ModuleEntry {
    pub id: ResourceId,
    pub label: String,
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
            Self::Completed => "Synthetic operation completed on the background worker.",
            Self::Cancelled => {
                "Result cancelled; queued or running work will finish in the background."
            }
            Self::Error(error) => error.message(),
        }
    }
}

/// Data shown by the UI. No provider, session, lease, PIN or raw handle lives here.
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
    next_request: u64,
}
impl UiState {
    pub fn start(&mut self, outcome: SyntheticOutcome) -> Option<BackendCommand> {
        if !self.worker_available || self.shutdown_request.is_some() {
            return None;
        }
        // Reserve the final ID for shutdown; never wrap or reuse cancelled IDs.
        if self.next_request >= u64::MAX - 1 {
            self.notification = Some(Notification::Error(BackendError::RequestExhausted));
            return None;
        }
        self.next_request += 1;
        let id = RequestId(self.next_request);
        self.current_operation = Some(id);
        self.notification = None;
        Some(BackendCommand::Synthetic { id, outcome })
    }

    pub fn cancel(&mut self) {
        if self.current_operation.take().is_some() {
            self.notification = Some(Notification::Cancelled);
        }
    }

    pub fn navigate(&mut self, screen: Screen) {
        if self.screen != screen {
            self.cancel();
            self.screen = screen;
            self.selected_module = None;
            self.selected_token = None;
            self.selected_object = None;
        }
    }

    pub fn event(&mut self, event: BackendEvent) {
        match event {
            BackendEvent::Completed { id, result }
                if self.shutdown_request.is_none() && self.current_operation == Some(id) =>
            {
                self.current_operation = None;
                self.notification = Some(match result {
                    Ok(()) => Notification::Completed,
                    Err(error) => Notification::Error(error),
                });
            }
            BackendEvent::Disconnected if self.shutdown_request.is_none() => {
                self.worker_available = false;
                self.current_operation = None;
                self.notification = Some(Notification::Error(BackendError::Disconnected));
            }
            BackendEvent::Stopped { id } if self.shutdown_request == Some(id) => {
                self.worker_available = false;
            }
            _ => {} // Cancelled, superseded and otherwise stale results are ignored.
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
        self.dialog = None;
        self.notification = None;
        Some(id)
    }

    pub fn status(&self) -> &'static str {
        if self.shutdown_request.is_some() {
            "Stopping background worker…"
        } else if !self.worker_available {
            "Background worker unavailable"
        } else if self.current_operation.is_some() {
            "Working in the background…"
        } else {
            "Ready"
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
            result: Ok(()),
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
            result: Ok(()),
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
            result: Ok(()),
        });
        assert_eq!(state.notification, Some(Notification::Cancelled));
        let navigated = request(&mut state);
        state.navigate(Screen::Modules);
        state.event(BackendEvent::Completed {
            id: navigated,
            result: Ok(()),
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
            result: Ok(()),
        });
        state.event(BackendEvent::Stopped { id: old });
        assert!(state.worker_available);
        state.event(BackendEvent::Stopped { id: shutdown });
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
}
