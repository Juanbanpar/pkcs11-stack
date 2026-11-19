// SPDX-License-Identifier: MIT OR Apache-2.0
mod message;
mod update;

use crate::{
    backend::{EventSource, Worker},
    state::{Notification, UiState},
    views,
};
use iced::{Element, Subscription, Theme};

pub use message::Message;

pub struct App {
    pub state: UiState,
    worker: Option<Worker>,
    source: Option<EventSource>,
}
impl App {
    #[cfg(test)]
    pub(crate) fn without_worker(state: UiState) -> Self {
        Self {
            state,
            worker: None,
            source: None,
        }
    }

    pub fn boot() -> Self {
        let mut state = UiState::default();
        let (worker, source) = match Worker::spawn() {
            Ok((worker, source)) => {
                state.worker_available = true;
                (Some(worker), Some(source))
            }
            Err(error) => {
                state.notification = Some(Notification::Error(error));
                (None, None)
            }
        };
        Self {
            state,
            worker,
            source,
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let events = self
            .source
            .as_ref()
            .map_or_else(Subscription::none, |source| {
                Subscription::run_with(source.clone(), EventSource::stream).map(Message::Backend)
            });
        Subscription::batch([
            events,
            iced::system::theme_changes()
                .map(|mode| Message::Ui(crate::ui::Action::SystemTheme(mode))),
            iced::window::resize_events()
                .map(|(_, size)| Message::Ui(crate::ui::Action::Resize(size))),
            iced::window::close_requests().map(|_| Message::CloseRequested),
        ])
    }

    pub fn theme(&self) -> Theme {
        crate::ui::theme::theme(self.state.presentation.dark())
    }

    pub fn view(&self) -> Element<'_, Message> {
        views::main::view(&self.state)
    }
}

pub(crate) fn shortcut(
    key: &iced::keyboard::Key,
    modifiers: iced::keyboard::Modifiers,
) -> Option<Message> {
    use crate::ui::Action;
    use iced::keyboard::{Key, key::Named};
    if key == &Key::Named(Named::Escape) {
        return Some(Message::Ui(Action::Escape));
    }
    if !modifiers.command() || modifiers.alt() || modifiers.shift() {
        return None;
    }
    match key.as_ref() {
        Key::Character("o") => Some(Message::Ui(Action::AddModule)),
        Key::Character("f") => Some(Message::Ui(Action::Filter)),
        Key::Character("r") => Some(Message::Ui(Action::Refresh)),
        Key::Character("q") => Some(Message::CloseRequested),
        _ => None,
    }
}

pub(crate) fn focus_navigation(
    key: iced::keyboard::Key,
    modifiers: iced::keyboard::Modifiers,
) -> Option<Message> {
    use iced::keyboard::{Key, key::Named};
    if key == Key::Named(Named::Tab)
        && !modifiers.control()
        && !modifiers.alt()
        && !modifiers.logo()
    {
        Some(Message::MoveFocus {
            backwards: modifiers.shift(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::{BackendError, BackendEvent, LoginRole, RequestId, ResourceId},
        state::{
            AdministrationField, AdministrationPinField, CipherField, CryptoField, Dialog,
            KeyField, RandomField,
        },
    };
    use std::path::PathBuf;

    #[test]
    fn form_focus_navigation_accepts_only_tab_and_shift_tab() {
        use iced::keyboard::{Key, Modifiers, key::Named};
        assert!(matches!(
            focus_navigation(Key::Named(Named::Tab), Modifiers::empty()),
            Some(Message::MoveFocus { backwards: false })
        ));
        assert!(matches!(
            focus_navigation(Key::Named(Named::Tab), Modifiers::SHIFT),
            Some(Message::MoveFocus { backwards: true })
        ));
        for modifier in [Modifiers::CTRL, Modifiers::ALT, Modifiers::LOGO] {
            assert!(focus_navigation(Key::Named(Named::Tab), modifier).is_none());
        }
        assert!(
            focus_navigation(
                Key::Character("secret-input-canary".into()),
                Modifiers::empty()
            )
            .is_none()
        );
        assert!(focus_navigation(Key::Named(Named::Enter), Modifiers::empty()).is_none());
    }

    #[test]
    fn client_errors_messages_and_notifications_do_not_echo_input() {
        let secret = "pin-value=desktop-redaction-canary";
        let error =
            pkcs11_client::CertificateDocument::from_der(secret.as_bytes().to_vec()).unwrap_err();
        let safe = BackendError::from(&error);
        let message = Message::Backend(BackendEvent::Completed {
            id: RequestId(7),
            result: Err(safe),
        });
        let rendered = format!("{safe:?} {message:?} {}", Notification::Error(safe).text());
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("desktop-redaction-canary"));
        assert_eq!(safe, BackendError::Client(pkcs11_client::ErrorKind::Client));
        assert_eq!(format!("{message:?}"), "Backend");
        assert_eq!(
            format!(
                "{:?}",
                Message::AdministrationPin {
                    id: RequestId(8),
                    field: AdministrationPinField::New,
                    pin: secret.into()
                }
            ),
            "AdministrationPin"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::AdministrationEdit {
                    id: RequestId(8),
                    field: AdministrationField::Confirmation,
                    value: secret.into()
                }
            ),
            "AdministrationEdit"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::KeyEdit {
                    id: RequestId(8),
                    field: KeyField::Input,
                    value: secret.into()
                }
            ),
            "KeyEdit"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::KeyPicked {
                    id: RequestId(8),
                    path: Some(secret.into())
                }
            ),
            "KeyPicked"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::CipherEdit {
                    id: RequestId(8),
                    field: CipherField::Input,
                    value: secret.into()
                }
            ),
            "CipherEdit"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::RandomEdit {
                    field: RandomField::Path,
                    value: secret.into()
                }
            ),
            "RandomEdit"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::CryptoPin {
                    id: RequestId(8),
                    pin: secret.into()
                }
            ),
            "CryptoPin"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::CryptoEdit {
                    id: RequestId(8),
                    field: CryptoField::Input,
                    value: secret.into()
                }
            ),
            "CryptoEdit"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::PinInput {
                    id: RequestId(1),
                    pin: secret.into()
                }
            ),
            "PinInput"
        );
        assert_eq!(
            format!("{:?}", Message::EditPath(secret.into())),
            "EditPath"
        );
        assert_eq!(
            format!("{:?}", Message::ObjectFilter(secret.into())),
            "ObjectFilter"
        );
        assert_eq!(
            format!("{:?}", Message::MechanismFilter(secret.into())),
            "MechanismFilter"
        );
        assert_eq!(
            format!(
                "{:?}",
                Message::Picked {
                    id: RequestId(8),
                    path: Some(PathBuf::from(secret))
                }
            ),
            "Picked"
        );
    }

    #[test]
    fn cancelling_a_pin_form_discards_secret_and_ignores_older_form_messages() {
        let mut app = App {
            state: UiState::default(),
            worker: None,
            source: None,
        };
        let id = RequestId(2);
        app.state.login_form = Some(crate::state::LoginForm {
            id,
            module: ResourceId(3),
            token: ResourceId(4),
            role: LoginRole::User,
            protected_path: false,
            pin: "original-canary".into(),
        });
        let _ = app.update(Message::DismissLogin(RequestId(1)));
        assert_eq!(
            app.state.login_form.as_ref().unwrap().pin.expose_secret(),
            "original-canary"
        );
        let _ = app.update(Message::PinInput {
            id,
            pin: "edited-canary".into(),
        });
        assert_eq!(
            app.state.login_form.as_ref().unwrap().pin.expose_secret(),
            "edited-canary"
        );
        let _ = app.update(Message::DismissLogin(id));
        let _ = app.update(Message::PinInput {
            id,
            pin: "late-canary".into(),
        });
        assert!(app.state.login_form.is_none());
    }

    #[test]
    fn theme_and_dialog_transitions_need_no_window() {
        let mut app = App {
            state: UiState::default(),
            worker: None,
            source: None,
        };
        let _ = app.update(Message::Ui(crate::ui::Action::SetAppearance(
            crate::ui::theme::Appearance::Dark,
        )));
        assert_eq!(app.theme(), crate::ui::theme::theme(true));
        let _ = app.update(Message::About);
        assert_eq!(app.state.dialog, Some(Dialog::About));
        let _ = app.update(Message::DismissDialog);
        assert_eq!(app.state.dialog, None);
    }

    #[test]
    fn stale_join_does_not_exit() {
        let mut app = App {
            state: UiState::default(),
            worker: None,
            source: None,
        };
        app.state.begin_shutdown();
        let task = app.update(Message::Joined {
            id: RequestId(0),
            result: Ok(()),
        });
        assert_eq!(task.units(), 0);
    }
}
