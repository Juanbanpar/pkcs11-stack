// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{App, Message, focus_navigation};
use crate::state::{Notification, UiState};
use crate::{
    backend::{BackendError, BackendEvent, LoginRole, RequestId, ResourceId},
    state::{
        AdministrationField, AdministrationPinField, CipherField, CryptoField, Dialog, KeyField,
        RandomField,
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
    let mut app = App::without_worker(UiState::default());
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
    let mut app = App::without_worker(UiState::default());
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
    let mut app = App::without_worker(UiState::default());
    app.state.begin_shutdown();
    let task = app.update(Message::Joined {
        id: RequestId(0),
        result: Ok(()),
    });
    assert_eq!(task.units(), 0);
}
