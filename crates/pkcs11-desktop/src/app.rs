// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    backend::{
        BackendCommand, BackendError, BackendEvent, CryptoMode, EventSource, LoginRole, RequestId,
        ResourceId, Worker,
    },
    state::{
        CryptoField, Dialog, FilePurpose, KeyChoice, ManagementField, Notification, Screen,
        SignatureChoice, TokenPage, UiState,
    },
    views,
};
use iced::{Element, Subscription, Task, Theme};
use std::path::PathBuf;

#[derive(Clone)]
pub enum Message {
    OpenCrypto(CryptoMode),
    CryptoChoice {
        id: RequestId,
        choice: SignatureChoice,
    },
    CryptoPolicy {
        id: RequestId,
        software: bool,
    },
    CryptoPin {
        id: RequestId,
        pin: secrecy::SecretString,
    },
    CryptoProtected {
        id: RequestId,
        enabled: bool,
    },
    CryptoEdit {
        id: RequestId,
        field: CryptoField,
        value: String,
    },
    CryptoBrowse {
        id: RequestId,
        field: CryptoField,
    },
    CryptoPicked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    SubmitCrypto(RequestId),
    DismissCrypto(RequestId),
    Navigate(Screen),
    ToggleTheme,
    EditPath(String),
    Browse,
    Picked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    Load,
    Unload,
    Refresh,
    OpenLogin(LoginRole),
    PinInput {
        id: RequestId,
        pin: secrecy::SecretString,
    },
    ProtectedPath {
        id: RequestId,
        enabled: bool,
    },
    SubmitLogin(RequestId),
    DismissLogin(RequestId),
    Logout,
    ShowPage(TokenPage),
    RefreshObjects,
    ReadCapabilities,
    ManagementEdit {
        field: ManagementField,
        value: String,
    },
    GenerationKey(KeyChoice),
    AlwaysAuthenticate(bool),
    Generate,
    ImportCertificate,
    ChooseCertificate,
    ExportObject,
    ObjectFilePicked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    RequestDelete,
    ConfirmDelete(RequestId),
    RefreshMechanisms,
    SelectObject(ResourceId),
    SelectMechanism(pkcs11_client::MechanismType),
    ObjectFilter(String),
    MechanismFilter(String),
    SelectModule(ResourceId),
    SelectToken {
        module: ResourceId,
        token: ResourceId,
    },
    Cancel,
    Backend(BackendEvent),
    CloseRequested,
    Joined {
        id: RequestId,
        result: Result<(), BackendError>,
    },
    About,
    DismissDialog,
    DismissNotification,
}
// Debug omits message payloads.
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenCrypto(_) => "OpenCrypto",
            Self::CryptoChoice { .. } => "CryptoChoice",
            Self::CryptoPolicy { .. } => "CryptoPolicy",
            Self::CryptoPin { .. } => "CryptoPin",
            Self::CryptoProtected { .. } => "CryptoProtected",
            Self::CryptoEdit { .. } => "CryptoEdit",
            Self::CryptoBrowse { .. } => "CryptoBrowse",
            Self::CryptoPicked { .. } => "CryptoPicked",
            Self::SubmitCrypto(_) => "SubmitCrypto",
            Self::DismissCrypto(_) => "DismissCrypto",
            Self::Navigate(_) => "Navigate",
            Self::ToggleTheme => "ToggleTheme",
            Self::EditPath(_) => "EditPath",
            Self::Browse => "Browse",
            Self::Picked { .. } => "Picked",
            Self::Load => "Load",
            Self::Unload => "Unload",
            Self::Refresh => "Refresh",
            Self::OpenLogin(_) => "OpenLogin",
            Self::PinInput { .. } => "PinInput",
            Self::ProtectedPath { .. } => "ProtectedPath",
            Self::SubmitLogin(_) => "SubmitLogin",
            Self::DismissLogin(_) => "DismissLogin",
            Self::Logout => "Logout",
            Self::ShowPage(_) => "ShowPage",
            Self::ReadCapabilities => "ReadCapabilities",
            Self::ManagementEdit { .. } => "ManagementEdit",
            Self::GenerationKey(_) => "GenerationKey",
            Self::AlwaysAuthenticate(_) => "AlwaysAuthenticate",
            Self::Generate => "Generate",
            Self::ImportCertificate => "ImportCertificate",
            Self::ChooseCertificate => "ChooseCertificate",
            Self::ExportObject => "ExportObject",
            Self::ObjectFilePicked { .. } => "ObjectFilePicked",
            Self::RequestDelete => "RequestDelete",
            Self::ConfirmDelete(_) => "ConfirmDelete",
            Self::RefreshObjects => "RefreshObjects",
            Self::RefreshMechanisms => "RefreshMechanisms",
            Self::SelectObject(_) => "SelectObject",
            Self::SelectMechanism(_) => "SelectMechanism",
            Self::ObjectFilter(_) => "ObjectFilter",
            Self::MechanismFilter(_) => "MechanismFilter",
            Self::SelectModule(_) => "SelectModule",
            Self::SelectToken { .. } => "SelectToken",
            Self::Cancel => "Cancel",
            Self::Backend(_) => "Backend",
            Self::CloseRequested => "CloseRequested",
            Self::Joined { .. } => "Joined",
            Self::About => "About",
            Self::DismissDialog => "DismissDialog",
            Self::DismissNotification => "DismissNotification",
        })
    }
}

pub struct App {
    pub state: UiState,
    worker: Option<Worker>,
    source: Option<EventSource>,
}
impl App {
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

    pub fn update(&mut self, message: Message) -> Task<Message> {
        // Shutdown remains responsive but cannot enqueue more commands or dialogs.
        if self.state.shutdown_request.is_some()
            && !matches!(
                message,
                Message::Backend(_) | Message::Joined { .. } | Message::CloseRequested
            )
        {
            return Task::none();
        }
        match message {
            Message::OpenCrypto(mode) => {
                let command = self.state.open_crypto(mode);
                self.submit(command);
            }
            Message::CryptoPolicy { id, software } => {
                let command = self.state.crypto_policy(id, software);
                self.submit(command);
            }
            Message::CryptoChoice { id, choice } => self.state.crypto_choice(id, choice),
            Message::CryptoPin { id, pin } => self.state.crypto_pin(id, pin),
            Message::CryptoProtected { id, enabled } => self.state.crypto_protected(id, enabled),
            Message::CryptoEdit { id, field, value } => self.state.crypto_edit(id, field, value),
            Message::CryptoPicked { id, path } => self.state.crypto_picked(id, path),
            Message::CryptoBrowse { id, field } => {
                if let Some((request, save)) = self.state.crypto_picker(id, field) {
                    return Task::perform(
                        async move {
                            let dialog = rfd::AsyncFileDialog::new();
                            let file = if save {
                                dialog
                                    .set_title("Save signature to a new file")
                                    .set_file_name("signature.bin")
                                    .save_file()
                                    .await
                            } else {
                                dialog
                                    .set_title("Select a message or signature file")
                                    .pick_file()
                                    .await
                            };
                            file.map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::CryptoPicked { id: request, path },
                    );
                }
            }
            Message::SubmitCrypto(id) => {
                let command = self.state.submit_crypto(id);
                self.submit(command);
            }
            Message::DismissCrypto(id) => self.state.dismiss_crypto(id),
            Message::Navigate(screen) => self.state.navigate(screen),
            Message::ToggleTheme => self.state.dark_theme = !self.state.dark_theme,
            Message::EditPath(path) => self.state.edit_path(path),
            Message::Browse => {
                if let Some(id) = self.state.begin_picker() {
                    return Task::perform(
                        async {
                            rfd::AsyncFileDialog::new()
                                .set_title("Select a trusted PKCS#11 module")
                                .pick_file()
                                .await
                                .map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::Picked { id, path },
                    );
                }
            }
            Message::Picked { id, path } => self.state.picked(id, path),
            Message::Load => {
                let command = self.state.load();
                self.submit(command);
            }
            Message::Unload => {
                let command = self.state.unload();
                self.submit(command);
            }
            Message::Refresh => {
                let command = self.state.refresh();
                self.submit(command);
            }
            Message::OpenLogin(role) => self.state.open_login(role),
            Message::PinInput { id, pin } => self.state.edit_pin(id, pin),
            Message::ProtectedPath { id, enabled } => self.state.use_protected_path(id, enabled),
            Message::SubmitLogin(id) => {
                let command = self.state.login(id);
                self.submit(command);
            }
            Message::DismissLogin(id) => {
                if self
                    .state
                    .login_form
                    .as_ref()
                    .is_some_and(|form| form.id == id)
                {
                    self.state.login_form = None;
                }
            }
            Message::Logout => {
                let command = self.state.logout();
                self.submit(command);
            }
            Message::ShowPage(page) => {
                let command = self.state.show_page(page);
                self.submit(command);
            }
            Message::ReadCapabilities => {
                let command = self.state.read_capabilities();
                self.submit(command);
            }
            Message::ManagementEdit { field, value } => self.state.edit_management(field, value),
            Message::GenerationKey(key) => {
                if self.state.can_submit() && self.state.management.keys.contains(&key) {
                    self.state.management.key = Some(key);
                }
            }
            Message::AlwaysAuthenticate(value) => {
                if self.state.can_submit() {
                    self.state.management.always_authenticate = value;
                }
            }
            Message::Generate => {
                let command = self.state.generate();
                self.submit(command);
            }
            Message::ImportCertificate => {
                let command = self.state.import_certificate();
                self.submit(command);
            }
            Message::RequestDelete => self.state.request_delete(),
            Message::ConfirmDelete(id) => {
                let command = self.state.confirm_delete(id);
                self.submit(command);
            }
            Message::ChooseCertificate | Message::ExportObject => {
                if let Some((id, purpose)) = self
                    .state
                    .begin_object_file(matches!(message, Message::ExportObject))
                {
                    return Task::perform(
                        async move {
                            let dialog = rfd::AsyncFileDialog::new();
                            let file = match purpose {
                                FilePurpose::Certificate => {
                                    dialog
                                        .set_title("Select a DER certificate")
                                        .pick_file()
                                        .await
                                }
                                FilePurpose::Export { .. } => {
                                    dialog
                                        .set_title("Export public object to a new file")
                                        .set_file_name("object.der")
                                        .save_file()
                                        .await
                                }
                            };
                            file.map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::ObjectFilePicked { id, path },
                    );
                }
            }
            Message::ObjectFilePicked { id, path } => {
                let command = self.state.object_file_picked(id, path);
                self.submit(command);
            }
            Message::RefreshObjects => {
                let command = self.state.read_objects();
                self.submit(command);
            }
            Message::RefreshMechanisms => {
                let command = self.state.read_mechanisms();
                self.submit(command);
            }
            Message::SelectObject(object) => {
                let command = self.state.select_object(object);
                self.submit(command);
            }
            Message::SelectMechanism(mechanism) => self.state.select_mechanism(mechanism),
            Message::ObjectFilter(filter) => self.state.edit_object_filter(filter),
            Message::MechanismFilter(filter) => self.state.edit_mechanism_filter(filter),
            Message::SelectModule(module) => self.state.select_module(module),
            Message::SelectToken { module, token } => self.state.select_token(module, token),
            Message::Cancel => self.state.cancel(),
            Message::Backend(event) => self.state.event(event),
            Message::CloseRequested => {
                if let Some(id) = self.state.begin_shutdown() {
                    return match self.worker.take() {
                        Some(worker) => Task::perform(worker.shutdown(id), move |result| {
                            Message::Joined { id, result }
                        }),
                        None => iced::exit(),
                    };
                }
            }
            Message::Joined { id, result } if self.state.shutdown_request == Some(id) => {
                if let Err(error) = result {
                    // Fixed text only; exit still occurs after the failed worker is joined.
                    eprintln!("{}", error.message());
                }
                return iced::exit();
            }
            Message::Joined { .. } => {}
            Message::About => {
                if let Some(id) = self.state.crypto_form.as_ref().map(|form| form.id) {
                    self.state.dismiss_crypto(id);
                }
                self.state.login_form = None;
                self.state.management.confirmation = None;
                self.state.dialog = Some(Dialog::About);
            }
            Message::DismissDialog => {
                self.state.dialog = None;
                self.state.management.confirmation = None;
            }
            Message::DismissNotification => self.state.notification = None,
        }
        Task::none()
    }

    fn submit(&mut self, command: Option<BackendCommand>) {
        if let Some(command) = command {
            let id = command.id();
            let result = self
                .worker
                .as_ref()
                .ok_or(BackendError::Disconnected)
                .and_then(|worker| worker.submit(command));
            if let Err(error) = result {
                self.state.event(BackendEvent::Completed {
                    id,
                    result: Err(error),
                });
            }
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
            iced::window::close_requests().map(|_| Message::CloseRequested),
        ])
    }

    pub fn theme(&self) -> Theme {
        if self.state.dark_theme {
            Theme::Dark
        } else {
            Theme::Light
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        views::main::view(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use secrecy::ExposeSecret;
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
        let _ = app.update(Message::ToggleTheme);
        assert_eq!(app.theme(), Theme::Dark);
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
