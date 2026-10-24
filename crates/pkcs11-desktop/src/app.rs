// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    backend::{
        AdministrationKind, BackendCommand, BackendError, BackendEvent, CryptoMode, EventSource,
        LoginRole, RequestId, ResourceId, Worker,
    },
    state::{
        AdministrationField, AdministrationPinField, CipherChoice, CipherField, CryptoField,
        Dialog, FilePurpose, KeyChoice, KeyField, ManagementField, Notification, RandomField,
        Screen, SignatureChoice, TokenPage, UiState, WrapTarget,
    },
    views,
};
use iced::{Element, Subscription, Task, Theme};
use std::path::PathBuf;

#[derive(Clone)]
pub enum Message {
    Ui(crate::ui::Action),
    MoveFocus {
        backwards: bool,
    },
    OpenAdministration(AdministrationKind),
    AdministrationPin {
        id: RequestId,
        field: AdministrationPinField,
        pin: secrecy::SecretString,
    },
    AdministrationEdit {
        id: RequestId,
        field: AdministrationField,
        value: String,
    },
    ReviewAdministration(RequestId),
    SubmitAdministration(RequestId),
    DismissAdministration(RequestId),
    OpenKeyOperation(CryptoMode),
    KeyEdit {
        id: RequestId,
        field: KeyField,
        value: String,
    },
    KeyTarget {
        id: RequestId,
        target: WrapTarget,
    },
    KeyBrowse {
        id: RequestId,
        field: KeyField,
    },
    KeyPicked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    SubmitKeyOperation(RequestId),
    DismissKeyOperation(RequestId),
    OpenCipher(CryptoMode),
    CipherEdit {
        id: RequestId,
        field: CipherField,
        value: String,
    },
    CipherChoice {
        id: RequestId,
        choice: CipherChoice,
    },
    CipherBrowse {
        id: RequestId,
        field: CipherField,
    },
    CipherPicked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    SubmitCipher(RequestId),
    DismissCipher(RequestId),
    RandomEdit {
        field: RandomField,
        value: String,
    },
    RandomBrowse,
    RandomPicked {
        id: RequestId,
        path: Option<PathBuf>,
    },
    GenerateRandom,
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
            Self::Ui(_) => "Ui",
            Self::MoveFocus { .. } => "MoveFocus",
            Self::OpenAdministration(_) => "OpenAdministration",
            Self::AdministrationPin { .. } => "AdministrationPin",
            Self::AdministrationEdit { .. } => "AdministrationEdit",
            Self::ReviewAdministration(_) => "ReviewAdministration",
            Self::SubmitAdministration(_) => "SubmitAdministration",
            Self::DismissAdministration(_) => "DismissAdministration",
            Self::OpenKeyOperation(_) => "OpenKeyOperation",
            Self::KeyEdit { .. } => "KeyEdit",
            Self::KeyTarget { .. } => "KeyTarget",
            Self::KeyBrowse { .. } => "KeyBrowse",
            Self::KeyPicked { .. } => "KeyPicked",
            Self::SubmitKeyOperation(_) => "SubmitKeyOperation",
            Self::DismissKeyOperation(_) => "DismissKeyOperation",
            Self::OpenCipher(_) => "OpenCipher",
            Self::CipherEdit { .. } => "CipherEdit",
            Self::CipherChoice { .. } => "CipherChoice",
            Self::CipherBrowse { .. } => "CipherBrowse",
            Self::CipherPicked { .. } => "CipherPicked",
            Self::SubmitCipher(_) => "SubmitCipher",
            Self::DismissCipher(_) => "DismissCipher",
            Self::RandomEdit { .. } => "RandomEdit",
            Self::RandomBrowse => "RandomBrowse",
            Self::RandomPicked { .. } => "RandomPicked",
            Self::GenerateRandom => "GenerateRandom",
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
        let before_object_task = self.state.crypto_form.is_some()
            || self.state.cipher_form.is_some()
            || self.state.key_form.is_some();
        let before_modal = self.state.dialog.is_some() || self.state.login_form.is_some();
        match message {
            Message::Ui(action) => return self.update_ui(action),
            Message::MoveFocus { backwards } => {
                return if backwards {
                    crate::ui::focus::walk(None, crate::ui::focus::Movement::Previous)
                } else {
                    crate::ui::focus::walk(None, crate::ui::focus::Movement::Next)
                };
            }
            Message::OpenAdministration(kind) => self.state.open_administration(kind),
            Message::AdministrationPin { id, field, pin } => {
                self.state.administration_pin(id, field, pin)
            }
            Message::AdministrationEdit { id, field, value } => {
                self.state.administration_edit(id, field, value)
            }
            Message::ReviewAdministration(id) => self.state.review_administration(id),
            Message::SubmitAdministration(id) => {
                let command = self.state.submit_administration(id);
                self.submit(command);
            }
            Message::DismissAdministration(id) => self.state.dismiss_administration(id),
            Message::OpenKeyOperation(mode) => {
                let command = self.state.open_key_operation(mode);
                self.submit(command);
            }
            Message::KeyEdit { id, field, value } => self.state.key_edit(id, field, value),
            Message::KeyTarget { id, target } => self.state.key_target(id, target),
            Message::KeyPicked { id, path } => self.state.key_picked(id, path),
            Message::SubmitKeyOperation(id) => {
                let command = self.state.submit_key_operation(id);
                self.submit(command);
            }
            Message::DismissKeyOperation(id) => self.state.dismiss_key_operation(id),
            Message::KeyBrowse { id, field } => {
                if let Some((request, save)) = self.state.key_picker(id, field) {
                    return Task::perform(
                        async move {
                            let dialog = rfd::AsyncFileDialog::new();
                            let file = if save {
                                dialog
                                    .set_title("Save wrapped AES key to a new file")
                                    .save_file()
                                    .await
                            } else {
                                dialog
                                    .set_title("Select peer public key or wrapped AES key")
                                    .pick_file()
                                    .await
                            };
                            file.map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::KeyPicked { id: request, path },
                    );
                }
            }
            Message::OpenCipher(mode) => {
                let command = self.state.open_cipher(mode);
                self.submit(command);
            }
            Message::CipherEdit { id, field, value } => self.state.cipher_edit(id, field, value),
            Message::CipherChoice { id, choice } => self.state.cipher_choice(id, choice),
            Message::CipherPicked { id, path } => self.state.cipher_picked(id, path),
            Message::SubmitCipher(id) => {
                let command = self.state.submit_cipher(id);
                self.submit(command);
            }
            Message::DismissCipher(id) => self.state.dismiss_cipher(id),
            Message::CipherBrowse { id, field } => {
                if let Some((request, save)) = self.state.cipher_picker(id, field) {
                    return Task::perform(
                        async move {
                            let dialog = rfd::AsyncFileDialog::new();
                            let file = if save {
                                dialog
                                    .set_title("Save RSA OAEP output to a new file")
                                    .save_file()
                                    .await
                            } else {
                                dialog.set_title("Select RSA OAEP input").pick_file().await
                            };
                            file.map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::CipherPicked { id: request, path },
                    );
                }
            }
            Message::RandomEdit { field, value } => self.state.random_edit(field, value),
            Message::RandomPicked { id, path } => self.state.random_picked(id, path),
            Message::GenerateRandom => {
                let command = self.state.generate_random();
                self.submit(command);
            }
            Message::RandomBrowse => {
                if let Some(id) = self.state.random_picker() {
                    return Task::perform(
                        async {
                            rfd::AsyncFileDialog::new()
                                .set_title("Save token random bytes to a new file")
                                .set_file_name("random.bin")
                                .save_file()
                                .await
                                .map(|file| file.path().to_path_buf())
                        },
                        move |path| Message::RandomPicked { id, path },
                    );
                }
            }
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
                self.state.presentation.overlay = None;
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
                self.state.presentation.task = None;
                self.state.presentation.show_detail = false;
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
                if self.state.selected_object == Some(object) {
                    self.state.presentation.show_detail = true;
                }
                self.submit(command);
            }
            Message::SelectMechanism(mechanism) => {
                self.state.select_mechanism(mechanism);
                if self.state.selected_mechanism == Some(mechanism) {
                    self.state.presentation.show_detail = true;
                }
            }
            Message::ObjectFilter(filter) => {
                self.state.edit_object_filter(filter);
                if self.state.selected_object.is_none() {
                    self.state.presentation.show_detail = false;
                }
            }
            Message::MechanismFilter(filter) => {
                self.state.edit_mechanism_filter(filter);
                if self.state.selected_mechanism.is_none() {
                    self.state.presentation.show_detail = false;
                }
            }
            Message::SelectModule(module) => self.state.select_module(module),
            Message::SelectToken { module, token } => self.state.select_token(module, token),
            Message::Cancel => self.state.cancel(),
            Message::Backend(event) => {
                self.state.event(event);
                if (self.state.token_page == TokenPage::Objects
                    && self.state.selected_object.is_none())
                    || (self.state.token_page == TokenPage::Mechanisms
                        && self.state.selected_mechanism.is_none())
                {
                    self.state.presentation.show_detail = false;
                }
                if self.state.token().is_none() {
                    self.state.presentation.task = None;
                    self.state.presentation.show_detail = false;
                    self.state.presentation.choice = None;
                }
            }
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
                if let Some(id) = self.state.key_form.as_ref().map(|form| form.id) {
                    self.state.dismiss_key_operation(id);
                }
                self.state.administration_form = None;
                if let Some(id) = self.state.cipher_form.as_ref().map(|form| form.id) {
                    self.state.dismiss_cipher(id);
                }
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
        let after_object_task = self.state.crypto_form.is_some()
            || self.state.cipher_form.is_some()
            || self.state.key_form.is_some();
        if !before_object_task && after_object_task {
            return crate::ui::focus::focus("object-task-back");
        }
        let after_modal = self.state.dialog.is_some() || self.state.login_form.is_some();
        if !before_modal && after_modal {
            self.state.presentation.restore_focus = self.state.presentation.focused.clone();
            return crate::ui::focus::focus("modal-cancel");
        }
        if before_modal
            && !after_modal
            && let Some(id) = self.state.presentation.restore_focus.take()
        {
            return crate::ui::focus::focus(id);
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
