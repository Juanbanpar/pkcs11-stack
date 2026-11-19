// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    backend::{BackendCommand, BackendError, BackendEvent},
    state::{Dialog, FilePurpose, TokenPage},
};
use iced::Task;

use super::{App, Message};

impl App {
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
            Message::HkdfOutput { id, output } => self.state.hkdf_output(id, output),
            Message::KeyEdit { id, field, value } => self.state.key_edit(id, field, value),
            Message::KeyTarget { id, target } => self.state.key_target(id, target),
            Message::KeyKdf { id, kdf } => self.state.key_kdf(id, kdf),
            Message::KeyOutput { id, output } => self.state.key_output(id, output),
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
                                    .set_title("Save key operation output to a new file")
                                    .save_file()
                                    .await
                            } else {
                                dialog
                                    .set_title("Select key operation input file")
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
                    if !key.0.supports_context_authentication() {
                        self.state.management.always_authenticate = false;
                    }
                }
            }
            Message::AlwaysAuthenticate(value) => {
                if self.state.can_submit()
                    && self
                        .state
                        .management
                        .key
                        .is_some_and(|key| key.0.supports_context_authentication())
                {
                    self.state.management.always_authenticate = value;
                }
            }
            Message::Generate => {
                let command = self.state.generate();
                self.submit(command);
            }
            Message::ImportPublicKey => {
                let command = self.state.import_public_key();
                self.submit(command);
            }
            Message::PublicKeyPurpose(purpose) => self.state.public_key_purpose(purpose),
            Message::ImportMlKem => {
                let command = self.state.import_ml_kem();
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
            Message::ChooseCertificate
            | Message::ChoosePublicKey
            | Message::ChooseMlKem
            | Message::ExportObject => {
                let request = if matches!(message, Message::ChoosePublicKey) {
                    self.state.begin_public_key_file()
                } else if matches!(message, Message::ChooseMlKem) {
                    self.state.begin_ml_kem_file()
                } else {
                    self.state
                        .begin_object_file(matches!(message, Message::ExportObject))
                };
                if let Some((id, purpose)) = request {
                    return Task::perform(
                        async move {
                            let dialog = rfd::AsyncFileDialog::new();
                            let file =
                                match purpose {
                                    FilePurpose::PublicKey => dialog
                                        .set_title(
                                            "Select an RSA/EC/EdDSA/Montgomery SPKI DER public key",
                                        )
                                        .pick_file()
                                        .await,
                                    FilePurpose::MlKem => {
                                        dialog
                                            .set_title("Select an ML-KEM SPKI DER public key")
                                            .pick_file()
                                            .await
                                    }
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
}
