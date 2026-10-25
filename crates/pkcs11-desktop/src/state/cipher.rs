// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{AesGcmFiles, CipherJob, CipherParameters, CryptoMode, CryptoScope};
use pkcs11_client::{DigestAlgorithm, ObjectClass};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherChoice(pub CipherParameters);
impl std::fmt::Display for CipherChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let choice = match self.0 {
            CipherParameters::AesGcm(caps) => {
                return write!(f, "AES-{} GCM / 128-bit tag", caps.key_size.length() * 8);
            }
            CipherParameters::Oaep(choice) => choice,
        };
        f.write_str(match choice.digest {
            DigestAlgorithm::Sha256 => "RSA-OAEP / SHA-256",
            DigestAlgorithm::Sha384 => "RSA-OAEP / SHA-384",
            DigestAlgorithm::Sha512 => "RSA-OAEP / SHA-512",
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub enum CipherField {
    Input,
    Output,
    Nonce,
    Aad,
}
pub struct CipherForm {
    pub id: RequestId,
    pub scope: CryptoScope,
    pub choices: Vec<CipherChoice>,
    pub choice: Option<CipherChoice>,
    pub loaded: bool,
    pub input: String,
    pub output: String,
    pub nonce: String,
    pub aad: String,
    picked_aad: Option<PathBuf>,
    picked_input: Option<PathBuf>,
    picked_output: Option<PathBuf>,
    pub picker: Option<(RequestId, CipherField)>,
}
impl UiState {
    pub fn can_open_cipher(&self, mode: CryptoMode) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Objects
            && self.object().is_some_and(|entry| {
                !entry.ambiguous
                    && entry.uri.is_some()
                    && match mode {
                        CryptoMode::Encrypt => {
                            entry.class == Some(ObjectClass::PUBLIC_KEY)
                                || (entry.class == Some(ObjectClass::SECRET_KEY)
                                    && self
                                        .token()
                                        .is_some_and(|token| token.login == LoginState::User))
                        }
                        CryptoMode::Decrypt => {
                            matches!(
                                entry.class,
                                Some(ObjectClass::PRIVATE_KEY | ObjectClass::SECRET_KEY)
                            ) && self
                                .token()
                                .is_some_and(|token| token.login == LoginState::User)
                        }
                        _ => false,
                    }
            })
    }
    pub fn open_cipher(&mut self, mode: CryptoMode) -> Option<BackendCommand> {
        if !self.can_open_cipher(mode) {
            return None;
        }
        let scope = CryptoScope {
            module: self.module()?.id,
            token: self.token()?.id,
            object: self.object()?.id,
            mode,
        };
        let id = self.begin(OperationKind::CryptoOptions)?;
        self.clear_crypto_form();
        self.cipher_form = Some(CipherForm {
            id,
            scope,
            choices: Vec::new(),
            choice: None,
            loaded: false,
            input: String::new(),
            output: String::new(),
            nonce: String::new(),
            aad: String::new(),
            picked_aad: None,
            picked_input: None,
            picked_output: None,
            picker: None,
        });
        Some(BackendCommand::CryptoOptions {
            id,
            scope,
            software_hashing: false,
        })
    }
    pub fn cipher_edit(&mut self, id: RequestId, field: CipherField, value: String) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.cipher_form
            && form.id == id
        {
            match field {
                CipherField::Nonce => form.nonce = value,
                CipherField::Aad => {
                    form.aad = value;
                    form.picked_aad = None;
                }
                CipherField::Input => {
                    form.input = value;
                    form.picked_input = None;
                }
                CipherField::Output => {
                    form.output = value;
                    form.picked_output = None;
                }
            }
            form.picker = None;
        }
    }
    pub fn cipher_choice(&mut self, id: RequestId, choice: CipherChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.cipher_form
            && form.id == id
            && form.choices.contains(&choice)
        {
            form.choice = Some(choice);
        }
    }
    pub fn cipher_picker(
        &mut self,
        id: RequestId,
        field: CipherField,
    ) -> Option<(RequestId, bool)> {
        let form = self.cipher_form.as_ref()?;
        if matches!(field, CipherField::Nonce) {
            return None;
        }
        if !self.can_submit() || form.id != id || form.picker.is_some() {
            return None;
        }
        let request = self.request_id()?;
        self.cipher_form.as_mut()?.picker = Some((request, field));
        Some((request, matches!(field, CipherField::Output)))
    }
    pub fn cipher_picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        if self.shutdown_request.is_some() {
            return;
        }
        if let Some(form) = &mut self.cipher_form
            && let Some((request, field)) = form.picker
            && request == id
        {
            form.picker = None;
            if let Some(path) = path {
                match field {
                    CipherField::Nonce => {}
                    CipherField::Aad => {
                        form.aad = path.to_string_lossy().into_owned();
                        form.picked_aad = Some(path);
                    }
                    CipherField::Input => {
                        form.input = path.to_string_lossy().into_owned();
                        form.picked_input = Some(path);
                    }
                    CipherField::Output => {
                        form.output = path.to_string_lossy().into_owned();
                        form.picked_output = Some(path);
                    }
                }
            }
        }
    }
    pub fn dismiss_cipher(&mut self, id: RequestId) {
        if self.cipher_form.as_ref().is_some_and(|form| form.id == id) {
            self.cancel();
            self.cipher_form = None;
        }
    }
    pub fn submit_cipher(&mut self, id: RequestId) -> Option<BackendCommand> {
        let form = self.cipher_form.as_ref()?;
        if form.id != id
            || !self.can_open_cipher(form.scope.mode)
            || self.selected_module != Some(form.scope.module)
            || self.selected_token != Some(form.scope.token)
            || self.selected_object != Some(form.scope.object)
        {
            return None;
        }
        if form.input.is_empty()
            || form.output.is_empty()
            || !form.loaded
            || !form
                .choice
                .is_some_and(|choice| form.choices.contains(&choice))
        {
            self.notification = Some(Notification::Error(BackendError::CipherInput));
            return None;
        }
        let aes_gcm = if matches!(form.choice?.0, CipherParameters::AesGcm(_)) {
            let nonce = (form.nonce.len() == 24)
                .then(|| management::identifier(&form.nonce))
                .flatten()
                .and_then(|bytes| bytes.try_into().ok());
            let Some(nonce) = nonce else {
                self.notification = Some(Notification::Error(BackendError::CipherInput));
                return None;
            };
            Some(AesGcmFiles {
                nonce,
                aad: form
                    .picked_aad
                    .clone()
                    .or_else(|| (!form.aad.is_empty()).then(|| PathBuf::from(&form.aad))),
            })
        } else {
            None
        };
        let form = self.cipher_form.take()?;
        let job = CipherJob {
            aes_gcm,
            choice: form.choice?.0,
            input: form
                .picked_input
                .unwrap_or_else(|| PathBuf::from(form.input)),
            output: form
                .picked_output
                .unwrap_or_else(|| PathBuf::from(form.output)),
        };
        let id = self.begin(OperationKind::Cipher)?;
        self.reset_browser();
        Some(BackendCommand::Cipher {
            id,
            scope: form.scope,
            job,
        })
    }
}
