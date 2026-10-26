// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{CryptoMode, CryptoScope, KeyJob, KeyProfile};
use pkcs11_client::{KeyType, ObjectClass};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyField {
    Salt,
    Info,
    Length,
    Input,
    Output,
    Label,
    Id,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapTarget {
    pub id: ResourceId,
    pub label: String,
    pub identifier: String,
}
impl std::fmt::Display for WrapTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} · ID {}", self.label, self.identifier)
    }
}
pub struct KeyForm {
    pub hkdf: HkdfForm,
    pub id: RequestId,
    pub scope: CryptoScope,
    pub profile: Option<KeyProfile>,
    pub loaded: bool,
    pub input: String,
    pub output: String,
    pub label: String,
    pub key_id: String,
    pub targets: Vec<WrapTarget>,
    pub target: Option<WrapTarget>,
    picked_input: Option<PathBuf>,
    picked_output: Option<PathBuf>,
    pub picker: Option<(RequestId, KeyField)>,
}
impl UiState {
    pub fn can_open_key_operation(&self, mode: CryptoMode) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Objects
            && self.token().is_some_and(|token| {
                token.login == LoginState::User && (mode == CryptoMode::Wrap || token.can_manage())
            })
            && self.object().is_some_and(|object| {
                !object.ambiguous
                    && object.uri.is_some()
                    && match mode {
                        CryptoMode::Hkdf => {
                            object.class == Some(ObjectClass::SECRET_KEY)
                                && matches!(
                                    self.object_key_type(),
                                    Some(KeyType::GENERIC_SECRET | KeyType::HKDF)
                                )
                        }
                        CryptoMode::Derive => {
                            object.class == Some(ObjectClass::PRIVATE_KEY)
                                && self.object_key_type() == Some(KeyType::EC)
                        }
                        CryptoMode::Encapsulate | CryptoMode::Decapsulate => {
                            object.class
                                == Some(if mode == CryptoMode::Encapsulate {
                                    ObjectClass::PUBLIC_KEY
                                } else {
                                    ObjectClass::PRIVATE_KEY
                                })
                                && self.object_key_type() == Some(KeyType::ML_KEM)
                        }
                        CryptoMode::Wrap | CryptoMode::Unwrap => {
                            object.class == Some(ObjectClass::SECRET_KEY)
                                && self.object_key_type() == Some(KeyType::AES)
                        }
                        _ => false,
                    }
            })
    }
    pub fn open_key_operation(&mut self, mode: CryptoMode) -> Option<BackendCommand> {
        if !self.can_open_key_operation(mode) {
            return None;
        }
        let scope = CryptoScope {
            module: self.module()?.id,
            token: self.token()?.id,
            object: self.object()?.id,
            mode,
        };
        let targets = self
            .objects
            .iter()
            .filter(|entry| {
                entry.id != scope.object
                    && entry.class == Some(ObjectClass::SECRET_KEY)
                    && entry.uri.is_some()
                    && !entry.ambiguous
            })
            .map(|entry| WrapTarget {
                id: entry.id,
                label: entry.label.clone(),
                identifier: entry.identifier.clone(),
            })
            .collect();
        let id = self.begin(OperationKind::CryptoOptions)?;
        self.clear_crypto_form();
        self.key_form = Some(KeyForm {
            hkdf: HkdfForm::default(),
            id,
            scope,
            profile: None,
            loaded: false,
            input: String::new(),
            output: String::new(),
            label: String::new(),
            key_id: String::new(),
            targets,
            target: None,
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
    pub fn key_edit(&mut self, id: RequestId, field: KeyField, value: String) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
        {
            form.picker = None;
            match field {
                KeyField::Salt if form.scope.mode == CryptoMode::Hkdf => form.hkdf.salt = value,
                KeyField::Info if form.scope.mode == CryptoMode::Hkdf => form.hkdf.info = value,
                KeyField::Length if form.scope.mode == CryptoMode::Hkdf => form.hkdf.length = value,
                KeyField::Salt | KeyField::Info | KeyField::Length => {}
                KeyField::Input => {
                    form.input = value;
                    form.picked_input = None;
                }
                KeyField::Output => {
                    form.output = value;
                    form.picked_output = None;
                }
                KeyField::Label => form.label = value,
                KeyField::Id => form.key_id = value,
            }
        }
    }
    pub fn key_target(&mut self, id: RequestId, target: WrapTarget) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.targets.contains(&target)
        {
            form.target = Some(target);
        }
    }
    pub fn key_picker(&mut self, id: RequestId, field: KeyField) -> Option<(RequestId, bool)> {
        let form = self.key_form.as_ref()?;
        if !self.can_submit()
            || form.id != id
            || form.picker.is_some()
            || !matches!(
                (form.scope.mode, field),
                (CryptoMode::Wrap | CryptoMode::Encapsulate, KeyField::Output)
                    | (
                        CryptoMode::Derive | CryptoMode::Unwrap | CryptoMode::Decapsulate,
                        KeyField::Input
                    )
            )
        {
            return None;
        }
        let request = self.request_id()?;
        self.key_form.as_mut()?.picker = Some((request, field));
        Some((request, field == KeyField::Output))
    }
    pub fn key_picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        if self.shutdown_request.is_some() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && let Some((request, field)) = form.picker
            && request == id
        {
            form.picker = None;
            if let Some(path) = path {
                match field {
                    KeyField::Input => {
                        form.input = path.to_string_lossy().into_owned();
                        form.picked_input = Some(path);
                    }
                    KeyField::Output => {
                        form.output = path.to_string_lossy().into_owned();
                        form.picked_output = Some(path);
                    }
                    _ => (),
                }
            }
        }
    }
    pub fn dismiss_key_operation(&mut self, id: RequestId) {
        if self.key_form.as_ref().is_some_and(|form| form.id == id) {
            self.cancel();
            self.clear_crypto_form();
        }
    }
    pub fn submit_key_operation(&mut self, id: RequestId) -> Option<BackendCommand> {
        let form = self.key_form.as_ref()?;
        if form.id != id
            || !self.can_open_key_operation(form.scope.mode)
            || self.selected_module != Some(form.scope.module)
            || self.selected_token != Some(form.scope.token)
            || self.selected_object != Some(form.scope.object)
        {
            return None;
        }
        let identity = management::identifier(&form.key_id);
        let hkdf_job = if let Some(KeyProfile::Hkdf(profile)) = form.profile {
            form.hkdf
                .job(profile, identity.as_deref(), &form.label)
                .ok()
        } else {
            None
        };
        let valid = form
            .profile
            .is_some_and(|profile| profile.supports(form.scope.mode))
            && form.loaded
            && match form.scope.mode {
                CryptoMode::Hkdf => hkdf_job.is_some(),
                CryptoMode::Wrap => {
                    !form.output.is_empty()
                        && form
                            .target
                            .as_ref()
                            .is_some_and(|target| form.targets.contains(target))
                }
                CryptoMode::Derive
                | CryptoMode::Unwrap
                | CryptoMode::Encapsulate
                | CryptoMode::Decapsulate => {
                    (if form.scope.mode == CryptoMode::Encapsulate {
                        !form.output.is_empty()
                    } else {
                        !form.input.is_empty()
                    }) && !form.label.is_empty()
                        && form.label.len() <= 128
                        && identity.as_ref().is_some_and(|id| id.len() <= 128)
                }
                _ => false,
            };
        if !valid {
            self.notification = Some(Notification::Error(
                if form.scope.mode == CryptoMode::Hkdf {
                    BackendError::HkdfInput
                } else {
                    BackendError::KeyOperationInput
                },
            ));
            return None;
        }
        let form = self.key_form.take()?;
        let input = form
            .picked_input
            .unwrap_or_else(|| PathBuf::from(form.input));
        let job = match form.scope.mode {
            CryptoMode::Hkdf => KeyJob::Hkdf(hkdf_job?),
            CryptoMode::Wrap => KeyJob::Wrap {
                target: form.target?.id,
                output: form
                    .picked_output
                    .unwrap_or_else(|| PathBuf::from(form.output)),
            },
            CryptoMode::Derive => KeyJob::Derive {
                peer: input,
                id: identity?,
                label: form.label.into_bytes(),
            },
            CryptoMode::Encapsulate => KeyJob::Encapsulate {
                output: form
                    .picked_output
                    .unwrap_or_else(|| PathBuf::from(form.output)),
                id: identity?,
                label: form.label.into_bytes(),
            },
            CryptoMode::Decapsulate => KeyJob::Decapsulate {
                input,
                id: identity?,
                label: form.label.into_bytes(),
            },
            CryptoMode::Unwrap => KeyJob::Unwrap {
                input,
                id: identity?,
                label: form.label.into_bytes(),
            },
            _ => return None,
        };
        let id = self.begin(OperationKind::KeyOperation)?;
        self.reset_browser();
        Some(BackendCommand::KeyOperation {
            id,
            scope: form.scope,
            profile: form.profile?,
            job,
        })
    }
}
