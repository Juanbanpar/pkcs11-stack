// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{CryptoJob, CryptoMode, CryptoScope, SignatureOption, SignatureProfile};
use pkcs11_client::{DigestAlgorithm, KeyType, ObjectClass, SignatureAlgorithm};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureChoice(pub SignatureOption);
impl std::fmt::Display for SignatureChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parameters = self.0.parameters;
        let parameters = match parameters {
            SignatureProfile::Classical(parameters) => parameters,
            SignatureProfile::MlDsa(parameter) => {
                return write!(
                    f,
                    "ML-DSA-{} / pure message",
                    match parameter {
                        pkcs11_client::MlDsaParameterSet::MlDsa44 => 44,
                        pkcs11_client::MlDsaParameterSet::MlDsa65 => 65,
                        pkcs11_client::MlDsaParameterSet::MlDsa87 => 87,
                    }
                );
            }
        };
        let family = match parameters.algorithm {
            SignatureAlgorithm::RsaPkcs1 => "RSA PKCS#1 v1.5",
            SignatureAlgorithm::RsaPss => "RSA PSS",
            SignatureAlgorithm::Ecdsa => "ECDSA",
        };
        let digest = match parameters.digest {
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha384 => "SHA-384",
            DigestAlgorithm::Sha512 => "SHA-512",
        };
        write!(f, "{family} / {digest}")?;
        if let Some(pss) = parameters.pss {
            write!(f, " / salt {} bytes", pss.salt_len)?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoField {
    Input,
    Signature,
    DomainContext,
}
pub struct CryptoForm {
    pub id: RequestId,
    pub scope: CryptoScope,
    pub options: Vec<SignatureChoice>,
    pub choice: Option<SignatureChoice>,
    pub loaded: bool,
    pub software_hashing: bool,
    pub domain_context: String,
    pub context_required: bool,
    pub protected_path: bool,
    pub pin: SecretString,
    pub input: String,
    pub signature: String,
    picked_input: Option<PathBuf>,
    picked_signature: Option<PathBuf>,
    pub picker: Option<(RequestId, CryptoField)>,
}
impl UiState {
    pub fn object_key_type(&self) -> Option<KeyType> {
        self.object_details.as_ref()?.key_type
    }
    pub(super) fn clear_crypto_form(&mut self) {
        self.cipher_form = None;
        self.key_form = None;
        self.crypto_form = None;
        if self.notification == Some(Notification::SignatureVerified) {
            self.notification = None;
        }
    }
    fn invalidate_verification(&mut self) {
        if self.operation_kind == Some(OperationKind::Verify) {
            self.cancel();
        }
        self.notification = None;
    }
    pub fn can_open_crypto(&self, mode: CryptoMode) -> bool {
        self.can_submit()
            && self.token_page == TokenPage::Objects
            && self.object().is_some_and(|object| {
                !object.ambiguous
                    && object.uri.is_some()
                    && match mode {
                        CryptoMode::Sign => {
                            object.class == Some(ObjectClass::PRIVATE_KEY)
                                && matches!(
                                    self.object_key_type(),
                                    Some(KeyType::RSA | KeyType::EC | KeyType::ML_DSA)
                                )
                                && self
                                    .token()
                                    .is_some_and(|token| token.login == LoginState::User)
                        }
                        CryptoMode::Verify => object.class == Some(ObjectClass::CERTIFICATE),
                        _ => false,
                    }
            })
    }
    pub fn open_crypto(&mut self, mode: CryptoMode) -> Option<BackendCommand> {
        if !self.can_open_crypto(mode) {
            return None;
        }
        let scope = CryptoScope {
            module: self.module()?.id,
            token: self.token()?.id,
            object: self.object()?.id,
            mode,
        };
        let protected_path = self.token()?.protected_path;
        let id = self.begin(OperationKind::CryptoOptions)?;
        self.cipher_form = None;
        self.key_form = None;
        self.crypto_form = Some(CryptoForm {
            id,
            scope,
            options: Vec::new(),
            choice: None,
            loaded: false,
            software_hashing: false,
            domain_context: String::new(),
            context_required: false,
            protected_path,
            pin: SecretString::default(),
            input: String::new(),
            signature: String::new(),
            picked_input: None,
            picked_signature: None,
            picker: None,
        });
        Some(BackendCommand::CryptoOptions {
            id,
            scope,
            software_hashing: false,
        })
    }
    pub fn crypto_policy(
        &mut self,
        form_id: RequestId,
        software_hashing: bool,
    ) -> Option<BackendCommand> {
        let form = self.crypto_form.as_ref()?;
        if form.id != form_id
            || form.scope.mode != CryptoMode::Sign
            || !self.can_submit()
            || self.object_key_type() == Some(KeyType::ML_DSA)
            || form
                .choice
                .is_some_and(|choice| matches!(choice.0.parameters, SignatureProfile::MlDsa(_)))
        {
            return None;
        }
        let scope = form.scope;
        let id = self.begin(OperationKind::CryptoOptions)?;
        let form = self.crypto_form.as_mut()?;
        form.id = id;
        form.software_hashing = software_hashing;
        form.options.clear();
        form.choice = None;
        form.loaded = false;
        form.pin = SecretString::default();
        form.context_required = false;
        Some(BackendCommand::CryptoOptions {
            id,
            scope,
            software_hashing,
        })
    }
    pub fn crypto_choice(&mut self, id: RequestId, choice: SignatureChoice) {
        if !self.can_submit() {
            return;
        }
        if !self
            .crypto_form
            .as_ref()
            .is_some_and(|form| form.id == id && form.options.contains(&choice))
        {
            return;
        }
        self.invalidate_verification();
        if let Some(form) = &mut self.crypto_form
            && form.id == id
            && form.options.contains(&choice)
        {
            form.choice = Some(choice);
            form.pin = SecretString::default();
        }
    }
    pub fn crypto_pin(&mut self, id: RequestId, pin: SecretString) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.crypto_form
            && form.id == id
            && form.loaded
            && form.context_required
            && !form.protected_path
        {
            form.pin = pin;
        }
    }
    pub fn crypto_protected(&mut self, id: RequestId, enabled: bool) {
        if !self.can_submit()
            || (enabled && !self.token().is_some_and(|token| token.protected_path))
        {
            return;
        }
        if let Some(form) = &mut self.crypto_form
            && form.id == id
        {
            form.pin = SecretString::default();
            form.protected_path = enabled;
        }
    }
    pub fn crypto_edit(&mut self, id: RequestId, field: CryptoField, value: String) {
        if !self.can_submit() {
            return;
        }
        if !self.crypto_form.as_ref().is_some_and(|form| form.id == id) {
            return;
        }
        if field == CryptoField::DomainContext
            && !self.crypto_form.as_ref().is_some_and(|form| {
                form.choice
                    .is_some_and(|choice| matches!(choice.0.parameters, SignatureProfile::MlDsa(_)))
            })
        {
            return;
        }
        self.invalidate_verification();
        if let Some(form) = &mut self.crypto_form
            && form.id == id
        {
            form.picker = None;
            match field {
                CryptoField::Input => {
                    form.input = value;
                    form.picked_input = None;
                }
                CryptoField::Signature => {
                    form.signature = value;
                    form.picked_signature = None;
                }
                CryptoField::DomainContext => form.domain_context = value,
            }
        }
    }
    pub fn crypto_picker(
        &mut self,
        form_id: RequestId,
        field: CryptoField,
    ) -> Option<(RequestId, bool)> {
        let form = self.crypto_form.as_ref()?;
        if !self.can_submit()
            || form.id != form_id
            || form.picker.is_some()
            || field == CryptoField::DomainContext
        {
            return None;
        }
        let save = field == CryptoField::Signature && form.scope.mode == CryptoMode::Sign;
        self.invalidate_verification();
        let id = self.request_id()?;
        self.crypto_form.as_mut()?.picker = Some((id, field));
        Some((id, save))
    }
    pub fn crypto_picked(&mut self, id: RequestId, path: Option<PathBuf>) {
        if self.shutdown_request.is_some() {
            return;
        }
        if let Some(form) = &mut self.crypto_form
            && let Some((request, field)) = form.picker
            && request == id
        {
            form.picker = None;
            if let Some(path) = path {
                match field {
                    CryptoField::Input => {
                        form.input = path.to_string_lossy().into_owned();
                        form.picked_input = Some(path);
                    }
                    CryptoField::Signature => {
                        form.signature = path.to_string_lossy().into_owned();
                        form.picked_signature = Some(path);
                    }
                    CryptoField::DomainContext => {}
                }
            }
        }
    }
    pub fn dismiss_crypto(&mut self, id: RequestId) {
        if self.crypto_form.as_ref().is_some_and(|form| form.id == id) {
            self.cancel();
            self.clear_crypto_form();
        }
    }
    pub fn submit_crypto(&mut self, form_id: RequestId) -> Option<BackendCommand> {
        let form = self.crypto_form.as_ref()?;
        if form.id != form_id
            || !self.can_open_crypto(form.scope.mode)
            || self.selected_module != Some(form.scope.module)
            || self.selected_token != Some(form.scope.token)
            || self.selected_object != Some(form.scope.object)
        {
            return None;
        }
        if form.input.is_empty()
            || form.signature.is_empty()
            || !form
                .choice
                .is_some_and(|choice| form.options.contains(&choice))
            || !form.loaded
            || (form.software_hashing
                && form.choice.is_some_and(|choice| {
                    matches!(choice.0.parameters, SignatureProfile::MlDsa(_))
                }))
        {
            self.notification = Some(Notification::Error(BackendError::SignatureChoice));
            self.crypto_form.as_mut()?.pin = SecretString::default();
            return None;
        }
        let form = self.crypto_form.take()?;
        if matches!(form.choice?.0.parameters, SignatureProfile::MlDsa(_))
            && form.domain_context.len() > 255
        {
            self.notification = Some(Notification::Error(BackendError::MlDsaContext));
            self.crypto_form = Some(CryptoForm {
                pin: SecretString::default(),
                ..form
            });
            return None;
        }
        let context = form.context_required.then_some(if form.protected_path {
            SecretInput::ProtectedPath
        } else {
            SecretInput::Value(form.pin)
        });
        let job = CryptoJob {
            parameters: form.choice?.0.parameters,
            software_hashing: form.software_hashing,
            domain_context: form.domain_context.as_bytes().to_vec(),
            input: form
                .picked_input
                .clone()
                .unwrap_or_else(|| PathBuf::from(&form.input)),
            signature: form
                .picked_signature
                .clone()
                .unwrap_or_else(|| PathBuf::from(&form.signature)),
            context,
        };
        let id = self.begin(if form.scope.mode == CryptoMode::Sign {
            OperationKind::Sign
        } else {
            OperationKind::Verify
        })?;
        if form.scope.mode == CryptoMode::Verify {
            // Keep the scope available for stale-response checks, but no submitted credential.
            self.crypto_form = Some(CryptoForm {
                pin: SecretString::default(),
                ..form
            });
        } else {
            self.reset_browser();
        }
        Some(BackendCommand::Crypto {
            id,
            scope: form.scope,
            job,
        })
    }
}
