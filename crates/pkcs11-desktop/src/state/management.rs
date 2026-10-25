// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::backend::{GenerationKind, ManagementAction};
use pkcs11_client::{
    AesKeyPurpose, KeyKind, MlDsaParameterSet, MlKemParameterSet, NamedCurve, ObjectClass,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyChoice(pub GenerationKind);
impl std::fmt::Display for KeyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            GenerationKind::Signing(KeyKind::Rsa { bits }) => write!(f, "RSA {bits} — signing"),
            GenerationKind::MlDsa(parameter) => write!(
                f,
                "ML-DSA-{} — signing",
                match parameter {
                    MlDsaParameterSet::MlDsa44 => 44,
                    MlDsaParameterSet::MlDsa65 => 65,
                    MlDsaParameterSet::MlDsa87 => 87,
                }
            ),
            GenerationKind::MlKem(parameter) => write!(
                f,
                "ML-KEM-{} — encapsulation/decapsulation",
                match parameter {
                    MlKemParameterSet::MlKem512 => 512,
                    MlKemParameterSet::MlKem768 => 768,
                    MlKemParameterSet::MlKem1024 => 1024,
                }
            ),
            GenerationKind::Signing(KeyKind::Ec(curve)) | GenerationKind::Ecdh(curve) => {
                let purpose = if matches!(self.0, GenerationKind::Ecdh(_)) {
                    "ECDH"
                } else {
                    "signing"
                };
                let curve = match curve {
                    NamedCurve::P256 => "P-256",
                    NamedCurve::P384 => "P-384",
                    NamedCurve::P521 => "P-521",
                };
                write!(f, "EC {curve} — {purpose}")
            }
            GenerationKind::Aes(size, purpose) => write!(
                f,
                "AES {} — {}",
                size.length() * 8,
                match purpose {
                    AesKeyPurpose::Encryption => "encryption/decryption",
                    AesKeyPurpose::Wrapping => "wrapping/unwrapping",
                }
            ),
        }
    }
}
#[derive(Clone, Copy)]
pub enum FilePurpose {
    Certificate,
    Export {
        module: ResourceId,
        token: ResourceId,
        object: ResourceId,
    },
}
pub struct FileRequest {
    pub id: RequestId,
    pub purpose: FilePurpose,
}
pub struct DeleteConfirmation {
    pub id: RequestId,
    pub module: ResourceId,
    pub token: ResourceId,
    pub object: ResourceId,
}
#[derive(Default)]
pub struct ManagementUi {
    pub keys: Vec<KeyChoice>,
    pub key: Option<KeyChoice>,
    pub capabilities_loaded: bool,
    pub key_label: String,
    pub key_id: String,
    pub always_authenticate: bool,
    pub certificate_label: String,
    pub certificate_id: String,
    pub certificate_path: String,
    pub picked_certificate: Option<PathBuf>,
    pub file_request: Option<FileRequest>,
    pub confirmation: Option<DeleteConfirmation>,
}
pub(super) fn identifier(value: &str) -> Option<Vec<u8>> {
    let value = value.trim().as_bytes();
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}
impl UiState {
    pub fn can_manage(&self) -> bool {
        self.can_submit() && self.token().is_some_and(TokenEntry::can_manage)
    }
    pub fn read_capabilities(&mut self) -> Option<BackendCommand> {
        if self.token_page != TokenPage::Operations {
            return None;
        }
        let module = self.module()?.id;
        let token = self.token()?.id;
        let id = self.begin(OperationKind::Capabilities)?;
        self.management.keys.clear();
        self.management.key = None;
        self.management.capabilities_loaded = false;
        Some(BackendCommand::Capabilities { id, module, token })
    }
    fn begin_management(
        &mut self,
        module: ResourceId,
        token: ResourceId,
        action: ManagementAction,
    ) -> Option<BackendCommand> {
        let id = self.begin(OperationKind::Manage)?;
        self.reset_browser();
        Some(BackendCommand::Manage {
            id,
            module,
            token,
            action,
        })
    }
    pub fn generate(&mut self) -> Option<BackendCommand> {
        if !self.can_manage() || self.token_page != TokenPage::Operations {
            return None;
        }
        let key = self.management.key?;
        let id = identifier(&self.management.key_id);
        if !self.management.keys.contains(&key)
            || self.management.key_label.is_empty()
            || id.is_none()
        {
            self.notification = Some(Notification::Error(BackendError::InvalidForm));
            return None;
        }
        let id = id.unwrap();
        if key
            .0
            .validate(
                &id,
                self.management.key_label.as_bytes(),
                self.management.always_authenticate,
            )
            .is_err()
        {
            self.notification = Some(Notification::Error(BackendError::InvalidForm));
            return None;
        }
        let action = ManagementAction::Generate {
            kind: key.0,
            id,
            label: self.management.key_label.as_bytes().to_vec(),
            always_authenticate: self.management.always_authenticate,
        };
        self.begin_management(self.module()?.id, self.token()?.id, action)
    }
    pub fn import_certificate(&mut self) -> Option<BackendCommand> {
        if !self.can_manage() || self.token_page != TokenPage::Operations {
            return None;
        }
        let id = identifier(&self.management.certificate_id);
        if id.is_none()
            || self.management.certificate_label.is_empty()
            || self.management.certificate_path.is_empty()
        {
            self.notification = Some(Notification::Error(BackendError::InvalidForm));
            return None;
        }
        let path = self
            .management
            .picked_certificate
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.management.certificate_path));
        let action = ManagementAction::ImportCertificate {
            path,
            id: id.unwrap(),
            label: self.management.certificate_label.as_bytes().to_vec(),
        };
        self.begin_management(self.module()?.id, self.token()?.id, action)
    }
    pub fn request_delete(&mut self) {
        if !self.can_manage()
            || !self
                .object()
                .is_some_and(|entry| !entry.ambiguous && entry.uri.is_some())
        {
            return;
        }
        let module = self.module().unwrap().id;
        let token = self.token().unwrap().id;
        let object = self.object().unwrap().id;
        self.cancel();
        self.login_form = None;
        self.management.file_request = None;
        if let Some(id) = self.request_id() {
            self.management.confirmation = Some(DeleteConfirmation {
                id,
                module,
                token,
                object,
            });
            self.dialog = Some(Dialog::Delete(id));
        }
    }
    pub fn confirm_delete(&mut self, confirmation_id: RequestId) -> Option<BackendCommand> {
        if !self.can_manage()
            || !self
                .management
                .confirmation
                .as_ref()
                .is_some_and(|entry| entry.id == confirmation_id)
        {
            return None;
        }
        let entry = self.management.confirmation.take()?;
        self.dialog = None;
        if self.selected_module != Some(entry.module)
            || self.selected_token != Some(entry.token)
            || self.selected_object != Some(entry.object)
        {
            return None;
        }
        self.begin_management(
            entry.module,
            entry.token,
            ManagementAction::Delete {
                object: entry.object,
            },
        )
    }
    pub fn can_export(&self) -> bool {
        self.can_submit()
            && self.object().is_some_and(|object| {
                !object.ambiguous
                    && object.uri.is_some()
                    && matches!(
                        object.class,
                        Some(
                            ObjectClass::DATA | ObjectClass::CERTIFICATE | ObjectClass::PUBLIC_KEY
                        )
                    )
            })
            && self.object_details.as_ref().is_some_and(|fields| {
                fields
                    .iter()
                    .any(|field| field.name == "Private" && field.value.as_deref() == Some("false"))
            })
    }
    pub fn begin_object_file(&mut self, export: bool) -> Option<(RequestId, FilePurpose)> {
        if self.management.file_request.is_some() || !self.can_submit() {
            return None;
        }
        let purpose = if export {
            if !self.can_export() {
                return None;
            }
            FilePurpose::Export {
                module: self.module()?.id,
                token: self.token()?.id,
                object: self.object()?.id,
            }
        } else {
            if self.token_page != TokenPage::Operations || !self.can_manage() {
                return None;
            }
            FilePurpose::Certificate
        };
        let id = self.request_id()?;
        self.management.file_request = Some(FileRequest { id, purpose });
        Some((id, purpose))
    }
    pub fn object_file_picked(
        &mut self,
        id: RequestId,
        path: Option<PathBuf>,
    ) -> Option<BackendCommand> {
        if self.shutdown_request.is_some()
            || !self
                .management
                .file_request
                .as_ref()
                .is_some_and(|entry| entry.id == id)
        {
            return None;
        }
        let request = self.management.file_request.take()?;
        let path = path?;
        match request.purpose {
            FilePurpose::Certificate if self.token_page == TokenPage::Operations => {
                self.management.certificate_path = path.to_string_lossy().into_owned();
                self.management.picked_certificate = Some(path);
                None
            }
            FilePurpose::Export {
                module,
                token,
                object,
            } if self.selected_module == Some(module)
                && self.selected_token == Some(token)
                && self.selected_object == Some(object)
                && self.can_export() =>
            {
                self.begin_management(module, token, ManagementAction::Export { object, path })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ManagementField {
    KeyLabel,
    KeyId,
    CertificateLabel,
    CertificateId,
    CertificatePath,
}
impl UiState {
    pub fn edit_management(&mut self, field: ManagementField, value: String) {
        if !self.can_submit() {
            return;
        }
        match field {
            ManagementField::KeyLabel => self.management.key_label = value,
            ManagementField::KeyId => self.management.key_id = value,
            ManagementField::CertificateLabel => self.management.certificate_label = value,
            ManagementField::CertificateId => self.management.certificate_id = value,
            ManagementField::CertificatePath => {
                self.management.certificate_path = value;
                self.management.picked_certificate = None;
                self.management.file_request = None;
            }
        }
    }
}
