// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{UiState, management::identifier};
use crate::backend::{BackendError, CryptoMode, HkdfJob, RequestId};
use pkcs11_client::{HkdfCapabilities, HkdfMode, HkdfOutput, HkdfRequest};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HkdfOutputChoice {
    Aes128,
    Aes192,
    #[default]
    Aes256,
    DerivationSecret,
}
impl HkdfOutputChoice {
    pub const ALL: [Self; 4] = [
        Self::Aes128,
        Self::Aes192,
        Self::Aes256,
        Self::DerivationSecret,
    ];
}
impl std::fmt::Display for HkdfOutputChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128 => "AES-128 — encryption/decryption",
            Self::Aes192 => "AES-192 — encryption/decryption",
            Self::Aes256 => "AES-256 — encryption/decryption",
            Self::DerivationSecret => "Generic secret — further derivation",
        })
    }
}
pub struct HkdfForm {
    pub mode: HkdfMode,
    pub output: HkdfOutputChoice,
    pub length: String,
    pub salt: String,
    pub salt_key: String,
    pub info: String,
}
impl Default for HkdfForm {
    fn default() -> Self {
        Self {
            mode: HkdfMode::ExtractAndExpand,
            output: HkdfOutputChoice::default(),
            length: "32".into(),
            salt: String::new(),
            salt_key: String::new(),
            info: String::new(),
        }
    }
}
impl HkdfForm {
    pub(super) fn job(
        &self,
        profile: HkdfCapabilities,
        id: Option<&[u8]>,
        label: &str,
    ) -> Result<HkdfJob, BackendError> {
        if self.salt.trim().len() > 8192 || self.info.len() > 4096 {
            return Err(BackendError::HkdfInput);
        }
        let salt = if self.salt.trim().is_empty() {
            Vec::new()
        } else {
            identifier(&self.salt).ok_or(BackendError::HkdfInput)?
        };
        let output = match self.output {
            HkdfOutputChoice::Aes128 => HkdfOutput::Aes128,
            HkdfOutputChoice::Aes192 => HkdfOutput::Aes192,
            HkdfOutputChoice::Aes256 => HkdfOutput::Aes256,
            HkdfOutputChoice::DerivationSecret => HkdfOutput::DerivationSecret {
                length: self
                    .length
                    .trim()
                    .parse()
                    .map_err(|_| BackendError::HkdfInput)?,
            },
        };
        let id = id.ok_or(BackendError::HkdfInput)?;
        let request = HkdfRequest {
            digest: profile.digest,
            output,
            salt: &salt,
            info: self.info.as_bytes(),
            id,
            label: label.as_bytes(),
        };
        let salt_key = if self.salt_key.trim().is_empty() {
            None
        } else {
            let uri: pkcs11_client::Pkcs11Uri = self
                .salt_key
                .trim()
                .parse()
                .map_err(|_| BackendError::HkdfInput)?;
            if uri.path_attribute("type") != Some(b"secret-key") {
                return Err(BackendError::HkdfInput);
            }
            Some(pkcs11_client::object_reference(uri).map_err(|_| BackendError::HkdfInput)?)
        };
        if salt_key.is_some() {
            request.validate_with_salt_key(self.mode)
        } else {
            request.validate_for_mode(self.mode)
        }
        .map_err(|_| BackendError::HkdfInput)?;
        Ok(HkdfJob {
            mode: self.mode,
            output,
            salt,
            salt_key,
            info: self.info.as_bytes().to_vec(),
            id: id.to_vec(),
            label: label.as_bytes().to_vec(),
        })
    }
}
impl UiState {
    pub fn hkdf_mode(&mut self, id: RequestId, mode: HkdfMode) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Hkdf
            && let Some(crate::backend::KeyProfile::Hkdf(profile)) = form.profile
        {
            form.hkdf.mode = mode;
            if mode == HkdfMode::ExtractOnly {
                form.hkdf.output = HkdfOutputChoice::DerivationSecret;
                form.hkdf.length = profile.digest.output_len().to_string();
                form.hkdf.info.clear();
            }
            if mode == HkdfMode::ExpandOnly {
                form.hkdf.salt.clear();
                form.hkdf.salt_key.clear();
            }
        }
    }
    pub fn hkdf_output(&mut self, id: RequestId, output: HkdfOutputChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Hkdf
            && (form.hkdf.mode != HkdfMode::ExtractOnly
                || output == HkdfOutputChoice::DerivationSecret)
        {
            form.hkdf.output = output;
        }
    }
}
