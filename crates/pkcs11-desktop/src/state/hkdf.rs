// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{UiState, management::identifier};
use crate::backend::{BackendError, CryptoMode, HkdfJob, RequestId};
use pkcs11_client::{HkdfCapabilities, HkdfOutput, HkdfRequest};

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
    pub output: HkdfOutputChoice,
    pub length: String,
    pub salt: String,
    pub info: String,
}
impl Default for HkdfForm {
    fn default() -> Self {
        Self {
            output: HkdfOutputChoice::default(),
            length: "32".into(),
            salt: String::new(),
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
        request.validate().map_err(|_| BackendError::HkdfInput)?;
        Ok(HkdfJob {
            output,
            salt,
            info: self.info.as_bytes().to_vec(),
            id: id.to_vec(),
            label: label.as_bytes().to_vec(),
        })
    }
}
impl UiState {
    pub fn hkdf_output(&mut self, id: RequestId, output: HkdfOutputChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Hkdf
        {
            form.hkdf.output = output;
        }
    }
}
