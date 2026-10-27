// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{HkdfOutputChoice, UiState};
use crate::backend::{BackendError, CryptoMode, KbkdfJob, KeyProfile, RequestId};
use pkcs11_client::{DigestAlgorithm, KbkdfMode, KbkdfOptions, KbkdfOutput, KbkdfRequest};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KbkdfDigest(pub DigestAlgorithm);
impl KbkdfDigest {
    pub const ALL: [Self; 3] = [
        Self(DigestAlgorithm::Sha256),
        Self(DigestAlgorithm::Sha384),
        Self(DigestAlgorithm::Sha512),
    ];
}
impl std::fmt::Display for KbkdfDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            DigestAlgorithm::Sha256 => "HMAC-SHA-256",
            DigestAlgorithm::Sha384 => "HMAC-SHA-384",
            DigestAlgorithm::Sha512 => "HMAC-SHA-512",
        })
    }
}
pub struct KbkdfForm {
    pub mode: KbkdfMode,
    pub iv: String,
    pub digest: KbkdfDigest,
    pub output: HkdfOutputChoice,
    pub length: String,
    pub kdf_label: String,
    pub context: String,
}
impl Default for KbkdfForm {
    fn default() -> Self {
        Self {
            mode: KbkdfMode::Counter,
            iv: String::new(),
            digest: KbkdfDigest(DigestAlgorithm::Sha256),
            output: HkdfOutputChoice::Aes256,
            length: "32".into(),
            kdf_label: String::new(),
            context: String::new(),
        }
    }
}
impl KbkdfForm {
    pub(super) fn job(
        &self,
        options: KbkdfOptions,
        id: Option<&[u8]>,
        label: &str,
    ) -> Result<KbkdfJob, BackendError> {
        let caps = options.get(self.mode).ok_or(BackendError::KbkdfInput)?;
        if self.iv.trim().len() > 128 {
            return Err(BackendError::KbkdfInput);
        }
        let iv = if self.mode == KbkdfMode::Feedback {
            if self.iv.trim().is_empty() {
                Vec::new()
            } else {
                super::management::identifier(&self.iv).ok_or(BackendError::KbkdfInput)?
            }
        } else {
            if !self.iv.is_empty() {
                return Err(BackendError::KbkdfInput);
            }
            Vec::new()
        };
        if !caps.supports(self.digest.0) {
            return Err(BackendError::KbkdfInput);
        }
        let output = match self.output {
            HkdfOutputChoice::Aes128 => KbkdfOutput::Aes128,
            HkdfOutputChoice::Aes192 => KbkdfOutput::Aes192,
            HkdfOutputChoice::Aes256 => KbkdfOutput::Aes256,
            HkdfOutputChoice::DerivationSecret => KbkdfOutput::DerivationSecret {
                length: self
                    .length
                    .trim()
                    .parse()
                    .map_err(|_| BackendError::KbkdfInput)?,
            },
        };
        let id = id.ok_or(BackendError::KbkdfInput)?;
        let request = KbkdfRequest {
            digest: self.digest.0,
            output,
            kdf_label: self.kdf_label.as_bytes(),
            context: self.context.as_bytes(),
            id,
            label: label.as_bytes(),
        };
        request
            .validate_with_mode(self.mode, &iv)
            .map_err(|_| BackendError::KbkdfInput)?;
        Ok(KbkdfJob {
            mode: self.mode,
            iv,
            digest: request.digest,
            output,
            kdf_label: request.kdf_label.to_vec(),
            context: request.context.to_vec(),
            id: id.to_vec(),
            label: label.as_bytes().to_vec(),
        })
    }
}
impl UiState {
    pub fn kbkdf_mode(&mut self, id: RequestId, mode: KbkdfMode) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Kbkdf
            && let Some(KeyProfile::Kbkdf(options)) = form.profile
            && let Some(caps) = options.get(mode)
        {
            if form.kbkdf.mode != mode {
                form.kbkdf.iv.clear();
            }
            form.kbkdf.mode = mode;
            if !caps.supports(form.kbkdf.digest.0)
                && let Some(digest) = KbkdfDigest::ALL.into_iter().find(|d| caps.supports(d.0))
            {
                form.kbkdf.digest = digest;
            }
        }
    }
    pub fn kbkdf_digest(&mut self, id: RequestId, digest: KbkdfDigest) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Kbkdf
            && let Some(KeyProfile::Kbkdf(caps)) = form.profile
            && caps
                .get(form.kbkdf.mode)
                .is_some_and(|caps| caps.supports(digest.0))
        {
            form.kbkdf.digest = digest;
        }
    }
    pub fn kbkdf_output(&mut self, id: RequestId, output: HkdfOutputChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Kbkdf
        {
            form.kbkdf.output = output;
        }
    }
}
