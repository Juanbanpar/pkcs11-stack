// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{HkdfOutputChoice, UiState};
use crate::backend::{BackendError, CryptoMode, EcdhParameters, RequestId};
use pkcs11_client::{AesKeySize, DigestAlgorithm, EcdhKdf, EcdhOutput};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EcdhChoice {
    #[default]
    Raw,
    X963Sha256,
    X963Sha384,
    X963Sha512,
    Sp800Sha256,
    Sp800Sha384,
    Sp800Sha512,
}
impl EcdhChoice {
    pub const ALL: [Self; 7] = [
        Self::Raw,
        Self::X963Sha256,
        Self::X963Sha384,
        Self::X963Sha512,
        Self::Sp800Sha256,
        Self::Sp800Sha384,
        Self::Sp800Sha512,
    ];
    fn kdf(self) -> EcdhKdf {
        match self {
            Self::Raw => EcdhKdf::Null,
            Self::X963Sha256 => EcdhKdf::X963(DigestAlgorithm::Sha256),
            Self::X963Sha384 => EcdhKdf::X963(DigestAlgorithm::Sha384),
            Self::X963Sha512 => EcdhKdf::X963(DigestAlgorithm::Sha512),
            Self::Sp800Sha256 => EcdhKdf::Sp80056a(DigestAlgorithm::Sha256),
            Self::Sp800Sha384 => EcdhKdf::Sp80056a(DigestAlgorithm::Sha384),
            Self::Sp800Sha512 => EcdhKdf::Sp80056a(DigestAlgorithm::Sha512),
        }
    }
}
impl std::fmt::Display for EcdhChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Raw => "Raw secret (null KDF)",
            Self::X963Sha256 => "ANSI X9.63 / SHA-256",
            Self::X963Sha384 => "ANSI X9.63 / SHA-384",
            Self::X963Sha512 => "ANSI X9.63 / SHA-512",
            Self::Sp800Sha256 => "NIST SP 800-56A / SHA-256",
            Self::Sp800Sha384 => "NIST SP 800-56A / SHA-384",
            Self::Sp800Sha512 => "NIST SP 800-56A / SHA-512",
        })
    }
}
pub struct EcdhForm {
    pub kdf: EcdhChoice,
    pub output: HkdfOutputChoice,
    pub length: String,
    pub info: String,
}
impl Default for EcdhForm {
    fn default() -> Self {
        Self {
            kdf: EcdhChoice::Raw,
            output: HkdfOutputChoice::Aes256,
            length: "64".into(),
            info: String::new(),
        }
    }
}
impl EcdhForm {
    pub fn parameters(&self) -> Result<EcdhParameters, BackendError> {
        if self.info.len() > 4096 {
            return Err(BackendError::KeyOperationInput);
        }
        let output = if self.kdf == EcdhChoice::Raw {
            if !self.info.is_empty() {
                return Err(BackendError::KeyOperationInput);
            }
            EcdhOutput::RawSecret
        } else {
            match self.output {
                HkdfOutputChoice::Aes128 => EcdhOutput::Aes(AesKeySize::Bits128),
                HkdfOutputChoice::Aes192 => EcdhOutput::Aes(AesKeySize::Bits192),
                HkdfOutputChoice::Aes256 => EcdhOutput::Aes(AesKeySize::Bits256),
                HkdfOutputChoice::DerivationSecret => {
                    let length = self
                        .length
                        .trim()
                        .parse()
                        .map_err(|_| BackendError::KeyOperationInput)?;
                    if !(1..=4096).contains(&length) {
                        return Err(BackendError::KeyOperationInput);
                    }
                    EcdhOutput::DerivationSecret { length }
                }
            }
        };
        Ok(EcdhParameters {
            kdf: self.kdf.kdf(),
            output,
            shared_info: self.info.as_bytes().to_vec(),
        })
    }
}
impl UiState {
    pub fn ecdh_kdf(&mut self, id: RequestId, kdf: EcdhChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Derive
        {
            form.ecdh.kdf = kdf;
            if kdf == EcdhChoice::Raw {
                form.ecdh.info.clear();
            }
        }
    }
    pub fn ecdh_output(&mut self, id: RequestId, output: HkdfOutputChoice) {
        if !self.can_submit() {
            return;
        }
        if let Some(form) = &mut self.key_form
            && form.id == id
            && form.scope.mode == CryptoMode::Derive
        {
            form.ecdh.output = output;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_and_hashed_outputs_have_distinct_permissions_and_bounds() {
        let mut form = EcdhForm::default();
        assert_eq!(form.parameters().unwrap().output, EcdhOutput::RawSecret);
        form.info = "context".into();
        assert!(form.parameters().is_err());
        form.kdf = EcdhChoice::X963Sha512;
        assert_eq!(
            form.parameters().unwrap().output,
            EcdhOutput::Aes(AesKeySize::Bits256)
        );
        form.output = HkdfOutputChoice::DerivationSecret;
        assert_eq!(
            form.parameters().unwrap().output,
            EcdhOutput::DerivationSecret { length: 64 }
        );
        for length in ["0", "4097", "invalid"] {
            form.length = length.into();
            assert!(form.parameters().is_err());
        }
    }
}
