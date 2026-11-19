// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Error, Module};
use cryptoki::context::Function;

/// A PKCS#11 function whose presence can be checked without invoking it.
#[derive(Clone, Copy, Debug)]
pub struct FunctionAvailability {
    /// Upstream function identifier.
    pub function: Function,
    /// Whether the loaded function list provides a non-null entry.
    pub supported: bool,
}

/// Functions relevant to the interfaces this project uses.
pub const INTERFACE_FUNCTIONS: &[Function] = &[
    Function::Initialize,
    Function::Finalize,
    Function::GetInfo,
    Function::GetSlotList,
    Function::GetTokenInfo,
    Function::GetMechanismList,
    Function::GetMechanismInfo,
    Function::OpenSession,
    Function::CloseSession,
    Function::GetSessionInfo,
    Function::Login,
    Function::Logout,
    Function::CreateObject,
    Function::DestroyObject,
    Function::GetAttributeValue,
    Function::SetAttributeValue,
    Function::FindObjectsInit,
    Function::FindObjects,
    Function::FindObjectsFinal,
    Function::EncryptInit,
    Function::Encrypt,
    Function::EncryptUpdate,
    Function::EncryptFinal,
    Function::DecryptInit,
    Function::Decrypt,
    Function::DecryptUpdate,
    Function::DecryptFinal,
    Function::DigestInit,
    Function::Digest,
    Function::DigestUpdate,
    Function::DigestFinal,
    Function::SignInit,
    Function::Sign,
    Function::SignUpdate,
    Function::SignFinal,
    Function::VerifyInit,
    Function::Verify,
    Function::VerifyUpdate,
    Function::VerifyFinal,
    Function::GenerateKey,
    Function::GenerateKeyPair,
    Function::WrapKey,
    Function::UnwrapKey,
    Function::DeriveKey,
    Function::GenerateRandom,
    Function::GetInterfaceList,
    Function::GetInterface,
    Function::LoginUser,
    Function::SessionCancel,
    Function::MessageEncryptInit,
    Function::EncryptMessage,
    Function::EncryptMessageBegin,
    Function::EncryptMessageNext,
    Function::MessageEncryptFinal,
    Function::MessageDecryptInit,
    Function::DecryptMessage,
    Function::DecryptMessageBegin,
    Function::DecryptMessageNext,
    Function::MessageDecryptFinal,
    Function::MessageSignInit,
    Function::SignMessage,
    Function::MessageSignFinal,
    Function::MessageVerifyInit,
    Function::VerifyMessage,
    Function::MessageVerifyFinal,
];

impl Module {
    /// Report which of the standard functions this module exposes.
    ///
    /// The upstream library selects a 3.2, 3.0 or legacy 2.40 function list.
    /// Availability is derived from the selected list; it is not assumed from
    /// the library's reported Cryptoki version.
    pub fn function_availability(&self) -> Result<Vec<FunctionAvailability>, Error> {
        let raw = self.raw()?;
        Ok(INTERFACE_FUNCTIONS
            .iter()
            .copied()
            .map(|function| FunctionAvailability {
                function,
                supported: raw.is_fn_supported(function),
            })
            .collect())
    }

    /// Check one standard function through the selected function list.
    pub fn supports_function(&self, function: Function) -> Result<bool, Error> {
        Ok(self.raw()?.is_fn_supported(function))
    }
}
