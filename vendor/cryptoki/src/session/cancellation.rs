// SPDX-License-Identifier: Apache-2.0
//! Explicit cancellation of session operations through PKCS #11 3.0 and later.
use crate::{
    context::Function,
    error::{Result, Rv},
    session::Session,
};
use bitflags::bitflags;
use cryptoki_sys::*;

bitflags! {
    /// Session operation classes supported by the consumer's cancellation API.
    /// Flags combine with bitwise OR; empty flags leave native state unchanged.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CancelFlags: CK_FLAGS {
        /// Object search operation.
        const FIND_OBJECTS = CKF_FIND_OBJECTS;
        /// Encryption operation.
        const ENCRYPT = CKF_ENCRYPT;
        /// Decryption operation.
        const DECRYPT = CKF_DECRYPT;
        /// Message digest operation.
        const DIGEST = CKF_DIGEST;
        /// Signing or MAC generation operation.
        const SIGN = CKF_SIGN;
        /// Signature or MAC verification operation.
        const VERIFY = CKF_VERIFY;
    }
}

impl Session {
    /// Cancel the selected operation classes once. Only CKR_OK confirms their
    /// termination; other operations and token authentication remain unchanged.
    /// No legacy cancellation function, retry or fallback is used.
    pub fn cancel_operations(&self, flags: CancelFlags) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SessionCancel)(
                self.handle(),
                flags.bits(),
            ))
            .into_result(Function::SessionCancel)
        }
    }
}
