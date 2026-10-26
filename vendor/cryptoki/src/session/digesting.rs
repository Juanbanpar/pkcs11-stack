// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Digesting functions

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session {
    /// Single-part digesting operation
    pub fn digest(&self, m: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = m.into();
        let mut digest_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
            ))
            .into_result(Function::DigestInit)?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Digest)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut digest_len,
            ))
            .into_result(Function::Digest)?;
        }

        let mut digest = vec![0; digest_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Digest)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                digest.as_mut_ptr(),
                &mut digest_len,
            ))
            .into_result(Function::Digest)?;
        }

        digest.truncate(digest_len.try_into()?);

        Ok(digest)
    }

    /// Complete an initialized single-part digest into an exactly sized buffer.
    /// No provider-controlled allocation or automatic retry occurs. A mismatched
    /// returned length is rejected; the caller must discard uncertain operations.
    pub fn digest_initialized_fixed(&self, data: &[u8], expected_length: usize) -> Result<Vec<u8>> {
        let mut output = vec![0; expected_length];
        let mut length = expected_length.try_into()?;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Digest)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                output.as_mut_ptr(),
                &mut length,
            ))
            .into_result(Function::Digest)?;
        }
        if usize::try_from(length)? != expected_length {
            return Err(crate::error::Error::InvalidValue);
        }
        Ok(output)
    }

    /// Finalize a multipart digest into an exactly sized buffer, without a length
    /// query, provider-controlled allocation or retry. Reject mismatched lengths.
    pub fn digest_final_fixed(&self, expected_length: usize) -> Result<Vec<u8>> {
        let mut output = vec![0; expected_length];
        let mut length = expected_length.try_into()?;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestFinal)(
                self.handle(),
                output.as_mut_ptr(),
                &mut length,
            ))
            .into_result(Function::DigestFinal)?;
        }
        if usize::try_from(length)? != expected_length {
            return Err(crate::error::Error::InvalidValue);
        }
        Ok(output)
    }

    /// Starts new multi-part digesting operation
    pub fn digest_init(&self, m: &Mechanism) -> Result<()> {
        let mut mechanism: CK_MECHANISM = m.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
            ))
            .into_result(Function::DigestInit)?;
        }

        Ok(())
    }

    /// Continues an ongoing multi-part digesting operation,
    /// taking in the next part of the data to digest
    pub fn digest_update(&self, data: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestUpdate)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
            ))
            .into_result(Function::DigestUpdate)?;
        }

        Ok(())
    }

    /// Continues an ongoing multi-part digesting operation,
    /// using the value of a secret key as input
    pub fn digest_key(&self, key: ObjectHandle) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestKey)(
                self.handle(),
                key.handle(),
            ))
            .into_result(Function::DigestKey)?;
        }

        Ok(())
    }

    /// Finalizes ongoing multi-part digest operation,
    /// returning the digest
    pub fn digest_final(&self) -> Result<Vec<u8>> {
        let mut digest_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestFinal)(
                self.handle(),
                std::ptr::null_mut(),
                &mut digest_len,
            ))
            .into_result(Function::DigestFinal)?;
        }

        let mut digest = vec![0; digest_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestFinal)(
                self.handle(),
                digest.as_mut_ptr(),
                &mut digest_len,
            ))
            .into_result(Function::DigestFinal)?;
        }

        digest.truncate(digest_len.try_into()?);

        Ok(digest)
    }
}
