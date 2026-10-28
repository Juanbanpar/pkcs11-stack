// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Decrypting data

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session {
    /// Single-part decryption operation
    pub fn decrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut data_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::DecryptInit)?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Decrypt)(
                self.handle(),
                // C_Decrypt should not modify this buffer
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                std::ptr::null_mut(),
                &mut data_len,
            ))
            .into_result(Function::Decrypt)?;
        }

        let mut data = vec![0; data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Decrypt)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                data.as_mut_ptr(),
                &mut data_len,
            ))
            .into_result(Function::Decrypt)?;
        }

        data.truncate(data_len.try_into()?);

        Ok(data)
    }

    /// Complete a single-part operation after `decrypt_init` and any required
    /// context login, without reinitialization. Allocation is bounded by the
    /// caller and the entire plaintext buffer zeroizes on failure or drop.
    pub fn decrypt_initialized(
        &self,
        encrypted_data: &[u8],
        maximum_output: usize,
    ) -> Result<secrecy::SecretBox<Vec<u8>>> {
        use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
        let input_length = encrypted_data.len().try_into()?;
        let mut length = 0;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Decrypt)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                input_length,
                std::ptr::null_mut(),
                &mut length,
            ))
            .into_result(Function::Decrypt)?;
        }
        let capacity: usize = length.try_into()?;
        if capacity > maximum_output {
            return Err(crate::error::Error::InvalidValue);
        }
        let mut output = SecretBox::new(Box::new(vec![0; capacity]));
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Decrypt)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                input_length,
                output.expose_secret_mut().as_mut_ptr(),
                &mut length,
            ))
            .into_result(Function::Decrypt)?;
        }
        let written: usize = length.try_into()?;
        if written > output.expose_secret().len() {
            return Err(crate::error::Error::InvalidValue);
        }
        output.expose_secret_mut()[written..].fill(0);
        output.expose_secret_mut().truncate(written);
        Ok(output)
    }

    /// Starts new multi-part decryption operation
    pub fn decrypt_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::DecryptInit)?;
        }

        Ok(())
    }

    /// Continues an ongoing multi-part decryption operation,
    /// taking in the next part of the encrypted data and returning its decryption
    pub fn decrypt_update(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let mut data_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptUpdate)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                std::ptr::null_mut(),
                &mut data_len,
            ))
            .into_result(Function::DecryptUpdate)?;
        }

        let mut data = vec![0; data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptUpdate)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                data.as_mut_ptr(),
                &mut data_len,
            ))
            .into_result(Function::DecryptUpdate)?;
        }

        data.truncate(data_len.try_into()?);

        Ok(data)
    }

    /// Finalizes ongoing multi-part decryption operation,
    /// returning any remaining bytes in the decrypted data
    pub fn decrypt_final(&self) -> Result<Vec<u8>> {
        let mut data_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptFinal)(
                self.handle(),
                std::ptr::null_mut(),
                &mut data_len,
            ))
            .into_result(Function::DecryptFinal)?;
        }

        let mut data = vec![0; data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptFinal)(
                self.handle(),
                data.as_mut_ptr(),
                &mut data_len,
            ))
            .into_result(Function::DecryptFinal)?;
        }

        data.truncate(data_len.try_into()?);

        Ok(data)
    }

    /// Continue initialized multipart decryption into caller-bounded storage.
    /// Makes no output-size query, allocation or retry. Output may be
    /// unauthenticated: callers must quarantine it and zeroize it on failure.
    pub fn decrypt_update_into(&self, encrypted_data: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut written = output.len().try_into()?;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptUpdate)(
                self.handle(),
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                output.as_mut_ptr(),
                &mut written,
            ))
            .into_result(Function::DecryptUpdate)?;
        }
        let written: usize = written.try_into()?;
        if written > output.len() {
            return Err(crate::error::Error::InvalidValue);
        }
        Ok(written)
    }

    /// Finalize multipart decryption into caller-bounded storage.
    /// Makes no output-size query, allocation or retry. Callers must zeroize the
    /// entire output on failure, including any bytes written before the error.
    pub fn decrypt_final_into(&self, output: &mut [u8]) -> Result<usize> {
        let mut written = output.len().try_into()?;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecryptFinal)(
                self.handle(),
                output.as_mut_ptr(),
                &mut written,
            ))
            .into_result(Function::DecryptFinal)?;
        }
        let written: usize = written.try_into()?;
        if written > output.len() {
            return Err(crate::error::Error::InvalidValue);
        }
        Ok(written)
    }
}
