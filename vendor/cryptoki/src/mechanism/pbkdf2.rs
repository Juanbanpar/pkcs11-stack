// SPDX-License-Identifier: Apache-2.0
//! Borrowed PKCS #5 PBKDF2 parameters using the corrected PARAMS2 layout.
use crate::error::{Error, Result};
use cryptoki_sys::*;
use std::{marker::PhantomData, num::NonZeroU32, ptr::null_mut};

/// Fixed-output SHA-2 HMAC PRFs defined by PKCS #11 for PBKDF2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pbkdf2Prf {
    /// HMAC-SHA-224.
    HmacSha224,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// HMAC-SHA-512.
    HmacSha512,
    /// HMAC-SHA-512/224, distinct from truncating SHA-512.
    HmacSha512_224,
    /// HMAC-SHA-512/256, distinct from truncating SHA-512.
    HmacSha512_256,
}
impl Pbkdf2Prf {
    /// Standard SHA-2 choices; provider support is checked at execution.
    pub const ALL: [Self; 6] = [
        Self::HmacSha224,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
        Self::HmacSha512_224,
        Self::HmacSha512_256,
    ];
    /// Full PRF output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::HmacSha224 | Self::HmacSha512_224 => 28,
            Self::HmacSha256 | Self::HmacSha512_256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }
    fn native(self) -> CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE {
        match self {
            Self::HmacSha224 => CKP_PKCS5_PBKD2_HMAC_SHA224,
            Self::HmacSha256 => CKP_PKCS5_PBKD2_HMAC_SHA256,
            Self::HmacSha384 => CKP_PKCS5_PBKD2_HMAC_SHA384,
            Self::HmacSha512 => CKP_PKCS5_PBKD2_HMAC_SHA512,
            Self::HmacSha512_224 => CKP_PKCS5_PBKD2_HMAC_SHA512_224,
            Self::HmacSha512_256 => CKP_PKCS5_PBKD2_HMAC_SHA512_256,
        }
    }
}
/// Synchronous password/salt borrows, without owned password copies.
/// Debug omits all parameter values. The provider must consume them during C_GenerateKey.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Pbkdf2Params<'a> {
    inner: CK_PKCS5_PBKD2_PARAMS2,
    borrowed: PhantomData<&'a [u8]>,
}
impl std::fmt::Debug for Pbkdf2Params<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pbkdf2Params").finish_non_exhaustive()
    }
}
impl<'a> Pbkdf2Params<'a> {
    /// Borrow exact password and salt bytes; neither is normalized. Salt must be
    /// nonempty. Lengths must fit CK_ULONG. PRF data is always NULL/zero.
    pub fn new(
        prf: Pbkdf2Prf,
        password: &'a [u8],
        salt: &'a [u8],
        iterations: NonZeroU32,
    ) -> Result<Self> {
        if salt.is_empty() {
            return Err(Error::InvalidValue);
        }
        Ok(Self {
            inner: CK_PKCS5_PBKD2_PARAMS2 {
                saltSource: CKZ_SALT_SPECIFIED,
                pSaltSourceData: salt.as_ptr().cast_mut().cast(),
                ulSaltSourceDataLen: salt.len().try_into()?,
                iterations: iterations.get().into(),
                prf: prf.native(),
                pPrfData: null_mut(),
                ulPrfDataLen: 0,
                pPassword: password.as_ptr().cast_mut(),
                ulPasswordLen: password.len().try_into()?,
            },
            borrowed: PhantomData,
        })
    }
    pub(crate) fn inner(&self) -> &CK_PKCS5_PBKD2_PARAMS2 {
        &self.inner
    }
}
