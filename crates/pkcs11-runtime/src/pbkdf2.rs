// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, Error, MechanismType, Session, SessionMode, key_operations::validate_secret_identity,
};
pub use cryptoki::mechanism::pbkdf2::Pbkdf2Prf;
use cryptoki::{
    context::Function,
    mechanism::{Mechanism, pbkdf2::Pbkdf2Params},
};
use secrecy::{ExposeSecret, SecretSlice};
use std::num::NonZeroU32;

/// Maximum password, salt and generic output length, in bytes.
pub const PBKDF2_MAXIMUM_LENGTH: usize = 4096;
/// Maximum iterations times output PRF blocks per request. This bounds work;
/// it is not a recommendation for password strength or protocol parameters.
pub const PBKDF2_MAXIMUM_WORK: u64 = 10_000_000;

/// Persistent, private, sensitive and nonextractable PBKDF2 output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pbkdf2Output {
    /// AES-128 with encryption/decryption permission only.
    Aes128,
    /// AES-192 with encryption/decryption permission only.
    Aes192,
    /// AES-256 with encryption/decryption permission only.
    Aes256,
    /// Generic secret with derivation permission only.
    DerivationSecret {
        /// Output length in bytes, 1..=4096.
        length: usize,
    },
}
impl Pbkdf2Output {
    /// Requested output length in bytes; validation enforces application bounds.
    pub fn length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
            Self::DerivationSecret { length } => length,
        }
    }
}
/// One native PKCS #5 PBKDF2 generation. Password and salt bytes are passed
/// verbatim, including NULs and newlines. Empty passwords are permitted.
/// Callers choose protocol-appropriate salts and iterations; there are no defaults.
/// Debug omits password, salt and object identity.
#[derive(Clone, Copy)]
pub struct Pbkdf2Request<'a> {
    /// Borrowed secret storage; the caller controls its lifetime and zeroization.
    pub password: &'a SecretSlice<u8>,
    /// Explicit, nonempty public salt, at most 4096 bytes.
    pub salt: &'a [u8],
    /// Explicit fixed-output SHA-2 HMAC PRF; no substitution occurs.
    pub prf: Pbkdf2Prf,
    /// Positive iteration count, subject to the total work bound.
    pub iterations: u32,
    /// Output type, length and permissions.
    pub output: Pbkdf2Output,
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// Nonempty object label, at most 128 bytes.
    pub label: &'a [u8],
}
impl Pbkdf2Request<'_> {
    /// Validate all application bounds without provider access. Work is bounded
    /// by iterations times ceil(output bytes / PRF output bytes), not wall time.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        if self.password.expose_secret().len() > PBKDF2_MAXIMUM_LENGTH
            || !(1..=PBKDF2_MAXIMUM_LENGTH).contains(&self.salt.len())
            || !(1..=PBKDF2_MAXIMUM_LENGTH).contains(&self.output.length())
        {
            return Err(Error::InvalidParameters("PBKDF2 input or output length"));
        }
        let blocks = self.output.length().div_ceil(self.prf.output_len()) as u64;
        if self.iterations == 0 || u64::from(self.iterations) * blocks > PBKDF2_MAXIMUM_WORK {
            return Err(Error::InvalidParameters("PBKDF2 iteration or work bound"));
        }
        Ok(())
    }
}
impl std::fmt::Debug for Pbkdf2Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pbkdf2Request")
            .field("prf", &self.prf)
            .field("iterations", &self.iterations)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl Session<'_> {
    /// Inspect advertised PBKDF2 generation support and the C_GenerateKey pointer.
    /// This is advisory: individual PRFs and output templates may be rejected.
    /// OASIS section 6.37 does not specify units for mechanism size bounds, so
    /// they are not reinterpreted here. No HMAC or C_DeriveKey support is required.
    pub fn pbkdf2_supported(&self) -> Result<bool, Error> {
        self.validate()?;
        let token = self.token();
        let mechanism = MechanismType::PKCS5_PBKD2;
        Ok(token.module.raw()?.is_fn_supported(Function::GenerateKey)
            && token.mechanisms()?.contains(&mechanism)
            && token.mechanism_info(mechanism)?.generate())
    }
    /// Generate one protected token key using CK_PKCS5_PBKD2_PARAMS2 and
    /// C_GenerateKey. Requires RW access and a new secret ID. Password bytes enter
    /// the provider; generated values are never read. No fallback, retry or rollback.
    /// Native errors invalidate the session and can leave persistent effects.
    /// Check session closure before reporting success.
    ///
    /// Parameter buffers must outlive the native call:
    /// ```compile_fail
    /// use cryptoki::mechanism::pbkdf2::{Pbkdf2Params, Pbkdf2Prf};
    /// let params = {
    ///     let password = vec![1, 2, 3];
    ///     Pbkdf2Params::new(Pbkdf2Prf::HmacSha256, &password, b"salt", std::num::NonZeroU32::new(2).unwrap()).unwrap()
    /// };
    /// println!("{params:?}");
    /// ```
    pub fn generate_pbkdf2(&mut self, request: &Pbkdf2Request<'_>) -> Result<(), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self.pbkdf2_supported()? {
            return Err(Error::UnsupportedKeyOperation);
        }
        let mut template = self.new_secret_template(
            request.id,
            request.label,
            !matches!(request.output, Pbkdf2Output::DerivationSecret { .. }),
        )?;
        template.push(Attribute::ValueLen(
            request
                .output
                .length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("PBKDF2 output length"))?,
        ));
        let iterations = NonZeroU32::new(request.iterations)
            .ok_or(Error::InvalidParameters("PBKDF2 iterations"))?;
        let params = Pbkdf2Params::new(
            request.prf,
            request.password.expose_secret(),
            request.salt,
            iterations,
        )
        .map_err(|e| crate::error::backend("PBKDF2 parameters", e))?;
        self.write_operation("generate PBKDF2 key", |raw| {
            raw.generate_key(&Mechanism::Pbkdf2(params), &template)
        })?;
        Ok(())
    }
}
