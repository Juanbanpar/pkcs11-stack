// SPDX-License-Identifier: MIT OR Apache-2.0
//! NIST SP 800-108 key derivation (KBKDF) through the published upstream types.
//!
//! Counter, feedback and double-pipeline modes are supported with HMAC-SHA-1/2
//! and full-block AES-CMAC PRFs. SHA-3 PRFs and general-length CMAC have no
//! typed upstream mechanism in `cryptoki` 0.12.1.

use crate::{
    Attribute, AttributeType, Error, MacAlgorithm, MechanismType, Object, ObjectClass, ObjectRef,
    Session, SessionMode, error::map_function_not_supported,
    key_operations::validate_secret_identity, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        kbkdf::{
            Endianness, KbkdfCounterFormat, KbkdfDkmLengthFormat, KbkdfDkmLengthMethod,
            KbkdfFeedbackParams, KbkdfParams, PrfDataParam, PrfDataParamType,
        },
    },
    object::KeyType,
};
use std::num::NonZeroUsize;

/// SP 800-108 mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KbkdfMode {
    /// 32-bit big-endian counter first.
    Counter,
    /// Previous PRF output first, then the counter.
    Feedback,
    /// Two PRF pipelines with an A(i) chain.
    DoublePipeline,
}

impl KbkdfMode {
    /// Every mode executable through this module.
    pub const ALL: [Self; 3] = [Self::Counter, Self::Feedback, Self::DoublePipeline];

    /// Numeric PKCS#11 mechanism identifier.
    pub fn mechanism(self) -> MechanismType {
        match self {
            Self::Counter => MechanismType::SP800_108_COUNTER_KDF,
            Self::Feedback => MechanismType::SP800_108_FEEDBACK_KDF,
            Self::DoublePipeline => MechanismType::SP800_108_DOUBLE_PIPELINE_KDF,
        }
    }
}

impl std::fmt::Display for KbkdfMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Counter => "counter",
            Self::Feedback => "feedback",
            Self::DoublePipeline => "double-pipeline",
        })
    }
}

/// SP 800-108 pseudorandom function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KbkdfPrf {
    /// HMAC-SHA-1. Retained for compatibility.
    HmacSha1,
    /// HMAC-SHA-224.
    HmacSha224,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// HMAC-SHA-512.
    HmacSha512,
    /// Full-block AES-CMAC.
    AesCmac,
}

impl KbkdfPrf {
    /// Every PRF executable through this module.
    pub const ALL: [Self; 6] = [
        Self::HmacSha1,
        Self::HmacSha224,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
        Self::AesCmac,
    ];

    /// PRF output block length, also the accepted feedback IV length, in bytes.
    pub fn output_length(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha224 => 28,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
            Self::AesCmac => 16,
        }
    }

    fn mechanism(self) -> MechanismType {
        self.mac().mechanism()
    }

    fn mac(self) -> MacAlgorithm {
        match self {
            Self::HmacSha1 => MacAlgorithm::HmacSha1,
            Self::HmacSha224 => MacAlgorithm::HmacSha224,
            Self::HmacSha256 => MacAlgorithm::HmacSha256,
            Self::HmacSha384 => MacAlgorithm::HmacSha384,
            Self::HmacSha512 => MacAlgorithm::HmacSha512,
            Self::AesCmac => MacAlgorithm::AesCmac,
        }
    }
}

impl std::fmt::Display for KbkdfPrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha224 => "hmac-sha224",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
            Self::AesCmac => "aes-cmac",
        })
    }
}

/// Output key type and permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KbkdfOutput {
    /// AES-128 with encryption/decryption permission only.
    Aes128,
    /// AES-192 with encryption/decryption permission only.
    Aes192,
    /// AES-256 with encryption/decryption permission only.
    Aes256,
    /// Generic secret with derivation permission only, 1..=4096 bytes.
    DerivationSecret {
        /// Output length in bytes.
        length: usize,
    },
}

impl KbkdfOutput {
    /// Requested length in bytes.
    pub fn length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
            Self::DerivationSecret { length } => length,
        }
    }

    fn aes(self) -> bool {
        !matches!(self, Self::DerivationSecret { .. })
    }
}

/// Explicit derivation request. Debug omits label/context/identity bytes.
#[derive(Clone, Copy)]
pub struct KbkdfRequest<'a> {
    /// Native PRF.
    pub prf: KbkdfPrf,
    /// Public protocol label, at most 4096 bytes; empty is permitted.
    pub kdf_label: &'a [u8],
    /// Public protocol context, at most 4096 bytes; empty is permitted.
    pub context: &'a [u8],
    /// Output key length, type and permissions.
    pub output: KbkdfOutput,
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// New nonempty object label, at most 128 bytes.
    pub label: &'a [u8],
}

impl std::fmt::Debug for KbkdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KbkdfRequest")
            .field("prf", &self.prf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}

impl KbkdfRequest<'_> {
    /// Validate identity, public input and output bounds without provider access.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)?;
        if self.kdf_label.len() > 4096
            || self.context.len() > 4096
            || !(1..=4096).contains(&self.output.length())
        {
            return Err(Error::InvalidParameters("SP800-108 input or output length"));
        }
        Ok(())
    }

    /// Validate the feedback IV shape for a mode.
    pub fn validate_with_mode(&self, mode: KbkdfMode, iv: &[u8]) -> Result<(), Error> {
        self.validate()?;
        match mode {
            KbkdfMode::Counter | KbkdfMode::DoublePipeline if !iv.is_empty() => Err(
                Error::InvalidParameters("KDF mode does not accept an external IV"),
            ),
            KbkdfMode::Feedback if !iv.is_empty() && iv.len() != self.prf.output_length() => {
                Err(Error::InvalidParameters("feedback KDF IV length"))
            }
            _ => Ok(()),
        }
    }
}

/// Advisory native support for one base, PRF and mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KbkdfCapabilities {
    /// Base-key length in bytes.
    pub input_length: usize,
    /// Checked PRF.
    pub prf: KbkdfPrf,
    /// Checked mode.
    pub mode: KbkdfMode,
}

fn base_metadata(object: &Object<'_, '_>) -> Result<(u64, usize), Error> {
    for (kind, expected) in [
        (
            AttributeType::Class,
            Attribute::Class(ObjectClass::SECRET_KEY),
        ),
        (AttributeType::Sensitive, Attribute::Sensitive(true)),
        (AttributeType::Extractable, Attribute::Extractable(false)),
        (AttributeType::Derive, Attribute::Derive(true)),
    ] {
        if attribute(object, kind, true)? != Some(expected) {
            return Err(Error::UnsupportedDerivation);
        }
    }
    let length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(n)) if (16..=4096).contains(&usize::from(n)) => usize::from(n),
        _ => return Err(Error::UnsupportedDerivation),
    };
    let kind = match attribute(object, AttributeType::KeyType, true)? {
        Some(Attribute::KeyType(kind)) => *kind,
        _ => return Err(Error::UnsupportedDerivation),
    };
    Ok((kind, length))
}

fn prf_capabilities(
    object: &Object<'_, '_>,
    prf: KbkdfPrf,
    mode: KbkdfMode,
) -> Result<KbkdfCapabilities, Error> {
    let (kind, length) = base_metadata(object)?;
    let matches = match prf {
        KbkdfPrf::AesCmac => kind == *KeyType::AES && matches!(length, 16 | 24 | 32),
        _ => prf.mac().matches_key_type(kind),
    };
    if !matches {
        return Err(Error::UnsupportedDerivation);
    }
    let mechanism = mode.mechanism();
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(allowed))
            if !allowed.is_empty() && !allowed.contains(&mechanism) =>
        {
            return Err(Error::UnsupportedDerivation);
        }
        Some(Attribute::AllowedMechanisms(_)) | None => {}
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
    let token = object.session.token();
    if !token.module.raw()?.is_fn_supported(Function::DeriveKey)
        || !token.mechanisms()?.contains(&mechanism)
    {
        return Err(Error::UnsupportedDerivation);
    }
    let info = token.mechanism_info(mechanism)?;
    if !info.derive() || !(info.min_key_size()..=info.max_key_size()).contains(&(length * 8)) {
        return Err(Error::UnsupportedDerivation);
    }
    Ok(KbkdfCapabilities {
        input_length: length,
        prf,
        mode,
    })
}

impl Session<'_> {
    /// Inspect one explicit PRF and mode without deriving.
    pub fn kbkdf_capabilities(
        &mut self,
        base: &ObjectRef,
        prf: KbkdfPrf,
        mode: KbkdfMode,
    ) -> Result<KbkdfCapabilities, Error> {
        prf_capabilities(&self.resolve(base)?, prf, mode)
    }

    /// Inspect every supported PRF/mode combination for a base key.
    ///
    /// Unsupported combinations are omitted; selection and provider errors
    /// propagate. An empty result means no typed profile qualifies.
    pub fn kbkdf_options(&mut self, base: &ObjectRef) -> Result<Vec<KbkdfCapabilities>, Error> {
        let object = self.resolve(base)?;
        let mut options = Vec::new();
        for mode in KbkdfMode::ALL {
            for prf in KbkdfPrf::ALL {
                match prf_capabilities(&object, prf, mode) {
                    Ok(capability) => options.push(capability),
                    Err(Error::UnsupportedDerivation) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(options)
    }

    /// Derive one persistent key using SP 800-108 once.
    ///
    /// Counter and double-pipeline reject a nonempty IV. Feedback accepts an
    /// omitted IV or exactly one PRF block. The result is private, sensitive and
    /// nonextractable. No values are read, no fallback is attempted, and a
    /// provider failure may leave persistent effects.
    pub fn derive_kbkdf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        request.validate_with_mode(mode, iv)?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut template =
            self.new_secret_template(request.id, request.label, request.output.aes())?;
        template.push(Attribute::ValueLen(
            request
                .output
                .length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("SP800-108 output length"))?,
        ));
        let object = self.resolve(base)?;
        prf_capabilities(&object, request.prf, mode)?;
        const WIDTH: NonZeroUsize = NonZeroUsize::new(32).unwrap();
        let counter = KbkdfCounterFormat::new(Endianness::Big, WIDTH);
        let length =
            KbkdfDkmLengthFormat::new(KbkdfDkmLengthMethod::SumOfKeys, Endianness::Big, WIDTH);
        let mut fields = vec![PrfDataParam::new(PrfDataParamType::IterationVariable(
            if mode == KbkdfMode::Counter {
                Some(&counter)
            } else {
                None
            },
        ))];
        if mode != KbkdfMode::Counter {
            fields.push(PrfDataParam::new(PrfDataParamType::Counter(&counter)));
        }
        if !request.kdf_label.is_empty() {
            fields.push(PrfDataParam::new(PrfDataParamType::ByteArray(
                request.kdf_label,
            )));
        }
        fields.push(PrfDataParam::new(PrfDataParamType::ByteArray(&[0])));
        if !request.context.is_empty() {
            fields.push(PrfDataParam::new(PrfDataParamType::ByteArray(
                request.context,
            )));
        }
        fields.push(PrfDataParam::new(PrfDataParamType::DkmLength(&length)));
        let prf = request.prf.mechanism();
        let mechanism = match mode {
            KbkdfMode::Counter => Mechanism::KbkdfCounter(KbkdfParams::new(prf, &fields, None)),
            KbkdfMode::DoublePipeline => {
                Mechanism::KbkdfDoublePipeline(KbkdfParams::new(prf, &fields, None))
            }
            KbkdfMode::Feedback => Mechanism::KbkdfFeedback(KbkdfFeedbackParams::new(
                prf,
                &fields,
                (!iv.is_empty()).then_some(iv),
                None,
            )),
        };
        object
            .session
            .write_operation("derive SP800-108 key", |raw| {
                raw.derive_key(&mechanism, object.handle, &template)
            })
            .map_err(|e| map_function_not_supported(e, Error::UnsupportedDerivation))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bounds_and_debug_are_explicit() {
        let request = KbkdfRequest {
            prf: KbkdfPrf::HmacSha256,
            kdf_label: b"label-canary",
            context: b"context-canary",
            output: KbkdfOutput::Aes256,
            id: b"id-canary",
            label: b"object-canary",
        };
        request.validate().unwrap();
        request
            .validate_with_mode(KbkdfMode::DoublePipeline, &[])
            .unwrap();
        assert!(!format!("{request:?}").contains("canary"));
        assert!(
            request
                .validate_with_mode(KbkdfMode::Feedback, &[0; 32])
                .is_ok()
        );
        assert!(
            request
                .validate_with_mode(KbkdfMode::Feedback, &[0; 31])
                .is_err()
        );
        assert!(
            request
                .validate_with_mode(KbkdfMode::Counter, &[0; 1])
                .is_err()
        );
        for output in [
            KbkdfOutput::DerivationSecret { length: 0 },
            KbkdfOutput::DerivationSecret { length: 4097 },
        ] {
            assert!(KbkdfRequest { output, ..request }.validate().is_err());
        }
    }

    #[test]
    fn prf_lengths_and_identifiers_are_stable() {
        for (prf, length) in [
            (KbkdfPrf::HmacSha1, 20),
            (KbkdfPrf::HmacSha224, 28),
            (KbkdfPrf::HmacSha256, 32),
            (KbkdfPrf::HmacSha384, 48),
            (KbkdfPrf::HmacSha512, 64),
            (KbkdfPrf::AesCmac, 16),
        ] {
            assert_eq!(prf.output_length(), length);
        }
        assert_eq!(
            KbkdfMode::Counter.mechanism(),
            MechanismType::SP800_108_COUNTER_KDF
        );
    }
}
