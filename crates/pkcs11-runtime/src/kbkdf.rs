// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, DigestAlgorithm, Error, MechanismType, Object, ObjectClass,
    ObjectRef, Session, SessionMode, hkdf::permits, key_operations::validate_secret_identity,
    signing::attribute,
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

/// Explicit SP 800-108 mode. Existing calls continue to use counter mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KbkdfMode {
    /// PRF input starts with a 32-bit big-endian counter.
    #[default]
    Counter,
    /// PRF input starts with the previous PRF output, then the counter.
    Feedback,
    /// Two PRF pipelines, with A(0) built from label, separator, context and L.
    /// Uses a 32-bit big-endian counter after A(i); external IVs are rejected.
    DoublePipeline,
}
impl KbkdfMode {
    /// Supported mode profiles; individual provider support remains advisory.
    pub const ALL: [Self; 3] = [Self::Counter, Self::Feedback, Self::DoublePipeline];
    fn mechanism(self) -> MechanismType {
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
            Self::Counter => "Counter",
            Self::Feedback => "Feedback",
            Self::DoublePipeline => "Double Pipeline",
        })
    }
}
/// Advisory PRF choices per mode, inspected from the same selected key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KbkdfOptions {
    /// Permitted counter-mode profile, if supported.
    pub counter: Option<KbkdfCapabilities>,
    /// Permitted feedback-mode profile, if supported.
    pub feedback: Option<KbkdfCapabilities>,
    /// Permitted double-pipeline profile, if supported.
    pub double_pipeline: Option<KbkdfCapabilities>,
}
impl KbkdfOptions {
    /// Get the inspected profile for a mode. Execution rechecks native support.
    pub fn get(self, mode: KbkdfMode) -> Option<KbkdfCapabilities> {
        match mode {
            KbkdfMode::Counter => self.counter,
            KbkdfMode::Feedback => self.feedback,
            KbkdfMode::DoublePipeline => self.double_pipeline,
        }
    }
}
/// Output type and permissions for the SP 800-108 profiles.
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
    /// Requested length in bytes; request validation enforces bounds.
    pub fn length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
            Self::DerivationSecret { length } => length,
        }
    }
}
/// Explicit SP 800-108 PRF. AES-CMAC requires a 16/24/32-byte AES base key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KbkdfPrf {
    /// HMAC-SHA-256, with a generic or matching typed HMAC base.
    HmacSha256,
    /// HMAC-SHA-384, with a generic or matching typed HMAC base.
    HmacSha384,
    /// HMAC-SHA-512, with a generic or matching typed HMAC base.
    HmacSha512,
    /// Full-block AES-CMAC; standalone MAC permission is not required.
    AesCmac,
}
impl KbkdfPrf {
    /// PRF output block length, also the nonempty Feedback IV length, in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
            Self::AesCmac => 16,
        }
    }
    fn mechanism(self) -> MechanismType {
        match self {
            Self::HmacSha256 => MechanismType::SHA256_HMAC,
            Self::HmacSha384 => MechanismType::SHA384_HMAC,
            Self::HmacSha512 => MechanismType::SHA512_HMAC,
            Self::AesCmac => MechanismType::AES_CMAC,
        }
    }
    fn permits(self, kind: KeyType, length: usize) -> bool {
        match self {
            Self::AesCmac => kind == KeyType::AES && matches!(length, 16 | 24 | 32),
            Self::HmacSha256 => kind == KeyType::GENERIC_SECRET || kind == KeyType::SHA256_HMAC,
            Self::HmacSha384 => kind == KeyType::GENERIC_SECRET || kind == KeyType::SHA384_HMAC,
            Self::HmacSha512 => kind == KeyType::GENERIC_SECRET || kind == KeyType::SHA512_HMAC,
        }
    }
}
impl TryFrom<DigestAlgorithm> for KbkdfPrf {
    type Error = Error;
    fn try_from(digest: DigestAlgorithm) -> Result<Self, Error> {
        match digest {
            DigestAlgorithm::Sha256 => Ok(Self::HmacSha256),
            DigestAlgorithm::Sha384 => Ok(Self::HmacSha384),
            DigestAlgorithm::Sha512 => Ok(Self::HmacSha512),
            _ => Err(Error::InvalidParameters("SP800-108 digest")),
        }
    }
}
/// One explicit PRF derivation, with the same encoding and output policy as KbkdfRequest.
/// Debug omits label/context/identity bytes. No PRF, mode or key-type substitution occurs.
#[derive(Clone, Copy)]
pub struct KbkdfPrfRequest<'a> {
    /// Native PRF to execute.
    pub prf: KbkdfPrf,
    /// Public protocol label, up to 4096 bytes; empty is permitted.
    pub kdf_label: &'a [u8],
    /// Public protocol context, up to 4096 bytes; empty is permitted.
    pub context: &'a [u8],
    /// Output key length, type and permissions.
    pub output: KbkdfOutput,
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// New nonempty object label, at most 128 bytes; distinct from kdf_label.
    pub label: &'a [u8],
}
impl KbkdfPrfRequest<'_> {
    /// Validate identity and public input/output bounds without provider access.
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
    /// Counter/Double Pipeline require an empty IV. Feedback accepts an omitted
    /// IV or exactly one PRF output block, including 16 bytes for AES-CMAC.
    pub fn validate_with_mode(&self, mode: KbkdfMode, iv: &[u8]) -> Result<(), Error> {
        self.validate()?;
        match mode {
            KbkdfMode::Counter | KbkdfMode::DoublePipeline if !iv.is_empty() => Err(
                Error::InvalidParameters("KDF mode does not accept an external IV"),
            ),
            KbkdfMode::Feedback if !iv.is_empty() && iv.len() != self.prf.output_len() => {
                Err(Error::InvalidParameters("feedback KDF IV length"))
            }
            _ => Ok(()),
        }
    }
}
impl std::fmt::Debug for KbkdfPrfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KbkdfPrfRequest")
            .field("prf", &self.prf)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
/// Advisory native support for exactly one selected base, PRF and mode.
/// Providers may still reject PRF parameters or output templates at execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KbkdfPrfCapabilities {
    /// Base-key length in bytes; AES-CMAC permits only 16/24/32.
    pub input_length: usize,
    /// Explicit native PRF checked by this snapshot.
    pub prf: KbkdfPrf,
    /// Explicit native KDF mode checked by this snapshot.
    pub mode: KbkdfMode,
}
/// SP 800-108 with HMAC-SHA-256/384/512, using counter mode by default.
/// The counter-mode PRF input is
/// `[i]_32 || kdf_label || 0x00 || context || [L]_32`, with big-endian integers
/// and L in bits. One persistent, private, sensitive, nonextractable key results.
#[derive(Clone, Copy)]
pub struct KbkdfRequest<'a> {
    /// HMAC hash; no digest or mode substitution occurs.
    pub digest: DigestAlgorithm,
    /// Public protocol label, up to 4096 bytes; empty is permitted.
    pub kdf_label: &'a [u8],
    /// Public protocol context, up to 4096 bytes; empty is permitted.
    pub context: &'a [u8],
    /// Output key length, type and permissions.
    pub output: KbkdfOutput,
    /// New nonempty secret ID, at most 128 bytes.
    pub id: &'a [u8],
    /// New nonempty object label, at most 128 bytes; distinct from kdf_label.
    pub label: &'a [u8],
}
impl<'a> KbkdfRequest<'a> {
    fn prf_request(&self) -> Result<KbkdfPrfRequest<'a>, Error> {
        Ok(KbkdfPrfRequest {
            prf: self.digest.try_into()?,
            kdf_label: self.kdf_label,
            context: self.context,
            output: self.output,
            id: self.id,
            label: self.label,
        })
    }
    /// Validate the existing HMAC profile and its explicit mode's public IV.
    /// Feedback accepts an omitted IV or exactly 32/48/64 bytes for the hash.
    pub fn validate_with_mode(&self, mode: KbkdfMode, iv: &[u8]) -> Result<(), Error> {
        self.prf_request()?.validate_with_mode(mode, iv)
    }
    /// Validate identity, input and output bounds without I/O. Callers establish
    /// an unambiguous protocol encoding for label/context and authenticate peers.
    pub fn validate(&self) -> Result<(), Error> {
        self.prf_request()?.validate()
    }
}
impl std::fmt::Debug for KbkdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KbkdfRequest")
            .field("digest", &self.digest)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
/// Advisory native PRF choices for one selected key and mode. Does not
/// promise native acceptance of individual PRF parameters or output templates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KbkdfCapabilities {
    /// Base-key length in bytes, restricted to 16..=4096 by this application.
    pub input_length: usize,
    /// HMAC-SHA-256 is compatible with the key type.
    pub sha256: bool,
    /// HMAC-SHA-384 is compatible with the key type.
    pub sha384: bool,
    /// HMAC-SHA-512 is compatible with the key type.
    pub sha512: bool,
}
impl KbkdfCapabilities {
    /// Whether the selected hash was permitted when inspected; execution rechecks.
    pub fn supports(self, digest: DigestAlgorithm) -> bool {
        match digest {
            DigestAlgorithm::Sha224
            | DigestAlgorithm::Sha3_224
            | DigestAlgorithm::Sha3_256
            | DigestAlgorithm::Sha3_384
            | DigestAlgorithm::Sha3_512 => false,
            DigestAlgorithm::Sha256 => self.sha256,
            DigestAlgorithm::Sha384 => self.sha384,
            DigestAlgorithm::Sha512 => self.sha512,
        }
    }
}
fn capabilities(object: &Object<'_, '_>, mode: KbkdfMode) -> Result<KbkdfCapabilities, Error> {
    let (kind, length) = base_metadata(object)?;
    let caps = KbkdfCapabilities {
        input_length: length,
        sha256: KbkdfPrf::HmacSha256.permits(kind, length),
        sha384: KbkdfPrf::HmacSha384.permits(kind, length),
        sha512: KbkdfPrf::HmacSha512.permits(kind, length),
    };
    if !caps.sha256 && !caps.sha384 && !caps.sha512 {
        return Err(Error::UnsupportedKeyOperation);
    }
    mechanism_support(object, mode, length)?;
    Ok(caps)
}
fn prf_capabilities(
    object: &Object<'_, '_>,
    prf: KbkdfPrf,
    mode: KbkdfMode,
) -> Result<KbkdfPrfCapabilities, Error> {
    let (kind, length) = base_metadata(object)?;
    if !prf.permits(kind, length) {
        return Err(Error::UnsupportedKeyOperation);
    }
    mechanism_support(object, mode, length)?;
    Ok(KbkdfPrfCapabilities {
        input_length: length,
        prf,
        mode,
    })
}
fn base_metadata(object: &Object<'_, '_>) -> Result<(KeyType, usize), Error> {
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
            return Err(Error::UnsupportedKeyOperation);
        }
    }
    let length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(n)) if (16..=4096).contains(&usize::from(n)) => usize::from(n),
        _ => return Err(Error::UnsupportedKeyOperation),
    };
    let kind = match attribute(object, AttributeType::KeyType, true)? {
        Some(Attribute::KeyType(kind)) => kind,
        _ => return Err(Error::UnsupportedKeyOperation),
    };
    Ok((kind, length))
}
fn mechanism_support(object: &Object<'_, '_>, mode: KbkdfMode, length: usize) -> Result<(), Error> {
    let mechanism = mode.mechanism();
    permits(object, mechanism)?;
    let token = object.session.token();
    if !token.module.raw()?.is_fn_supported(Function::DeriveKey)
        || !token.mechanisms()?.contains(&mechanism)
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    let info = token.mechanism_info(mechanism)?;
    // OASIS 3.2 section 6.42 defines these base-key bounds in bits, across PRFs.
    if !info.derive() || !(info.min_key_size()..=info.max_key_size()).contains(&(length * 8)) {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(())
}
impl Session<'_> {
    /// Inspect one explicit PRF/mode. Requires sensitive, nonextractable,
    /// derivation-enabled secret metadata and native derive support. AES-CMAC
    /// accepts only AES-128/192/256 bases; standalone CMAC flags/pointers are irrelevant.
    pub fn kbkdf_prf_capabilities(
        &mut self,
        base: &ObjectRef,
        prf: KbkdfPrf,
        mode: KbkdfMode,
    ) -> Result<KbkdfPrfCapabilities, Error> {
        prf_capabilities(&self.resolve(base)?, prf, mode)
    }
    /// Inspect a unique generic or SHA-2 HMAC secret for native counter derivation.
    /// Requires sensitive/nonextractable policy, CKA_DERIVE, permitted mechanism,
    /// bit-based mechanism bounds and a native C_DeriveKey entry point.
    pub fn kbkdf_capabilities(&mut self, base: &ObjectRef) -> Result<KbkdfCapabilities, Error> {
        self.kbkdf_capabilities_with_mode(base, KbkdfMode::Counter)
    }
    /// Inspect native support for an explicit mode without performing derivation.
    /// Key policy, mechanism flags and bit-based bounds are checked per mode.
    pub fn kbkdf_capabilities_with_mode(
        &mut self,
        base: &ObjectRef,
        mode: KbkdfMode,
    ) -> Result<KbkdfCapabilities, Error> {
        capabilities(&self.resolve(base)?, mode)
    }
    /// Inspect all three modes. Only unsupported profiles are omitted; selection
    /// and provider errors propagate. Fails if no supported profile qualifies.
    pub fn kbkdf_options(&mut self, base: &ObjectRef) -> Result<KbkdfOptions, Error> {
        let object = self.resolve(base)?;
        let inspect = |mode| match capabilities(&object, mode) {
            Ok(caps) => Ok(Some(caps)),
            Err(Error::UnsupportedKeyOperation) => Ok(None),
            Err(error) => Err(error),
        };
        let options = KbkdfOptions {
            counter: inspect(KbkdfMode::Counter)?,
            feedback: inspect(KbkdfMode::Feedback)?,
            double_pipeline: inspect(KbkdfMode::DoublePipeline)?,
        };
        if KbkdfMode::ALL
            .into_iter()
            .all(|mode| options.get(mode).is_none())
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        Ok(options)
    }
    /// Derive one key via CKM_SP800_108_COUNTER_KDF. Requires RW mode. Uses a
    /// 32-bit big-endian counter, zero separator and 32-bit big-endian sum-of-keys
    /// length in bits, with no additional keys. No key values, software fallback,
    /// retries or rollback. Native errors invalidate the session and may leave
    /// persistent effects. Check closure; a capability snapshot is advisory.
    pub fn derive_kbkdf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
    ) -> Result<(), Error> {
        self.derive_kbkdf_with_mode(base, request, KbkdfMode::Counter, &[])
    }
    /// Derive once using an explicit mode and public feedback IV. Counter and
    /// double-pipeline modes reject nonempty IVs; feedback accepts empty or
    /// hash-length IVs. Feedback PRF input is `K(i-1) || [i]_32 || label || 0x00 || context || [L]_32`,
    /// with K(0) equal to the supplied IV. Double pipeline uses
    /// `A(0) = label || 0x00 || context || [L]_32`, `A(i) = PRF(K, A(i-1))`,
    /// then `PRF(K, A(i) || [i]_32 || label || 0x00 || context || [L]_32)`.
    /// Integers are big-endian; L is in bits.
    /// Requires the same key policy, RW access and checked closure as derive_kbkdf.
    /// Native rejection invalidates the session and is never retried in another mode.
    pub fn derive_kbkdf_with_mode(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        self.derive_kbkdf_prf(base, &request.prf_request()?, mode, iv)
    }
    /// Derive once using an explicit PRF and mode with the fixed 32-bit big-endian
    /// counter/output bit length, zero separator and one protected output key.
    /// Feedback uses an omitted or PRF-block-length IV. Requires RW access and a
    /// fresh identity. No values are read; native failure discards the session and
    /// may leave persistent effects. Check closure before reporting success.
    pub fn derive_kbkdf_prf(
        &mut self,
        base: &ObjectRef,
        request: &KbkdfPrfRequest<'_>,
        mode: KbkdfMode,
        iv: &[u8],
    ) -> Result<(), Error> {
        request.validate_with_mode(mode, iv)?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut template = self.new_secret_template(
            request.id,
            request.label,
            !matches!(request.output, KbkdfOutput::DerivationSecret { .. }),
        )?;
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
            })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_bounds_and_debug_reject_or_omit_input() {
        let request = KbkdfRequest {
            digest: DigestAlgorithm::Sha256,
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
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let request = KbkdfRequest { digest, ..request };
            for iv in [&[][..], &vec![0xA5; digest.output_len()][..]] {
                request.validate_with_mode(KbkdfMode::Feedback, iv).unwrap();
            }
            for length in [1, 31, 33, 65, 4097] {
                let iv = vec![0; length];
                assert!(
                    request
                        .validate_with_mode(KbkdfMode::Feedback, &iv)
                        .is_err()
                );
                assert!(request.validate_with_mode(KbkdfMode::Counter, &iv).is_err());
                assert!(
                    request
                        .validate_with_mode(KbkdfMode::DoublePipeline, &iv)
                        .is_err()
                );
            }
        }
        for length in [1, 4096] {
            KbkdfRequest {
                kdf_label: &[],
                context: &[],
                output: KbkdfOutput::DerivationSecret { length },
                ..request
            }
            .validate()
            .unwrap();
        }
        for bad in [
            KbkdfRequest { id: &[], ..request },
            KbkdfRequest {
                label: &[0; 129],
                ..request
            },
            KbkdfRequest {
                kdf_label: &[0; 4097],
                ..request
            },
            KbkdfRequest {
                context: &[0; 4097],
                ..request
            },
            KbkdfRequest {
                output: KbkdfOutput::DerivationSecret { length: 0 },
                ..request
            },
            KbkdfRequest {
                output: KbkdfOutput::DerivationSecret { length: 4097 },
                ..request
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
