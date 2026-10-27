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
            KbkdfParams, PrfDataParam, PrfDataParamType,
        },
    },
    object::KeyType,
};
use std::num::NonZeroUsize;

/// Output type and permissions for the counter-mode SP 800-108 profile.
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
/// SP 800-108 counter mode with HMAC-SHA-256/384/512. The exact PRF input is
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
impl KbkdfRequest<'_> {
    /// Validate identity, input and output bounds without I/O. Callers establish
    /// an unambiguous protocol encoding for label/context and authenticate peers.
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
}
impl std::fmt::Debug for KbkdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KbkdfRequest")
            .field("digest", &self.digest)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
/// Advisory native counter-mode PRF choices for one selected key. Does not
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
            DigestAlgorithm::Sha256 => self.sha256,
            DigestAlgorithm::Sha384 => self.sha384,
            DigestAlgorithm::Sha512 => self.sha512,
        }
    }
}
fn capabilities(object: &Object<'_, '_>) -> Result<KbkdfCapabilities, Error> {
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
    let generic = kind == KeyType::GENERIC_SECRET;
    let caps = KbkdfCapabilities {
        input_length: length,
        sha256: generic || kind == KeyType::SHA256_HMAC,
        sha384: generic || kind == KeyType::SHA384_HMAC,
        sha512: generic || kind == KeyType::SHA512_HMAC,
    };
    if !caps.sha256 && !caps.sha384 && !caps.sha512 {
        return Err(Error::UnsupportedKeyOperation);
    }
    let mechanism = MechanismType::SP800_108_COUNTER_KDF;
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
    Ok(caps)
}
impl Session<'_> {
    /// Inspect a unique generic or SHA-2 HMAC secret for native counter derivation.
    /// Requires sensitive/nonextractable policy, CKA_DERIVE, permitted mechanism,
    /// bit-based mechanism bounds and a native C_DeriveKey entry point.
    pub fn kbkdf_capabilities(&mut self, base: &ObjectRef) -> Result<KbkdfCapabilities, Error> {
        capabilities(&self.resolve(base)?)
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
        request.validate()?;
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
        if !capabilities(&object)?.supports(request.digest) {
            return Err(Error::UnsupportedKeyOperation);
        }
        const WIDTH: NonZeroUsize = NonZeroUsize::new(32).unwrap();
        let counter = KbkdfCounterFormat::new(Endianness::Big, WIDTH);
        let length =
            KbkdfDkmLengthFormat::new(KbkdfDkmLengthMethod::SumOfKeys, Endianness::Big, WIDTH);
        let mut fields = vec![PrfDataParam::new(PrfDataParamType::IterationVariable(
            Some(&counter),
        ))];
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
        let prf = match request.digest {
            DigestAlgorithm::Sha256 => MechanismType::SHA256_HMAC,
            DigestAlgorithm::Sha384 => MechanismType::SHA384_HMAC,
            DigestAlgorithm::Sha512 => MechanismType::SHA512_HMAC,
        };
        let mechanism = Mechanism::KbkdfCounter(KbkdfParams::new(prf, &fields, None));
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
        assert!(!format!("{request:?}").contains("canary"));
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
