// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, DigestAlgorithm, Error, MechanismType, Object, ObjectClass,
    ObjectRef, Session, SessionMode, key_operations::validate_secret_identity, signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::{
        Mechanism,
        hkdf::{HkdfParams, HkdfSalt},
    },
    object::KeyType,
};

/// Explicit HKDF stage selection; existing derivation calls extract and expand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HkdfMode {
    /// Extract IKM to a PRK and expand to the requested output.
    #[default]
    ExtractAndExpand,
    /// Create a hash-length derivation secret containing the PRK.
    ExtractOnly,
    /// Expand a caller-established PRK, without another extraction.
    ExpandOnly,
}
impl HkdfMode {
    /// Available stage selections; individual parameter support remains advisory.
    pub const ALL: [Self; 3] = [Self::ExtractAndExpand, Self::ExtractOnly, Self::ExpandOnly];
}
impl std::fmt::Display for HkdfMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExtractAndExpand => "Extract and expand",
            Self::ExtractOnly => "Extract PRK only",
            Self::ExpandOnly => "Expand PRK only",
        })
    }
}
/// Output type and permissions for HKDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HkdfOutput {
    /// AES-128, permitting encryption and decryption only.
    Aes128,
    /// AES-192, permitting encryption and decryption only.
    Aes192,
    /// AES-256, permitting encryption and decryption only.
    Aes256,
    /// Generic secret permitting only further derivation.
    DerivationSecret {
        /// Output length in bytes, from 1 through 255 times the hash length.
        length: usize,
    },
}
impl HkdfOutput {
    /// Output length in bytes.
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
/// Bounded HKDF request, extracting and expanding by default. No base-key bytes are accepted.
/// All output keys are persistent, private, sensitive and nonextractable.
#[derive(Clone, Copy)]
pub struct HkdfRequest<'a> {
    /// SHA-256, SHA-384 or SHA-512. PKCS#11 requires a hash-length base key.
    pub digest: DigestAlgorithm,
    /// Non-secret extraction salt, at most 4096 bytes. Empty means RFC 5869 zero salt.
    /// Must be empty in expand-only mode.
    pub salt: &'a [u8],
    /// Public protocol context, at most 4096 bytes. Empty is permitted and required
    /// in extract-only mode, where this parameter would otherwise be ignored.
    pub info: &'a [u8],
    /// Output key type, length and permissions.
    pub output: HkdfOutput,
    /// New nonempty CKA_ID, at most 128 bytes; existing secret IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for HkdfRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HkdfRequest")
            .field("digest", &self.digest)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl HkdfRequest<'_> {
    /// Validate an explicit stage without I/O. Extract-only requires a generic
    /// derivation secret of exactly the hash length and no info. Expand-only
    /// requires empty salt. Parameters for disabled stages are rejected.
    pub fn validate_for_mode(&self, mode: HkdfMode) -> Result<(), Error> {
        self.validate()?;
        match mode {
            HkdfMode::ExtractOnly
                if self.output
                    != (HkdfOutput::DerivationSecret {
                        length: self.digest.output_len(),
                    })
                    || !self.info.is_empty() =>
            {
                Err(Error::InvalidParameters(
                    "HKDF extract requires hash-length derivation output and empty info",
                ))
            }
            HkdfMode::ExpandOnly if !self.salt.is_empty() => {
                Err(Error::InvalidParameters("HKDF expand requires empty salt"))
            }
            _ => Ok(()),
        }
    }
    /// Validate a token salt key selection without I/O. The byte salt must be
    /// empty and extraction must be enabled; ignored or conflicting salts fail.
    pub fn validate_with_salt_key(&self, mode: HkdfMode) -> Result<(), Error> {
        self.validate_for_mode(mode)?;
        if mode == HkdfMode::ExpandOnly || !self.salt.is_empty() {
            return Err(Error::InvalidParameters(
                "HKDF salt key requires extraction and empty byte salt",
            ));
        }
        Ok(())
    }
    /// Validate the default extract-and-expand profile without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(
            self.digest,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
        ) {
            return Err(Error::InvalidParameters("HKDF digest"));
        }
        validate_secret_identity(self.id, self.label)?;
        if self.salt.len() > 4096 || self.info.len() > 4096 {
            return Err(Error::InvalidParameters("HKDF salt or info length"));
        }
        if self.output.length() == 0 || self.output.length() > 255 * self.digest.output_len() {
            return Err(Error::InvalidParameters("HKDF output length"));
        }
        Ok(())
    }
}
/// Advisory snapshot; rediscovered before every derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HkdfCapabilities {
    /// Requested hash; actual provider parameter support is checked by C_DeriveKey.
    pub digest: DigestAlgorithm,
    /// Observed base-key length, equal to the hash length under PKCS#11's profile.
    pub input_length: usize,
}
pub(crate) fn secret_length(object: &Object<'_, '_>) -> Result<usize, Error> {
    for (kind, expected) in [
        (
            AttributeType::Class,
            Attribute::Class(ObjectClass::SECRET_KEY),
        ),
        (AttributeType::Derive, Attribute::Derive(true)),
        (AttributeType::Sensitive, Attribute::Sensitive(true)),
        (AttributeType::Extractable, Attribute::Extractable(false)),
    ] {
        if attribute(object, kind, true)? != Some(expected) {
            return Err(Error::UnsupportedKeyOperation);
        }
    }
    if !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::GENERIC_SECRET | KeyType::HKDF))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    let input_length = match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) => usize::from(length),
        _ => return Err(Error::MissingMetadata("HKDF base-key length")),
    };
    Ok(input_length)
}
fn capabilities(object: &Object<'_, '_>) -> Result<HkdfCapabilities, Error> {
    let input_length = secret_length(object)?;
    // PKCS#11 3.2 section 6.62.3 restricts secret-key input to the hash length.
    let digest = match input_length {
        32 => DigestAlgorithm::Sha256,
        48 => DigestAlgorithm::Sha384,
        64 => DigestAlgorithm::Sha512,
        _ => return Err(Error::UnsupportedKeyOperation),
    };
    permits(object, MechanismType::HKDF_DERIVE)?;
    let token = object.session.token();
    if !token.module.raw()?.is_fn_supported(Function::DeriveKey)
        || !token.mechanisms()?.contains(&MechanismType::HKDF_DERIVE)
        || !token.mechanism_info(MechanismType::HKDF_DERIVE)?.derive()
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(HkdfCapabilities {
        digest,
        input_length,
    })
}
pub(crate) fn permits(object: &Object<'_, '_>, mechanism: MechanismType) -> Result<(), Error> {
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(allowed))
            if !allowed.is_empty() && !allowed.contains(&mechanism) =>
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        Some(Attribute::AllowedMechanisms(_)) | None => (),
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
    Ok(())
}
impl Session<'_> {
    /// Discover the SHA-2 HKDF profile permitted by a uniquely selected base.
    /// Reads one object and its metadata once. Unsupported bases/mechanisms produce
    /// no choices; selection, missing metadata and provider errors propagate.
    pub fn hkdf_options(&mut self, base: &ObjectRef) -> Result<Vec<HkdfCapabilities>, Error> {
        match capabilities(&self.resolve(base)?) {
            Ok(profile) => Ok(vec![profile]),
            Err(Error::UnsupportedKeyOperation) => Ok(vec![]),
            Err(error) => Err(error),
        }
    }
    /// Inspect a unique sensitive, nonextractable generic/HKDF secret without reading its value.
    /// Requires CKA_DERIVE, permitted mechanisms and an advertised HKDF derive entry point.
    pub fn hkdf_capabilities(
        &mut self,
        base: &ObjectRef,
        digest: DigestAlgorithm,
    ) -> Result<HkdfCapabilities, Error> {
        if !matches!(
            digest,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
        ) {
            return Err(Error::UnsupportedKeyOperation);
        }
        let profile = capabilities(&self.resolve(base)?)?;
        if profile.digest != digest {
            return Err(Error::UnsupportedKeyOperation);
        }
        Ok(profile)
    }
    /// Perform HKDF extract-and-expand once, creating a persistent private token key.
    /// Requires RW mode and a sensitive, nonextractable hash-length generic/HKDF base.
    /// Never reads key values, emits data objects or falls back to software.
    /// Errors may leave persistent effects; no retry, rollback or base-key deletion occurs.
    pub fn derive_hkdf(
        &mut self,
        base: &ObjectRef,
        request: &HkdfRequest<'_>,
    ) -> Result<(), Error> {
        self.derive_hkdf_with_mode(base, request, HkdfMode::ExtractAndExpand)
    }
    /// Perform the explicitly selected HKDF stage once on the token. Extract-only
    /// creates a sensitive, nonextractable PRK with derivation permission only.
    /// Expand-only assumes the base is a PRK; metadata cannot prove its origin.
    /// Requires RW mode and the existing hash-length generic/HKDF base profile.
    /// Errors may leave persistent effects; no rollback or base-key deletion occurs.
    /// No ignored parameters, software fallback, stage substitution or retry.
    pub fn derive_hkdf_with_mode(
        &mut self,
        base: &ObjectRef,
        request: &HkdfRequest<'_>,
        mode: HkdfMode,
    ) -> Result<(), Error> {
        self.derive_hkdf_inner(base, request, mode, None)
    }
    /// Extract with a persistent token salt key, optionally followed by expansion.
    /// The request's byte salt must be empty; expand-only is rejected. Both keys
    /// are freshly resolved in this session. This application accepts sensitive,
    /// nonextractable generic/HKDF salt keys of 1..=4096 bytes, permitting derivation
    /// and HKDF in CKA_ALLOWED_MECHANISMS. The salt need not be hash-length.
    /// Requires RW mode. No key values, software fallback, retries or rollback;
    /// failure may leave persistent output. Check closure before releasing results.
    pub fn derive_hkdf_with_salt_key(
        &mut self,
        base: &ObjectRef,
        salt_key: &ObjectRef,
        request: &HkdfRequest<'_>,
        mode: HkdfMode,
    ) -> Result<(), Error> {
        self.derive_hkdf_inner(base, request, mode, Some(salt_key))
    }
    fn derive_hkdf_inner(
        &mut self,
        base: &ObjectRef,
        request: &HkdfRequest<'_>,
        mode: HkdfMode,
        salt_key: Option<&ObjectRef>,
    ) -> Result<(), Error> {
        if salt_key.is_some() {
            request.validate_with_salt_key(mode)?;
        } else {
            request.validate_for_mode(mode)?;
        }
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
                .map_err(|_| Error::InvalidParameters("HKDF output length"))?,
        ));
        let base_handle = {
            let object = self.resolve(base)?;
            if capabilities(&object)?.digest != request.digest {
                return Err(Error::UnsupportedKeyOperation);
            }
            object.handle
        };
        let salt_handle = if let Some(reference) = salt_key {
            let object = self.resolve(reference)?;
            if !(1..=4096).contains(&secret_length(&object)?) {
                return Err(Error::UnsupportedKeyOperation);
            }
            permits(&object, MechanismType::HKDF_DERIVE)?;
            Some(object.handle)
        } else {
            None
        };
        let hash = request.digest.mechanism();
        let salt = if let Some(handle) = salt_handle {
            Some(HkdfSalt::Key(handle))
        } else if mode == HkdfMode::ExpandOnly {
            None
        } else if request.salt.is_empty() {
            Some(HkdfSalt::Null)
        } else {
            Some(HkdfSalt::Data(request.salt))
        };
        let info = (mode != HkdfMode::ExtractOnly).then_some(request.info);
        let mechanism = Mechanism::HkdfDerive(HkdfParams::new(hash, salt, info));
        self.write_operation("derive HKDF key", |raw| {
            raw.derive_key(&mechanism, base_handle, &template)
        })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn salt_keys_reject_disabled_or_conflicting_salts_without_io() {
        let request = HkdfRequest {
            digest: DigestAlgorithm::Sha256,
            salt: &[],
            info: &[],
            output: HkdfOutput::DerivationSecret { length: 32 },
            id: b"output",
            label: b"output",
        };
        for mode in [HkdfMode::ExtractOnly, HkdfMode::ExtractAndExpand] {
            request.validate_with_salt_key(mode).unwrap();
            assert!(
                HkdfRequest {
                    salt: b"conflict",
                    ..request
                }
                .validate_with_salt_key(mode)
                .is_err()
            );
        }
        assert!(
            request
                .validate_with_salt_key(HkdfMode::ExpandOnly)
                .is_err()
        );
    }
    #[test]
    fn individual_stages_reject_ignored_inputs_and_non_prk_extraction_outputs() {
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let extract = HkdfRequest {
                digest,
                salt: b"salt",
                info: &[],
                output: HkdfOutput::DerivationSecret {
                    length: digest.output_len(),
                },
                id: b"prk",
                label: b"extracted PRK",
            };
            extract.validate_for_mode(HkdfMode::ExtractOnly).unwrap();
            for output in [
                HkdfOutput::Aes256,
                HkdfOutput::DerivationSecret {
                    length: digest.output_len() - 1,
                },
                HkdfOutput::DerivationSecret {
                    length: digest.output_len() + 1,
                },
            ] {
                assert!(
                    HkdfRequest { output, ..extract }
                        .validate_for_mode(HkdfMode::ExtractOnly)
                        .is_err()
                );
            }
            assert!(
                HkdfRequest {
                    info: b"ignored",
                    ..extract
                }
                .validate_for_mode(HkdfMode::ExtractOnly)
                .is_err()
            );
            assert!(extract.validate_for_mode(HkdfMode::ExpandOnly).is_err());
            HkdfRequest {
                salt: &[],
                info: b"protocol",
                output: HkdfOutput::Aes256,
                ..extract
            }
            .validate_for_mode(HkdfMode::ExpandOnly)
            .unwrap();
            extract
                .validate_for_mode(HkdfMode::ExtractAndExpand)
                .unwrap();
        }
    }
    #[test]
    fn request_bounds_output_permissions_and_debug_are_explicit() {
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let request = HkdfRequest {
                digest,
                salt: b"salt-canary",
                info: b"info-canary",
                output: HkdfOutput::Aes256,
                id: b"id-canary",
                label: b"label-canary",
            };
            request.validate().unwrap();
            assert!(!format!("{request:?}").contains("canary"));
            for length in [0, 255 * digest.output_len() + 1] {
                assert!(
                    HkdfRequest {
                        output: HkdfOutput::DerivationSecret { length },
                        ..request
                    }
                    .validate()
                    .is_err()
                );
            }
            HkdfRequest {
                output: HkdfOutput::DerivationSecret {
                    length: 255 * digest.output_len(),
                },
                salt: &[0; 4096],
                info: &[0; 4096],
                ..request
            }
            .validate()
            .unwrap();
            for bad in [
                HkdfRequest {
                    salt: &[0; 4097],
                    ..request
                },
                HkdfRequest {
                    info: &[0; 4097],
                    ..request
                },
                HkdfRequest { id: b"", ..request },
                HkdfRequest {
                    label: &[0; 129],
                    ..request
                },
            ] {
                assert!(bad.validate().is_err());
            }
        }
        for (output, length, aes) in [
            (HkdfOutput::Aes128, 16, true),
            (HkdfOutput::Aes192, 24, true),
            (HkdfOutput::Aes256, 32, true),
            (HkdfOutput::DerivationSecret { length: 42 }, 42, false),
        ] {
            assert_eq!(output.length(), length);
            assert_eq!(output.aes(), aes);
        }
    }
}
