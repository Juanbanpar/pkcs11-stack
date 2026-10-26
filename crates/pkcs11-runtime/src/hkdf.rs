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

/// Output type and permissions for HKDF extract-and-expand.
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
/// Bounded HKDF extract-and-expand request. No base-key bytes are accepted.
/// All output keys are persistent, private, sensitive and nonextractable.
#[derive(Clone, Copy)]
pub struct HkdfRequest<'a> {
    /// SHA-256, SHA-384 or SHA-512. PKCS#11 requires a hash-length base key.
    pub digest: DigestAlgorithm,
    /// Non-secret extraction salt, at most 4096 bytes. Empty means RFC 5869 zero salt.
    pub salt: &'a [u8],
    /// Public protocol context, at most 4096 bytes. Empty is permitted.
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
    /// Validate bounds before contacting a provider. Always extracts and expands.
    pub fn validate(&self) -> Result<(), Error> {
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
        request.validate()?;
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
        let object = self.resolve(base)?;
        if capabilities(&object)?.digest != request.digest {
            return Err(Error::UnsupportedKeyOperation);
        }
        let hash = match request.digest {
            DigestAlgorithm::Sha256 => MechanismType::SHA256,
            DigestAlgorithm::Sha384 => MechanismType::SHA384,
            DigestAlgorithm::Sha512 => MechanismType::SHA512,
        };
        let salt = if request.salt.is_empty() {
            HkdfSalt::Null
        } else {
            HkdfSalt::Data(request.salt)
        };
        let mechanism =
            Mechanism::HkdfDerive(HkdfParams::new(hash, Some(salt), Some(request.info)));
        object.session.write_operation("derive HKDF key", |raw| {
            raw.derive_key(&mechanism, object.handle, &template)
        })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
