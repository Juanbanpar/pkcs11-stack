// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, KeyKind, MechanismType, NamedCurve, ObjectClass, ObjectRef,
    Session,
    error::backend,
    signing::{attribute, key_kind},
};
use cryptoki::{mechanism::Mechanism, object::KeyType};

/// Explicit AES key-wrap algorithm; no automatic substitution is performed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AesKeyWrapAlgorithm {
    /// RFC 3394, using the default 8-byte IV.
    #[default]
    Kw,
    /// RFC 5649, using CKM_AES_KEY_WRAP_KWP and its default alternative IV.
    Kwp,
}
impl std::fmt::Display for AesKeyWrapAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Kw => "AES-KW (RFC 3394)",
            Self::Kwp => "AES-KWP (RFC 5649)",
        })
    }
}
impl AesKeyWrapAlgorithm {
    fn mechanism(self) -> Mechanism<'static> {
        match self {
            Self::Kw => Mechanism::AesKeyWrap,
            Self::Kwp => Mechanism::AesKeyWrapKwp,
        }
    }
}
/// Advisory wrapping-key size and supported algorithms after permission checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesKeyWrapCapabilities {
    /// AES wrapping/unwrapping key length, in bytes.
    pub key_length: usize,
    /// RFC 3394 is advertised and permitted for this key and operation.
    pub kw: bool,
    /// RFC 5649 is advertised and permitted for this key and operation.
    pub kwp: bool,
}
impl AesKeyWrapCapabilities {
    /// Whether the selected algorithm was permitted when queried; execution rechecks.
    pub fn supports(self, algorithm: AesKeyWrapAlgorithm) -> bool {
        match algorithm {
            AesKeyWrapAlgorithm::Kw => self.kw,
            AesKeyWrapAlgorithm::Kwp => self.kwp,
        }
    }
}

/// Supported token key derivation and transfer operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOperation {
    /// ECDH with an explicitly selected KDF and token-held output.
    Derive,
    /// RFC 3394 AES key wrap, with the default IV.
    Wrap,
    /// RFC 3394 AES key unwrap, creating a private nonextractable AES key.
    Unwrap,
}
/// Advisory profile after current class, permission and mechanism checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOperationProfile {
    /// ECDH base on this curve; individual KDF parameter support is checked on use.
    EcdhRaw(NamedCurve),
    /// RFC 3394 using an AES wrapping key of this length in bytes.
    AesKeyWrap(usize),
}
/// Explicit parameters for raw ECDH generic-secret creation. Debug omits all input.
pub struct EcdhDerivation<'a> {
    /// Named curve shared by base and peer keys.
    pub curve: NamedCurve,
    /// Validated uncompressed SEC1 peer point.
    pub peer: &'a [u8],
    /// New nonempty secret key ID, bounded to 128 bytes.
    pub id: &'a [u8],
    /// New nonempty label, bounded to 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for EcdhDerivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdhDerivation([REDACTED])")
    }
}
fn enabled(object: &crate::Object<'_, '_>, kind: AttributeType) -> Result<bool, Error> {
    Ok(matches!(
        attribute(object, kind, true)?,
        Some(
            Attribute::Derive(true)
                | Attribute::Wrap(true)
                | Attribute::Unwrap(true)
                | Attribute::Extractable(true)
                | Attribute::Trusted(true)
        )
    ))
}
fn aes_length(object: &crate::Object<'_, '_>) -> Result<usize, Error> {
    if !matches!(
        attribute(object, AttributeType::Class, true)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    ) || !matches!(
        attribute(object, AttributeType::KeyType, true)?,
        Some(Attribute::KeyType(KeyType::AES))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    match attribute(object, AttributeType::ValueLen, true)? {
        Some(Attribute::ValueLen(length)) if [16, 24, 32].contains(&usize::from(length)) => {
            Ok(usize::from(length))
        }
        _ => Err(Error::UnsupportedKeyOperation),
    }
}
pub(crate) fn profile(
    object: &crate::Object<'_, '_>,
    operation: KeyOperation,
) -> Result<KeyOperationProfile, Error> {
    profile_with_algorithm(object, operation, AesKeyWrapAlgorithm::Kw)
}
fn profile_with_algorithm(
    object: &crate::Object<'_, '_>,
    operation: KeyOperation,
    algorithm: AesKeyWrapAlgorithm,
) -> Result<KeyOperationProfile, Error> {
    let (permission, mechanism) = match operation {
        KeyOperation::Derive => (AttributeType::Derive, MechanismType::ECDH1_DERIVE),
        KeyOperation::Wrap => (AttributeType::Wrap, algorithm.mechanism().mechanism_type()),
        KeyOperation::Unwrap => (
            AttributeType::Unwrap,
            algorithm.mechanism().mechanism_type(),
        ),
    };
    if !enabled(object, permission)? {
        return Err(Error::UnsupportedKeyOperation);
    }
    let (result, bits) = if operation == KeyOperation::Derive {
        if !matches!(
            attribute(object, AttributeType::Class, true)?,
            Some(Attribute::Class(ObjectClass::PRIVATE_KEY))
        ) || !matches!(
            attribute(object, AttributeType::AlwaysAuthenticate, true)?,
            Some(Attribute::AlwaysAuthenticate(false))
        ) {
            return Err(Error::UnsupportedKeyOperation);
        }
        let KeyKind::Ec(curve) = key_kind(object)? else {
            return Err(Error::UnsupportedKeyOperation);
        };
        (
            KeyOperationProfile::EcdhRaw(curve),
            match curve {
                NamedCurve::P256 => 256,
                NamedCurve::P384 => 384,
                NamedCurve::P521 => 521,
            },
        )
    } else {
        let length = aes_length(object)?;
        (KeyOperationProfile::AesKeyWrap(length), length * 8)
    };
    if let Some(Attribute::AllowedMechanisms(allowed)) =
        attribute(object, AttributeType::AllowedMechanisms, false)?
    {
        if !allowed.is_empty() && !allowed.contains(&mechanism) {
            return Err(Error::UnsupportedKeyOperation);
        }
    }
    let token = object.session.token();
    let function = match operation {
        KeyOperation::Derive => crate::Function::DeriveKey,
        KeyOperation::Wrap => crate::Function::WrapKey,
        KeyOperation::Unwrap => crate::Function::UnwrapKey,
    };
    if !token.module.raw()?.is_fn_supported(function) {
        return Err(Error::UnsupportedKeyOperation);
    }
    if !token.mechanisms()?.contains(&mechanism) {
        return Err(Error::UnsupportedKeyOperation);
    }
    let info = token.mechanism_info(mechanism)?;
    // PKCS#11 specifies AES mechanism bounds in bytes and EC bounds in bits.
    let size = if operation == KeyOperation::Derive {
        bits
    } else {
        bits / 8
    };
    if size < info.min_key_size()
        || size > info.max_key_size()
        || !match operation {
            KeyOperation::Derive => info.derive(),
            KeyOperation::Wrap => info.wrap(),
            KeyOperation::Unwrap => info.unwrap(),
        }
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(result)
}
pub(crate) fn validate_secret_identity(id: &[u8], label: &[u8]) -> Result<(), Error> {
    if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
        return Err(Error::InvalidParameters("secret key identity"));
    }
    Ok(())
}
fn identity_template(id: &[u8], label: &[u8], aes: bool) -> Result<Vec<Attribute>, Error> {
    validate_secret_identity(id, label)?;
    Ok(vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(if aes {
            KeyType::AES
        } else {
            KeyType::GENERIC_SECRET
        }),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.to_vec()),
        Attribute::Encrypt(aes),
        Attribute::Decrypt(aes),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Derive(!aes),
    ])
}
impl Session<'_> {
    /// Inspect KW and KWP independently for Wrap or Unwrap, without performing
    /// crypto. Unsupported algorithms are omitted; metadata/backend errors propagate.
    /// Derive is rejected. This does not inspect a future target or unwrap template.
    pub fn aes_key_wrap_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<AesKeyWrapCapabilities, Error> {
        if operation == KeyOperation::Derive {
            return Err(Error::InvalidParameters("AES wrap direction"));
        }
        let object = self.resolve(key)?;
        let key_length = aes_length(&object)?;
        let permitted = |algorithm| match profile_with_algorithm(&object, operation, algorithm) {
            Ok(_) => Ok(true),
            Err(Error::UnsupportedKeyOperation) => Ok(false),
            Err(error) => Err(error),
        };
        let kw = permitted(AesKeyWrapAlgorithm::Kw)?;
        let kwp = permitted(AesKeyWrapAlgorithm::Kwp)?;
        if !kw && !kwp {
            return Err(Error::UnsupportedKeyOperation);
        }
        Ok(AesKeyWrapCapabilities {
            key_length,
            kw,
            kwp,
        })
    }
    /// Inspect a uniquely resolved key. Advertised KDF/profile support is advisory.
    pub fn key_operation_profile(
        &mut self,
        key: &ObjectRef,
        operation: KeyOperation,
    ) -> Result<KeyOperationProfile, Error> {
        profile(&self.resolve(key)?, operation)
    }
    pub(crate) fn new_secret_template(
        &mut self,
        id: &[u8],
        label: &[u8],
        aes: bool,
    ) -> Result<Vec<Attribute>, Error> {
        let template = identity_template(id, label, aes)?;
        if !self
            .find_objects(&[
                Attribute::Token(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Id(id.to_vec()),
            ])?
            .is_empty()
        {
            return Err(Error::InvalidParameters("secret key ID already exists"));
        }
        Ok(template)
    }
    /// Derive a persistent raw ECDH generic secret using the explicitly selected null KDF.
    /// Encryption, decryption and transfer permissions are disabled; only derivation is allowed.
    /// The caller must validate the peer point on the selected curve before calling.
    /// No key bytes leave the provider. Failures can have persistent effects; no retry.
    pub fn derive_ecdh_secret(
        &mut self,
        base: &ObjectRef,
        request: &EcdhDerivation<'_>,
    ) -> Result<(), Error> {
        self.derive_ecdh_key(
            base,
            &crate::EcdhKeyRequest {
                curve: request.curve,
                peer: request.peer,
                kdf: crate::EcdhKdf::Null,
                shared_info: &[],
                output: crate::EcdhOutput::RawSecret,
                id: request.id,
                label: request.label,
            },
        )
    }

    /// Wrap an extractable AES-128/192/256 key using RFC 3394. Never reads CKA_VALUE.
    /// CKA_WRAP_WITH_TRUSTED is honored; provider wrap templates remain authoritative.
    pub fn wrap_aes_key(
        &mut self,
        wrapping: &ObjectRef,
        target: &ObjectRef,
    ) -> Result<Vec<u8>, Error> {
        self.wrap_aes_key_with_algorithm(wrapping, target, AesKeyWrapAlgorithm::Kw)
    }
    /// Wrap one extractable AES-128/192/256 key with the explicitly selected KW
    /// or KWP algorithm and default IV. Never reads CKA_VALUE or changes policy.
    pub fn wrap_aes_key_with_algorithm(
        &mut self,
        wrapping: &ObjectRef,
        target: &ObjectRef,
        algorithm: AesKeyWrapAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let (wrapping_handle, trusted) = {
            let object = self.resolve(wrapping)?;
            profile_with_algorithm(&object, KeyOperation::Wrap, algorithm)?;
            (
                object.handle,
                matches!(
                    attribute(&object, AttributeType::Trusted, false)?,
                    Some(Attribute::Trusted(true))
                ),
            )
        };
        let target = self.resolve(target)?;
        let size = aes_length(&target)?;
        if wrapping_handle == target.handle || !enabled(&target, AttributeType::Extractable)? {
            return Err(Error::UnsupportedKeyOperation);
        }
        // Unknown trust policy fails closed instead of guessing its default.
        match attribute(&target, AttributeType::WrapWithTrusted, true)? {
            Some(Attribute::WrapWithTrusted(false)) => (),
            Some(Attribute::WrapWithTrusted(true)) if trusted => (),
            _ => return Err(Error::UnsupportedKeyOperation),
        }
        let target_handle = target.handle;
        let raw = self.raw()?;
        self.healthy.set(false);
        let bytes = raw
            .wrap_key(&algorithm.mechanism(), wrapping_handle, target_handle)
            .map_err(|e| backend("wrap AES key", e))?;
        if bytes.len() != size + 8 {
            return Err(Error::InvalidKeyOutput);
        }
        self.healthy.set(true);
        Ok(bytes)
    }
    /// Unwrap one RFC 3394 AES blob as a sensitive nonextractable token key.
    /// The ciphertext length determines AES-128/192/256. No metadata is encoded in it.
    pub fn unwrap_aes_key(
        &mut self,
        unwrapping: &ObjectRef,
        wrapped: &[u8],
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.unwrap_aes_key_with_algorithm(unwrapping, wrapped, id, label, AesKeyWrapAlgorithm::Kw)
    }
    /// Unwrap a KW or KWP blob into a persistent private, sensitive,
    /// nonextractable AES key, restricted to encryption/decryption. Only AES
    /// 128/192/256 is supported. Ciphertext carries no application metadata.
    /// RW access is required; no retry, algorithm fallback or rollback occurs.
    pub fn unwrap_aes_key_with_algorithm(
        &mut self,
        unwrapping: &ObjectRef,
        wrapped: &[u8],
        id: &[u8],
        label: &[u8],
        algorithm: AesKeyWrapAlgorithm,
    ) -> Result<(), Error> {
        if ![24, 32, 40].contains(&wrapped.len()) {
            return Err(Error::InvalidParameters("AES wrapped input length"));
        }
        let template = self.new_secret_template(id, label, true)?;
        let object = self.resolve(unwrapping)?;
        profile_with_algorithm(&object, KeyOperation::Unwrap, algorithm)?;
        object.session.write_operation("unwrap AES key", |raw| {
            raw.unwrap_key(&algorithm.mechanism(), object.handle, wrapped, &template)
        })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_template_never_grants_extractability_or_transfer_permissions() {
        let attrs = identity_template(b"id", b"key", true).unwrap();
        for attr in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Private(true),
            Attribute::Token(true),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
        ] {
            assert!(attrs.contains(&attr));
        }
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Value(_))));
        let material = identity_template(b"id", b"material", false).unwrap();
        for attr in [
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
        ] {
            assert!(material.contains(&attr));
        }
        assert!(identity_template(b"", b"key", true).is_err());
        assert!(identity_template(b"id", &[0; 129], true).is_err());
    }
}
