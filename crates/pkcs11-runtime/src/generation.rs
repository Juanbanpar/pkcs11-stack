// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, Error, MechanismType, NamedCurve, Object, ObjectClass, Session, SessionMode, Token,
    key_operations::validate_secret_identity,
};
use cryptoki::{context::Function, mechanism::Mechanism};

/// AES key size, independent of the mechanism's byte-based metadata bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesKeySize {
    /// AES-128.
    Bits128,
    /// AES-192.
    Bits192,
    /// AES-256.
    Bits256,
}
impl AesKeySize {
    /// Length in bytes, as required by CKA_VALUE_LEN and AES generation bounds.
    pub fn length(self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits192 => 24,
            Self::Bits256 => 32,
        }
    }
}
/// Mutually exclusive permissions for a generated AES key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesKeyPurpose {
    /// Encryption/decryption only; mode support is checked by the consuming operation.
    Encryption,
    /// Wrapping/unwrapping only; mechanism support is checked by the consuming operation.
    Wrapping,
}
/// Generate a persistent EC pair for derivation, with no signing permission.
#[derive(Clone, Copy)]
pub struct EcdhKeyPairRequest<'a> {
    /// Named curve; advertised support remains advisory until generation succeeds.
    pub curve: NamedCurve,
    /// Shared nonempty CKA_ID, at most 128 bytes. Existing key-pair IDs are rejected.
    pub id: &'a [u8],
    /// Shared nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}
impl EcdhKeyPairRequest<'_> {
    /// Validate identity bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for EcdhKeyPairRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhKeyPairRequest")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}
/// Generate a persistent private, sensitive, nonextractable AES key.
#[derive(Clone, Copy)]
pub struct AesKeyRequest<'a> {
    /// AES key size.
    pub size: AesKeySize,
    /// Only the selected pair of operation permissions will be enabled.
    pub purpose: AesKeyPurpose,
    /// Nonempty CKA_ID, at most 128 bytes. Existing secret IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}
impl AesKeyRequest<'_> {
    /// Validate identity bounds without I/O.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
impl std::fmt::Debug for AesKeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesKeyRequest")
            .field("size", &self.size)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}
pub(crate) fn curve_parameters(curve: NamedCurve) -> Vec<u8> {
    match curve {
        NamedCurve::P256 => vec![6, 8, 42, 134, 72, 206, 61, 3, 1, 7],
        NamedCurve::P384 => vec![6, 5, 43, 129, 4, 0, 34],
        NamedCurve::P521 => vec![6, 5, 43, 129, 4, 0, 35],
    }
}
fn curves(enabled: bool, minimum: usize, maximum: usize) -> Vec<NamedCurve> {
    [NamedCurve::P256, NamedCurve::P384, NamedCurve::P521]
        .into_iter()
        .filter(|curve| enabled && (minimum..=maximum).contains(&curve.bits()))
        .collect()
}
fn sizes(enabled: bool, minimum: usize, maximum: usize) -> Vec<AesKeySize> {
    [
        AesKeySize::Bits128,
        AesKeySize::Bits192,
        AesKeySize::Bits256,
    ]
    .into_iter()
    .filter(|size| enabled && (minimum..=maximum).contains(&size.length()))
    .collect()
}
impl Token<'_> {
    /// Advertised EC pair generation choices in bits, with a GenerateKeyPair entry point.
    /// Does not guarantee curve/template acceptance or support for a later ECDH operation.
    pub fn ecdh_generation_options(&self) -> Result<Vec<NamedCurve>, Error> {
        if !self
            .module
            .raw()?
            .is_fn_supported(Function::GenerateKeyPair)
            || !self
                .mechanisms()?
                .contains(&MechanismType::ECC_KEY_PAIR_GEN)
        {
            return Ok(vec![]);
        }
        let info = self.mechanism_info(MechanismType::ECC_KEY_PAIR_GEN)?;
        Ok(curves(
            info.generate_key_pair(),
            info.min_key_size(),
            info.max_key_size(),
        ))
    }
    /// Advertised AES generation sizes in bytes, with a GenerateKey entry point.
    /// Does not guarantee template acceptance or encryption/wrapping mode support.
    pub fn aes_generation_options(&self) -> Result<Vec<AesKeySize>, Error> {
        if !self.module.raw()?.is_fn_supported(Function::GenerateKey)
            || !self.mechanisms()?.contains(&MechanismType::AES_KEY_GEN)
        {
            return Ok(vec![]);
        }
        let info = self.mechanism_info(MechanismType::AES_KEY_GEN)?;
        Ok(sizes(
            info.generate(),
            info.min_key_size(),
            info.max_key_size(),
        ))
    }
}
impl<'m> Session<'m> {
    /// Generate one persistent derivation pair in an RW session. The public key is
    /// public; the private key is sensitive/nonextractable and permits only derivation.
    /// Per-operation authentication is disabled; this binding cannot interleave it
    /// with ECDH. Both objects share a bounded ID/label. Existing public/private key
    /// IDs are checked before generation, without uniqueness against concurrent writers.
    /// Capabilities are rechecked. No values leave the token, no retry/rollback occurs,
    /// and provider failure can leave persistent objects. Check session closure.
    pub fn generate_ecdh_key_pair(
        &mut self,
        request: &EcdhKeyPairRequest<'_>,
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self
            .token()
            .ecdh_generation_options()?
            .contains(&request.curve)
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
            if !self
                .find_objects(&[
                    Attribute::Token(true),
                    Attribute::Class(class),
                    Attribute::Id(request.id.to_vec()),
                ])?
                .is_empty()
            {
                return Err(Error::InvalidParameters("key pair ID already exists"));
            }
        }
        let public = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(request.id.to_vec()),
            Attribute::Label(request.label.to_vec()),
            Attribute::EcParams(curve_parameters(request.curve)),
            Attribute::Verify(false),
            Attribute::VerifyRecover(false),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(request.id.to_vec()),
            Attribute::Label(request.label.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Sign(false),
            Attribute::SignRecover(false),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::AlwaysAuthenticate(false),
        ];
        let (public, private) = self.write_operation("generate ECDH key pair", |raw| {
            raw.generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
        })?;
        Ok((
            Object {
                session: self,
                handle: public,
            },
            Object {
                session: self,
                handle: private,
            },
        ))
    }
    /// Generate one private, sensitive, nonextractable AES key in an RW session.
    /// Only encryption/decryption or wrapping/unwrapping is enabled; derivation,
    /// signing and verification are disabled. No extractability/trust override is
    /// accepted. A wrapping key does not make nonextractable targets exportable.
    /// Capabilities and duplicate secret IDs are rechecked before the provider call.
    /// This is not transactional with concurrent writers. No key bytes are read,
    /// no retry/rollback occurs, and failures may leave objects. Check session closure.
    pub fn generate_aes_key(
        &mut self,
        request: &AesKeyRequest<'_>,
    ) -> Result<Object<'_, 'm>, Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if !self
            .token()
            .aes_generation_options()?
            .contains(&request.size)
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        let mut template = self.new_secret_template(request.id, request.label, true)?;
        let encryption = request.purpose == AesKeyPurpose::Encryption;
        for attr in &mut template {
            match attr {
                Attribute::Encrypt(value) | Attribute::Decrypt(value) => *value = encryption,
                Attribute::Wrap(value) | Attribute::Unwrap(value) => *value = !encryption,
                _ => {}
            }
        }
        template.push(Attribute::ValueLen(
            request
                .size
                .length()
                .try_into()
                .map_err(|_| Error::InvalidParameters("AES key length"))?,
        ));
        let handle = self.write_operation("generate AES key", |raw| {
            raw.generate_key(&Mechanism::AesKeyGen, &template)
        })?;
        Ok(Object {
            session: self,
            handle,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_uses_bits_for_ec_and_bytes_for_aes_and_requires_flags() {
        assert_eq!(
            curves(true, 384, 521),
            vec![NamedCurve::P384, NamedCurve::P521]
        );
        assert_eq!(
            sizes(true, 24, 32),
            vec![AesKeySize::Bits192, AesKeySize::Bits256]
        );
        assert!(curves(false, 0, 521).is_empty());
        assert!(sizes(false, 0, 32).is_empty());
        assert!(curves(true, 521, 256).is_empty());
        assert!(sizes(true, 32, 16).is_empty());
        assert!(sizes(true, 128, 256).is_empty());
    }
    #[test]
    fn generation_identity_is_bounded_and_debug_omits_buffers() {
        let ec = EcdhKeyPairRequest {
            curve: NamedCurve::P256,
            id: b"identity-canary",
            label: b"label-canary",
        };
        let aes = AesKeyRequest {
            size: AesKeySize::Bits256,
            purpose: AesKeyPurpose::Wrapping,
            id: ec.id,
            label: ec.label,
        };
        assert!(ec.validate().is_ok());
        assert!(aes.validate().is_ok());
        for text in [format!("{ec:?}"), format!("{aes:?}")] {
            assert!(!text.contains("canary"));
        }
        for (id, label) in [
            (&[][..], b"label".as_slice()),
            (b"id".as_slice(), &[][..]),
            (&[0; 129][..], b"label".as_slice()),
            (b"id".as_slice(), &[0; 129][..]),
        ] {
            assert!(EcdhKeyPairRequest { id, label, ..ec }.validate().is_err());
            assert!(AesKeyRequest { id, label, ..aes }.validate().is_err());
        }
        assert!(
            EcdhKeyPairRequest {
                id: &[0; 128],
                label: &[0; 128],
                ..ec
            }
            .validate()
            .is_ok()
        );
    }
}
