// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Attribute, AttributeType, Error, MechanismType, Object, ObjectClass, ObjectRef, PrivateKeyRef,
    PublicKeyRef, Session, SessionMode, Token, key_operations::validate_secret_identity,
    signing::attribute,
};
use cryptoki::{
    context::Function,
    mechanism::Mechanism,
    object::{KeyType, MlKemParameterSetType, ParameterSetType},
};

/// FIPS 203 parameter sets. PKCS#11 mechanism bounds use public-key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemParameterSet {
    /// ML-KEM-512 (NIST security category 1).
    MlKem512,
    /// ML-KEM-768 (NIST security category 3).
    MlKem768,
    /// ML-KEM-1024 (NIST security category 5).
    MlKem1024,
}
impl MlKemParameterSet {
    /// Exact encoded encapsulation-key size, in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }
    /// Exact ciphertext size, in bytes. Shared secrets are always 32 bytes.
    pub fn ciphertext_length(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
    fn attribute(self) -> ParameterSetType {
        match self {
            Self::MlKem512 => MlKemParameterSetType::ML_KEM_512,
            Self::MlKem768 => MlKemParameterSetType::ML_KEM_768,
            Self::MlKem1024 => MlKemParameterSetType::ML_KEM_1024,
        }
        .into()
    }
    fn from_attribute(value: ParameterSetType) -> Result<Self, Error> {
        PARAMETERS
            .into_iter()
            .find(|parameter| parameter.attribute() == value)
            .ok_or(Error::UnsupportedKeyOperation)
    }
}
const PARAMETERS: [MlKemParameterSet; 3] = [
    MlKemParameterSet::MlKem512,
    MlKemParameterSet::MlKem768,
    MlKemParameterSet::MlKem1024,
];
/// Direction of an ML-KEM operation; the key class and permission must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemOperation {
    /// Use a public encapsulation key.
    Encapsulate,
    /// Use a private decapsulation key without always-authenticate.
    Decapsulate,
}
/// Advisory snapshot after key, permission, mechanism and entry-point checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlKemCapabilities {
    /// Parameter set observed on the selected key.
    pub parameter_set: MlKemParameterSet,
    /// Permitted direction. Rediscovered before each operation.
    pub operation: MlKemOperation,
}
/// Expected parameter set and identity for a new persistent raw shared secret.
/// Debug omits identity bytes; no private key or shared-secret bytes are accepted.
#[derive(Clone, Copy)]
pub struct MlKemRequest<'a> {
    /// Expected key parameter set; protects against a changed key behind a locator.
    pub parameter_set: MlKemParameterSet,
    /// New nonempty CKA_ID, at most 128 bytes; existing secret IDs are rejected.
    pub id: &'a [u8],
    /// Nonempty CKA_LABEL, at most 128 bytes.
    pub label: &'a [u8],
}
impl std::fmt::Debug for MlKemRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKemRequest")
            .field("parameter_set", &self.parameter_set)
            .finish_non_exhaustive()
    }
}
impl MlKemRequest<'_> {
    /// Check identity bounds without contacting a provider.
    pub fn validate(&self) -> Result<(), Error> {
        validate_secret_identity(self.id, self.label)
    }
}
fn capabilities(
    object: &Object<'_, '_>,
    operation: MlKemOperation,
) -> Result<MlKemCapabilities, Error> {
    let (class, permission, function) = match operation {
        MlKemOperation::Encapsulate => (
            ObjectClass::PUBLIC_KEY,
            AttributeType::Encapsulate,
            Function::EncapsulateKey,
        ),
        MlKemOperation::Decapsulate => (
            ObjectClass::PRIVATE_KEY,
            AttributeType::Decapsulate,
            Function::DecapsulateKey,
        ),
    };
    if !matches!(attribute(object,AttributeType::Class,true)?,Some(Attribute::Class(value)) if value==class)
        || !matches!(
            attribute(object, AttributeType::KeyType, true)?,
            Some(Attribute::KeyType(KeyType::ML_KEM))
        )
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    let parameter_set = match attribute(object, AttributeType::ParameterSet, true)? {
        Some(Attribute::ParameterSet(value)) => MlKemParameterSet::from_attribute(value)?,
        _ => return Err(Error::MissingMetadata("ML-KEM parameter set")),
    };
    if !matches!(
        attribute(object, permission, true)?,
        Some(Attribute::Encapsulate(true) | Attribute::Decapsulate(true))
    ) {
        return Err(Error::UnsupportedKeyOperation);
    }
    if operation == MlKemOperation::Decapsulate
        && !matches!(
            attribute(object, AttributeType::AlwaysAuthenticate, true)?,
            Some(Attribute::AlwaysAuthenticate(false))
        )
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    match attribute(object, AttributeType::AllowedMechanisms, false)? {
        Some(Attribute::AllowedMechanisms(allowed))
            if !allowed.is_empty() && !allowed.contains(&MechanismType::ML_KEM) =>
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        Some(Attribute::AllowedMechanisms(_)) | None => (),
        _ => return Err(Error::MissingMetadata("CKA_ALLOWED_MECHANISMS")),
    }
    let token = object.session.token();
    if !token.module.raw()?.is_fn_supported(function)
        || !token.mechanisms()?.contains(&MechanismType::ML_KEM)
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    let info = token.mechanism_info(MechanismType::ML_KEM)?;
    if !(info.min_key_size()..=info.max_key_size()).contains(&parameter_set.public_key_length())
        || !match operation {
            MlKemOperation::Encapsulate => info.encapsulate(),
            MlKemOperation::Decapsulate => info.decapsulate(),
        }
    {
        return Err(Error::UnsupportedKeyOperation);
    }
    Ok(MlKemCapabilities {
        parameter_set,
        operation,
    })
}
impl Token<'_> {
    /// Advertised parameter sets; does not prove that a provider accepts a template.
    pub fn ml_kem_generation_options(&self) -> Result<Vec<MlKemParameterSet>, Error> {
        if !self
            .module
            .raw()?
            .is_fn_supported(Function::GenerateKeyPair)
            || !self
                .mechanisms()?
                .contains(&MechanismType::ML_KEM_KEY_PAIR_GEN)
        {
            return Ok(vec![]);
        }
        let info = self.mechanism_info(MechanismType::ML_KEM_KEY_PAIR_GEN)?;
        Ok(PARAMETERS
            .into_iter()
            .filter(|p| {
                info.generate_key_pair()
                    && (info.min_key_size()..=info.max_key_size()).contains(&p.public_key_length())
            })
            .collect())
    }
}
impl<'m> Session<'m> {
    /// Generate one persistent ML-KEM pair; the private key is sensitive and
    /// nonextractable. Requires RW mode. Duplicate IDs remain possible, as with
    /// signing-key generation; later selection requires exactly one match.
    /// No private seed is imported or read, and failures are not retried.
    pub fn generate_ml_kem_key_pair(
        &mut self,
        parameter: MlKemParameterSet,
        id: &[u8],
        label: &[u8],
    ) -> Result<(Object<'_, 'm>, Object<'_, 'm>), Error> {
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        if id.is_empty() {
            return Err(Error::InvalidParameters("key ID must not be empty"));
        }
        if !self
            .token()
            .ml_kem_generation_options()?
            .contains(&parameter)
        {
            return Err(Error::UnsupportedKeyOperation);
        }
        let public = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Encapsulate(true),
            Attribute::ParameterSet(parameter.attribute()),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.to_vec()),
            Attribute::Decapsulate(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::AlwaysAuthenticate(false),
        ];
        let (public, private) = self.write_operation("generate ML-KEM key pair", |raw| {
            raw.generate_key_pair(&Mechanism::MlKemKeyPairGen, &public, &private)
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
    /// Discover current class, parameters, permissions, flags and required entry point.
    /// Always-authenticate decapsulation is unsupported by this single-call profile.
    pub fn ml_kem_capabilities(
        &mut self,
        key: &ObjectRef,
        operation: MlKemOperation,
    ) -> Result<MlKemCapabilities, Error> {
        capabilities(&self.resolve(key)?, operation)
    }
    fn ml_kem_secret_template(
        &mut self,
        request: &MlKemRequest<'_>,
    ) -> Result<Vec<Attribute>, Error> {
        request.validate()?;
        self.validate()?;
        if self.mode != SessionMode::ReadWrite {
            return Err(Error::ReadWriteRequired);
        }
        let mut template = self.new_secret_template(request.id, request.label, false)?;
        template.push(Attribute::ValueLen(32.into()));
        Ok(template)
    }
    /// Encapsulate once and return only the public ciphertext. Creates a persistent
    /// private, sensitive, nonextractable 32-byte generic secret permitting only
    /// further derivation. Requires RW mode; no software fallback or retry.
    /// Even failure can leave persistent effects. Authenticate the peer separately
    /// and apply a protocol KDF before using the raw secret as key material.
    pub fn encapsulate_ml_kem(
        &mut self,
        key: &PublicKeyRef,
        request: &MlKemRequest<'_>,
    ) -> Result<Vec<u8>, Error> {
        let template = self.ml_kem_secret_template(request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, MlKemOperation::Encapsulate)?;
        if caps.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedKeyOperation);
        }
        let (ciphertext, _) = object
            .session
            .write_operation("encapsulate ML-KEM secret", |raw| {
                raw.encapsulate_key(&Mechanism::MlKem, object.handle, &template)
            })?;
        if ciphertext.len() != request.parameter_set.ciphertext_length() {
            self.healthy.set(false);
            return Err(Error::InvalidKeyOutput);
        }
        Ok(ciphertext)
    }
    /// Decapsulate once into a new token-held generic secret with the same
    /// restrictions as encapsulation. The ciphertext must have the exact length.
    /// ML-KEM implicit rejection means a changed same-length ciphertext can succeed
    /// with a different secret; success does not establish peer authentication.
    pub fn decapsulate_ml_kem(
        &mut self,
        key: &PrivateKeyRef,
        request: &MlKemRequest<'_>,
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        request.validate()?;
        if ciphertext.len() != request.parameter_set.ciphertext_length() {
            return Err(Error::InvalidParameters("ML-KEM ciphertext length"));
        }
        let template = self.ml_kem_secret_template(request)?;
        let object = self.resolve(key.as_object_ref())?;
        let caps = capabilities(&object, MlKemOperation::Decapsulate)?;
        if caps.parameter_set != request.parameter_set {
            return Err(Error::UnsupportedKeyOperation);
        }
        object
            .session
            .write_operation("decapsulate ML-KEM secret", |raw| {
                raw.decapsulate_key(&Mechanism::MlKem, object.handle, &template, ciphertext)
            })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parameters_and_identity_bounds_are_explicit() {
        for (parameter, public, ciphertext) in [
            (MlKemParameterSet::MlKem512, 800, 768),
            (MlKemParameterSet::MlKem768, 1184, 1088),
            (MlKemParameterSet::MlKem1024, 1568, 1568),
        ] {
            assert_eq!(parameter.public_key_length(), public);
            assert_eq!(parameter.ciphertext_length(), ciphertext);
            assert_eq!(
                MlKemParameterSet::from_attribute(parameter.attribute()).unwrap(),
                parameter
            );
            let request = MlKemRequest {
                parameter_set: parameter,
                id: b"identifier-canary",
                label: b"label-canary",
            };
            request.validate().unwrap();
            assert!(!format!("{request:?}").contains("canary"));
            for (id, label) in [
                (b"".as_slice(), b"label".as_slice()),
                (b"id".as_slice(), b"".as_slice()),
                (&[0; 129], b"label".as_slice()),
                (b"id".as_slice(), &[0; 129]),
            ] {
                assert!(matches!(
                    MlKemRequest {
                        id,
                        label,
                        ..request
                    }
                    .validate(),
                    Err(Error::InvalidParameters(_))
                ));
            }
            MlKemRequest {
                id: &[0; 128],
                label: &[0; 128],
                ..request
            }
            .validate()
            .unwrap();
        }
    }
}
