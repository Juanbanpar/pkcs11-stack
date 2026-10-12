// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{CertificateDocument, Client, Error, Pkcs11Uri, SigningPolicy};
use pkcs11_runtime::{
    Attribute, AttributeInfo, AttributeType, AttributeValues, Authentication, CertificateType,
    KeyKind, LibraryInfo, MechanismInfo, MechanismType, Module, Object, ObjectClass, ObjectRef,
    Session, SessionMode, SessionPool, SessionState, SlotInfo, TokenInfo,
};
use secrecy::{ExposeSecret, SecretString};
use std::{num::NonZeroUsize, path::Path, sync::Arc};

/// Explicit owner of one trusted module, shared by signing and management workflows.
/// Close borrowed and owned consumers before finalization or token initialization.
#[derive(Debug)]
pub struct Provider {
    module: Arc<Module>,
}
/// Discovery metadata; a slot ID is diagnostic, not persistent token identity.
#[derive(Debug)]
pub struct SlotSnapshot {
    /// Current provider slot ID.
    pub id: u64,
    /// Provider slot metadata.
    pub info: SlotInfo,
}
/// Token metadata without a live session or object handle.
#[derive(Debug)]
pub struct TokenSnapshot {
    /// Current provider slot ID.
    pub slot_id: u64,
    /// Token metadata snapshot.
    pub info: TokenInfo,
}
impl TokenSnapshot {
    /// Construct stable token criteria from all four token identity fields.
    /// Identical metadata can still be ambiguous; resolution never picks arbitrarily.
    pub fn uri(&self) -> Result<Pkcs11Uri, Error> {
        metadata_uri(&self.info)
    }
}
/// Advertised mechanism and its provider flags/bounds, without a signing decision.
#[derive(Debug)]
pub struct MechanismSnapshot {
    /// PKCS#11 mechanism identifier.
    pub mechanism: MechanismType,
    /// Advertised mechanism properties.
    pub info: MechanismInfo,
}
/// Results of an explicit pool-capacity and reuse diagnostic.
#[derive(Debug)]
pub struct PoolDiagnostic {
    /// Requested concurrent capacity.
    pub capacity: usize,
    /// An additional checkout was rejected while all leases were held.
    pub exhaustion_verified: bool,
    /// Returned leases could be checked out and queried again.
    pub reuse_verified: bool,
    /// Authentication state observed on the first lease.
    pub session_state: SessionState,
}
impl Provider {
    /// Common RSA sizes and named curves within advertised key-generation bounds.
    /// These are advisory choices, not a guarantee that a vendor accepts a template.
    pub fn generation_options(&self, uri: &Pkcs11Uri) -> Result<Vec<KeyKind>, Error> {
        Ok(self
            .mechanisms(uri)?
            .into_iter()
            .flat_map(|entry| {
                crate::generation::choices(
                    entry.mechanism,
                    entry.info.generate_key_pair(),
                    entry.info.min_key_size(),
                    entry.info.max_key_size(),
                )
            })
            .collect())
    }
    /// Load and initialize an explicitly trusted library path. A URI never loads code.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self {
            module: Arc::new(Module::load(path)?),
        })
    }
    /// Loaded library metadata.
    pub fn info(&self) -> &LibraryInfo {
        self.module.info()
    }
    /// Enumerate slot metadata, optionally requiring a present token.
    pub fn slots(&self, token_present: bool) -> Result<Vec<SlotSnapshot>, Error> {
        self.module
            .slots(token_present)?
            .into_iter()
            .map(|slot| {
                Ok(SlotSnapshot {
                    id: slot.id(),
                    info: self.module.slot_info(slot)?,
                })
            })
            .collect()
    }
    /// Enumerate available tokens, including uninitialized tokens where reported.
    pub fn tokens(&self) -> Result<Vec<TokenSnapshot>, Error> {
        Ok(self
            .module
            .tokens()?
            .into_iter()
            .map(|token| TokenSnapshot {
                slot_id: token.slot().id(),
                info: token.info().clone(),
            })
            .collect())
    }
    /// Enumerate mechanisms for one uniquely resolved token, without authentication.
    pub fn mechanisms(&self, uri: &Pkcs11Uri) -> Result<Vec<MechanismSnapshot>, Error> {
        let token = self.module.resolve_token_uri(uri)?;
        token
            .mechanisms()?
            .into_iter()
            .map(|mechanism| {
                Ok(MechanismSnapshot {
                    mechanism,
                    info: token.mechanism_info(mechanism)?,
                })
            })
            .collect()
    }
    /// Create a read-only signing client under an explicit policy.
    pub fn client(
        &self,
        uri: &Pkcs11Uri,
        maximum: NonZeroUsize,
        policy: SigningPolicy,
    ) -> Result<Client<'_>, Error> {
        Client::connect(&self.module, uri, maximum, policy)
    }
    /// Open one scoped management session and authenticate once, with no retry.
    /// Authentication is explicit; USER/SO state is shared across token sessions.
    pub fn management(
        &self,
        uri: &Pkcs11Uri,
        mode: SessionMode,
        authentication: Authentication<'_>,
    ) -> Result<ManagementSession<'_>, Error> {
        let token = self.module.resolve_token_uri(uri)?;
        let mut session = token.open_session(mode)?;
        session.authenticate(authentication)?;
        Ok(ManagementSession { session })
    }
    /// Open a management session that retains the existing module owner.
    /// Useful when authentication must survive between application requests.
    /// No credential is retained. Close all owned sessions before finalization.
    pub fn management_owned(
        &self,
        uri: &Pkcs11Uri,
        mode: SessionMode,
        authentication: Authentication<'_>,
    ) -> Result<ManagementSession<'static>, Error> {
        let mut session = self.module.open_owned_session(uri, mode)?;
        session.authenticate(authentication)?;
        Ok(ManagementSession { session })
    }
    /// Exercise bounded simultaneous leases, exhaustion and reuse on a fresh pool.
    /// No signatures or mutations occur. PINs are borrowed and never retained.
    pub fn diagnose<'a>(
        &self,
        uri: &Pkcs11Uri,
        mode: SessionMode,
        maximum: NonZeroUsize,
        authentication: impl Fn() -> Authentication<'a>,
    ) -> Result<PoolDiagnostic, Error> {
        let pool = SessionPool::new(self.module.resolve_token_uri(uri)?, mode, maximum);
        let mut leases = Vec::new();
        for _ in 0..maximum.get() {
            leases.push(pool.try_acquire(authentication())?);
        }
        let session_state = leases[0].session().info()?.session_state();
        let exhaustion_verified = match pool.try_acquire(Authentication::None) {
            Err(pkcs11_runtime::Error::PoolExhausted) => true,
            Err(error) => return Err(error.into()),
            Ok(_) => false,
        };
        drop(leases);
        pool.try_acquire(authentication())?.session().info()?;
        Ok(PoolDiagnostic {
            capacity: maximum.get(),
            exhaustion_verified,
            reuse_verified: true,
            session_state,
        })
    }
    /// Initialize or erase an explicit current slot. Can destroy existing contents.
    /// Exclusive access prevents live consumers from surviving initialization.
    pub fn initialize_token(
        &mut self,
        slot_id: u64,
        so_pin: &SecretString,
        label: &str,
    ) -> Result<(), Error> {
        let module = Arc::get_mut(&mut self.module).ok_or(Error::ProviderInUse)?;
        let slot = module
            .slots(false)?
            .into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or(pkcs11_runtime::Error::NotFound("slot"))?;
        Ok(module.initialize_token(slot, so_pin, label)?)
    }
    /// Finalize after all consumers close. Live owned sessions return `ProviderInUse`.
    /// The consumed provider is released; owned sessions retain initialization until drop.
    pub fn finalize(self) -> Result<(), Error> {
        let module = Arc::try_unwrap(self.module).map_err(|_| Error::ProviderInUse)?;
        Ok(module.finalize()?)
    }
}

/// One attribute's availability and explicitly requested, redacted value container.
#[derive(Debug)]
pub struct AttributeRead {
    /// Requested attribute type.
    pub kind: AttributeType,
    /// Provider availability status.
    pub status: AttributeInfo,
    /// Value if available; providers may still omit it. Explicit access may expose secrets.
    pub values: Option<AttributeValues>,
}
fn read(object: &Object<'_, '_>, types: &[AttributeType]) -> Result<Vec<AttributeRead>, Error> {
    types
        .iter()
        .map(|&kind| {
            let status = object
                .attribute_info(&[kind])?
                .into_iter()
                .next()
                .ok_or(Error::MissingAttributeStatus)?;
            let values = if matches!(status, AttributeInfo::Available(_)) {
                Some(object.read_attributes(&[kind])?)
            } else {
                None
            };
            Ok(AttributeRead {
                kind,
                status,
                values,
            })
        })
        .collect()
}
/// A scoped inspection/administration session, without exposed runtime handles.
/// Close explicitly to report cleanup errors; Drop remains best effort.
/// Failures preserve runtime invalidation and no-retry behavior.
#[derive(Debug)]
pub struct ManagementSession<'p> {
    pub(crate) session: Session<'p>,
}
impl ManagementSession<'_> {
    /// Export only public certificate/data values or public keys as SPKI DER.
    /// Private/secret key classes and CKA_PRIVATE objects are rejected before value reads.
    pub fn export_public(&mut self, reference: &ObjectRef) -> Result<Vec<u8>, Error> {
        let object = self.session.resolve(reference)?;
        let identity = object.read_attributes(&[AttributeType::Class, AttributeType::Private])?;
        let class = identity
            .expose_values()
            .iter()
            .find_map(|value| match value {
                Attribute::Class(class) => Some(*class),
                _ => None,
            })
            .ok_or(Error::UnsupportedExport)?;
        if !identity
            .expose_values()
            .contains(&Attribute::Private(false))
        {
            return Err(Error::UnsupportedExport);
        }
        match class {
            ObjectClass::DATA | ObjectClass::CERTIFICATE => {
                let values = object.read_attributes(&[AttributeType::Value])?;
                values
                    .expose_values()
                    .iter()
                    .find_map(|value| match value {
                        Attribute::Value(bytes) => Some(bytes.clone()),
                        _ => None,
                    })
                    .ok_or(Error::MissingAttributeStatus)
            }
            ObjectClass::PUBLIC_KEY => {
                let key = crate::PublicKeyRef::new(
                    reference
                        .uri()
                        .to_string()
                        .parse()
                        .map_err(pkcs11_runtime::Error::from)?,
                )?;
                let metadata = key.public_metadata(&mut self.session)?;
                crate::public_export::encode_public_key(metadata)
            }
            _ => Err(Error::UnsupportedExport),
        }
    }
    /// Query actual token-wide login state through this live session.
    pub fn state(&self) -> Result<SessionState, Error> {
        Ok(self.session.info()?.session_state())
    }
    /// Authenticate once without storing or retrying a credential.
    pub fn authenticate(&mut self, authentication: Authentication<'_>) -> Result<(), Error> {
        Ok(self.session.authenticate(authentication)?)
    }
    /// Log out this application's sessions on the token, invalidating private handles.
    pub fn logout(&mut self) -> Result<(), Error> {
        Ok(self.session.logout()?)
    }
    /// Identity criteria for the selected token; no slot ID is persisted.
    pub fn token_uri(&self) -> Result<Pkcs11Uri, Error> {
        metadata_uri(self.session.token().info())
    }
    /// Read requested attributes for every persistent object visible in this session.
    /// Object handles remain scoped to this call. No values are requested implicitly.
    pub fn objects(&mut self, types: &[AttributeType]) -> Result<Vec<Vec<AttributeRead>>, Error> {
        self.session
            .find_objects(&[Attribute::Token(true)])?
            .iter()
            .map(|object| read(object, types))
            .collect()
    }
    /// Resolve exactly one object and read availability plus requested attributes.
    pub fn inspect(
        &mut self,
        reference: &ObjectRef,
        types: &[AttributeType],
    ) -> Result<Vec<AttributeRead>, Error> {
        read(&self.session.resolve(reference)?, types)
    }
    /// Export raw certificate/data bytes, without interpreting the signing algorithm.
    /// Private/public/secret key objects are rejected before reading their value.
    pub fn export_value(&mut self, reference: &ObjectRef) -> Result<Vec<u8>, Error> {
        let object = self.session.resolve(reference)?;
        let classes = object.read_attributes(&[AttributeType::Class])?;
        if !classes.expose_values().iter().any(|v| matches!(v, Attribute::Class(c) if *c == ObjectClass::CERTIFICATE || *c == ObjectClass::DATA)) {
            return Err(Error::UnsupportedExport);
        }
        object
            .read_attributes(&[AttributeType::Value])?
            .expose_values()
            .iter()
            .find_map(|v| match v {
                Attribute::Value(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .ok_or_else(|| pkcs11_runtime::Error::MissingMetadata("object value").into())
    }
    /// Initialize/reset USER PIN with an RW SO session. No PIN is retained.
    pub fn initialize_pin(&mut self, pin: &SecretString) -> Result<(), Error> {
        Ok(self.session.initialize_pin(pin)?)
    }
    /// Change the authenticated role's host PIN once. No retry or rollback occurs.
    pub fn change_pin(&mut self, old: &SecretString, new: &SecretString) -> Result<(), Error> {
        Ok(self.session.change_pin(old, new)?)
    }
    /// Generate a persistent sensitive, nonextractable signing pair with explicit identity.
    /// Duplicate IDs/labels remain possible; no arbitrary handle is returned.
    pub fn generate_signing_key_pair(
        &mut self,
        kind: KeyKind,
        id: &[u8],
        label: &[u8],
        always_authenticate: bool,
    ) -> Result<(), Error> {
        self.session
            .generate_signing_key_pair(kind, id, label, always_authenticate)?;
        Ok(())
    }
    /// Import a parsed X.509 document as a persistent public certificate.
    /// Does not require a supported signing algorithm or establish trust/binding.
    pub fn import_certificate(
        &mut self,
        document: &CertificateDocument,
        id: &[u8],
        label: &[u8],
    ) -> Result<(), Error> {
        self.session.create_object(&[
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(label.to_vec()),
            Attribute::Value(document.der().to_vec()),
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Subject(document.subject_der().to_vec()),
            Attribute::Issuer(document.issuer_der().to_vec()),
            Attribute::SerialNumber(document.serial_der().to_vec()),
            Attribute::Id(id.to_vec()),
        ])?;
        Ok(())
    }
    /// Import bytes as a persistent public data object with CKA_OBJECT_ID.
    pub fn import_data(&mut self, value: &[u8], id: &[u8], label: &[u8]) -> Result<(), Error> {
        self.session.create_object(&[
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(label.to_vec()),
            Attribute::ObjectId(id.to_vec()),
            Attribute::Value(value.to_vec()),
        ])?;
        Ok(())
    }
    /// Relabel one freshly resolved object. A provider failure may have partial effects.
    pub fn set_label(&mut self, reference: &ObjectRef, label: &[u8]) -> Result<(), Error> {
        Ok(self
            .session
            .resolve(reference)?
            .update_attributes(&[Attribute::Label(label.to_vec())])?)
    }
    /// Destroy exactly one freshly resolved object, with no retry.
    pub fn delete(&mut self, reference: &ObjectRef) -> Result<(), Error> {
        Ok(self.session.resolve(reference)?.destroy()?)
    }
    /// Close this session and report provider cleanup errors.
    pub fn close(self) -> Result<(), Error> {
        Ok(self.session.close()?)
    }
}
/// Validate object criteria before loading a provider and retain a stable selector.
pub fn object_reference(uri: Pkcs11Uri) -> Result<ObjectRef, Error> {
    Ok(ObjectRef::new(uri)?)
}
/// Validate token criteria before loading a provider.
pub fn validate_token_uri(uri: &Pkcs11Uri) -> Result<(), Error> {
    Ok(pkcs11_runtime::validate_token_uri(uri)?)
}
/// Validate an object URI and project its token/module constraints for connection.
pub fn token_uri(uri: Pkcs11Uri) -> Result<Pkcs11Uri, Error> {
    let reference = object_reference(uri)?;
    let uri = reference.uri();
    let mut builder = Pkcs11Uri::builder();
    for (name, value) in uri.path_attributes() {
        if !["object", "id", "type"].contains(&name) {
            builder = builder
                .path_attribute(name, value)
                .map_err(pkcs11_runtime::Error::from)?;
        }
    }
    if let Some(value) = uri.query_values("module-path").next() {
        builder = builder
            .query_attribute("module-path", SecretString::from(value.expose_secret()))
            .map_err(pkcs11_runtime::Error::from)?;
    }
    Ok(builder.build().map_err(pkcs11_runtime::Error::from)?)
}
fn metadata_uri(info: &TokenInfo) -> Result<Pkcs11Uri, Error> {
    let build = || -> Result<Pkcs11Uri, pkcs11_locator::Error> {
        Pkcs11Uri::builder()
            .path_attribute("token", info.label().as_bytes())?
            .path_attribute("serial", info.serial_number().as_bytes())?
            .path_attribute("manufacturer", info.manufacturer_id().as_bytes())?
            .path_attribute("model", info.model().as_bytes())?
            .build()
    };
    Ok(build().map_err(pkcs11_runtime::Error::from)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn object_projection_preserves_location_and_rejects_credentials() {
        let uri = "pkcs11:token=test;serial=123;library-description=module;slot-description=reader;object=key;id=%00%FF;type=private".parse().unwrap();
        let token = token_uri(uri).unwrap();
        assert_eq!(
            token.to_string(),
            "pkcs11:library-description=module;serial=123;slot-description=reader;token=test"
        );
        validate_token_uri(&token).unwrap();
        let path = std::env::current_dir().unwrap().join("trusted.so");
        let mut builder = Pkcs11Uri::builder();
        for (name, value) in token.path_attributes() {
            builder = builder.path_attribute(name, value).unwrap();
        }
        let uri = builder
            .path_attribute("object", b"key")
            .unwrap()
            .query_attribute("module-path", path.to_str().unwrap().into())
            .unwrap()
            .build()
            .unwrap();
        let token = token_uri(uri).unwrap();
        validate_token_uri(&token).unwrap();
        assert_eq!(
            token
                .query_values("module-path")
                .next()
                .unwrap()
                .expose_secret(),
            path.to_str().unwrap()
        );
        for bad in [
            "pkcs11:token=test;object=key;type=private?pin-value=secret",
            "pkcs11:token=test;slot-id=1;object=key;type=private",
            "pkcs11:token=test;object=key;type=private?module-name=unknown",
        ] {
            let error = token_uri(bad.parse().unwrap()).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Input);
            assert!(!format!("{error:?}").contains("secret"));
        }
    }
}
