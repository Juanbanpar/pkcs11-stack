// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{BackendError, Registry, ResourceId};
use pkcs11_client::{
    Attribute, AttributeInfo, AttributeRead, AttributeType, Authentication, ManagementSession,
    MechanismType, ObjectClass, Pkcs11Uri, SessionMode,
};

#[derive(Clone, Debug)]
pub struct MetadataField {
    pub name: &'static str,
    pub status: &'static str,
    pub value: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ObjectEntry {
    pub id: ResourceId,
    pub class: Option<ObjectClass>,
    pub label: String,
    pub identifier: String,
    pub uri: Option<String>,
    pub ambiguous: bool,
    pub fields: Vec<MetadataField>,
}
impl ObjectEntry {
    pub fn class_name(&self) -> String {
        match self.class {
            Some(ObjectClass::DATA) => "Data".into(),
            Some(ObjectClass::CERTIFICATE) => "Certificate".into(),
            Some(ObjectClass::PUBLIC_KEY) => "Public key".into(),
            Some(ObjectClass::PRIVATE_KEY) => "Private key".into(),
            Some(ObjectClass::SECRET_KEY) => "Secret key".into(),
            Some(class) => class.to_string(),
            None => "Unknown class".into(),
        }
    }
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        [
            &self.label,
            &self.identifier,
            &self.class_name(),
            self.uri.as_deref().unwrap_or(""),
        ]
        .iter()
        .any(|value| value.to_lowercase().contains(&query))
    }
}

#[derive(Clone, Debug)]
pub struct MechanismEntry {
    pub id: MechanismType,
    pub name: String,
    pub identifier: String,
    pub minimum: usize,
    pub maximum: usize,
    pub flags: Vec<&'static str>,
}
impl MechanismEntry {
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        self.name.to_lowercase().contains(&query)
            || self.identifier.to_lowercase().contains(&query)
            || self
                .flags
                .iter()
                .any(|flag| flag.to_lowercase().contains(&query))
    }
}

pub(super) struct ObjectCatalog {
    token: ResourceId,
    objects: Vec<ObjectEntry>,
}

fn values(reads: &[AttributeRead]) -> impl Iterator<Item = &Attribute> {
    reads
        .iter()
        .filter(|read| matches!(read.status, AttributeInfo::Available(_)))
        .filter_map(|read| read.values.as_ref().map(|values| (read.kind, values)))
        .flat_map(|(kind, values)| {
            values
                .expose_values()
                .iter()
                .filter(move |value| value.attribute_type() == kind)
        })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
fn public_value(value: &Attribute) -> Option<String> {
    Some(match value {
        Attribute::Class(class) => class.to_string(),
        Attribute::KeyType(kind) => kind.to_string(),
        Attribute::CertificateType(kind) => kind.to_string(),
        Attribute::ModulusBits(bits) | Attribute::ValueLen(bits) => bits.to_string(),
        Attribute::Label(bytes) | Attribute::Application(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .unwrap_or_else(|_| format!("hex: {}", hex(bytes))),
        Attribute::Id(bytes) | Attribute::ObjectId(bytes) => hex(bytes),
        Attribute::Token(value)
        | Attribute::Private(value)
        | Attribute::Sign(value)
        | Attribute::Verify(value)
        | Attribute::Encrypt(value)
        | Attribute::Decrypt(value)
        | Attribute::Wrap(value)
        | Attribute::Unwrap(value)
        | Attribute::WrapWithTrusted(value)
        | Attribute::Trusted(value)
        | Attribute::Derive(value)
        | Attribute::Encapsulate(value)
        | Attribute::Decapsulate(value)
        | Attribute::Sensitive(value)
        | Attribute::Extractable(value)
        | Attribute::AlwaysAuthenticate(value) => value.to_string(),
        _ => return None,
    })
}
fn field(read: &AttributeRead, name: &'static str) -> MetadataField {
    let value = values(std::slice::from_ref(read))
        .next()
        .and_then(public_value);
    MetadataField {
        name,
        status: match read.status {
            AttributeInfo::Available(_) if value.is_some() => "available",
            AttributeInfo::Available(_) | AttributeInfo::Unavailable => "unavailable",
            AttributeInfo::Sensitive => "sensitive",
            AttributeInfo::TypeInvalid => "unsupported",
        },
        value,
    }
}
const SUMMARY: [(AttributeType, &str); 3] = [
    (AttributeType::Class, "Class"),
    (AttributeType::Label, "Label"),
    (AttributeType::Id, "ID (hex)"),
];
fn detail_attributes(class: Option<ObjectClass>) -> Vec<(AttributeType, &'static str)> {
    use AttributeType as A;
    let mut types = vec![(A::Token, "Persistent"), (A::Private, "Private")];
    match class {
        Some(ObjectClass::PUBLIC_KEY | ObjectClass::PRIVATE_KEY | ObjectClass::SECRET_KEY) => {
            types.extend([
                (A::KeyType, "Key type"),
                (A::Sign, "Sign"),
                (A::Verify, "Verify"),
                (A::Encrypt, "Encrypt"),
                (A::Decrypt, "Decrypt"),
                (A::Wrap, "Wrap"),
                (A::Unwrap, "Unwrap"),
                (A::Derive, "Derive"),
                (A::Encapsulate, "Encapsulate"),
                (A::Decapsulate, "Decapsulate"),
            ]);
            if class == Some(ObjectClass::SECRET_KEY) {
                types.extend([
                    (A::ValueLen, "Key bytes"),
                    (A::Trusted, "Trusted"),
                    (A::WrapWithTrusted, "Wrap with trusted"),
                ]);
            } else {
                types.push((A::ModulusBits, "RSA modulus bits"));
            }
            if class != Some(ObjectClass::PUBLIC_KEY) {
                types.extend([(A::Sensitive, "Sensitive"), (A::Extractable, "Extractable")]);
            }
            if class == Some(ObjectClass::PRIVATE_KEY) {
                types.push((A::AlwaysAuthenticate, "Always authenticate"));
            }
        }
        Some(ObjectClass::CERTIFICATE) => types.push((A::CertificateType, "Certificate type")),
        Some(ObjectClass::DATA) => types.extend([
            (A::Application, "Application"),
            (A::ObjectId, "Object ID (hex)"),
        ]),
        _ => {}
    }
    types
}

pub(super) fn read_session<T>(
    module: &super::LoadedModule,
    token: &Pkcs11Uri,
    mode: SessionMode,
    operation: impl FnOnce(&mut ManagementSession<'_>) -> Result<T, BackendError>,
) -> Result<T, BackendError> {
    let mut session = module
        .provider
        .management(token, mode, Authentication::None)
        .map_err(|e| BackendError::from(&e))?;
    let result = operation(&mut session);
    let closed = session.close().map_err(|e| BackendError::from(&e));
    super::finish_session(result, closed, &module.cleanup_failed)
}

impl Registry {
    pub(super) fn location(
        &self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<(usize, Pkcs11Uri), BackendError> {
        let index = self
            .modules
            .iter()
            .position(|m| m.entry.id == module)
            .ok_or(BackendError::UnknownModule)?;
        if self.modules[index].cleanup_failed.get() {
            return Err(BackendError::SessionCleanup);
        }
        let entry = self.modules[index]
            .entry
            .tokens
            .iter()
            .find(|t| t.id == token)
            .ok_or(BackendError::UnknownToken)?;
        let uri = entry
            .uri
            .as_ref()
            .ok_or(BackendError::UnknownToken)?
            .parse()
            .map_err(|_| BackendError::UnknownToken)?;
        Ok((index, uri))
    }
    pub(super) fn objects(
        &mut self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<Vec<ObjectEntry>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        self.modules[index]
            .catalogs
            .retain(|catalog| catalog.token != token);
        let reads = read_session(
            &self.modules[index],
            &uri,
            self.modules[index].read_mode(token)?,
            |session| {
                session
                    .objects(&SUMMARY.map(|(kind, _)| kind))
                    .map_err(|e| BackendError::from(&e))
            },
        )?;
        let mut objects = Vec::new();
        for reads in reads {
            let mut class = None;
            let mut label = String::new();
            let mut identifier = String::new();
            for value in values(&reads) {
                match value {
                    Attribute::Class(value) => class = Some(*value),
                    Attribute::Label(_) => label = public_value(value).unwrap_or_default(),
                    Attribute::Id(bytes) => identifier = hex(bytes),
                    _ => {}
                }
            }
            let locator =
                pkcs11_client::object_locator(&uri, &reads).map_err(|e| BackendError::from(&e))?;
            objects.push(ObjectEntry {
                id: self.allocate()?,
                class,
                label,
                identifier,
                uri: locator.map(|uri| uri.to_string()),
                ambiguous: false,
                fields: reads
                    .iter()
                    .zip(SUMMARY)
                    .map(|(read, (_, name))| field(read, name))
                    .collect(),
            });
        }
        let mut counts = std::collections::HashMap::new();
        for entry in &objects {
            if let Some(uri) = &entry.uri {
                *counts.entry(uri.clone()).or_insert(0usize) += 1;
            }
        }
        for entry in &mut objects {
            entry.ambiguous = entry.uri.as_ref().is_some_and(|uri| counts[uri] > 1);
        }
        self.modules[index].catalogs.push(ObjectCatalog {
            token,
            objects: objects.clone(),
        });
        Ok(objects)
    }
    pub(super) fn reference(
        &self,
        module: ResourceId,
        token: ResourceId,
        object: ResourceId,
    ) -> Result<(pkcs11_client::ObjectRef, Option<ObjectClass>), BackendError> {
        let (index, _) = self.location(module, token)?;
        let entry = self.modules[index]
            .catalogs
            .iter()
            .find(|catalog| catalog.token == token)
            .and_then(|catalog| catalog.objects.iter().find(|entry| entry.id == object))
            .ok_or(BackendError::UnknownObject)?;
        if entry.ambiguous {
            return Err(BackendError::AmbiguousObject);
        }
        let reference = pkcs11_client::object_reference(
            entry
                .uri
                .as_ref()
                .ok_or(BackendError::UnknownObject)?
                .parse()
                .map_err(|_| BackendError::UnknownObject)?,
        )
        .map_err(|e| BackendError::from(&e))?;
        Ok((reference, entry.class))
    }

    pub(super) fn inspect(
        &self,
        module: ResourceId,
        token: ResourceId,
        object: ResourceId,
    ) -> Result<Vec<MetadataField>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        let (reference, class) = self.reference(module, token, object)?;
        let attributes = detail_attributes(class);
        read_session(
            &self.modules[index],
            &uri,
            self.modules[index].read_mode(token)?,
            |session| {
                let reads = session
                    .inspect(
                        &reference,
                        &attributes.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                    )
                    .map_err(|e| BackendError::from(&e))?;
                Ok(reads
                    .iter()
                    .zip(attributes)
                    .map(|(read, (_, name))| field(read, name))
                    .collect())
            },
        )
    }
    pub(super) fn mechanisms(
        &self,
        module: ResourceId,
        token: ResourceId,
    ) -> Result<Vec<MechanismEntry>, BackendError> {
        let (index, uri) = self.location(module, token)?;
        let entries = self.modules[index]
            .provider
            .mechanisms(&uri)
            .map_err(|e| BackendError::from(&e))?;
        let mut mechanisms = entries
            .into_iter()
            .map(|entry| {
                let info = entry.info;
                let flags = [
                    ("Hardware", info.hardware()),
                    ("Encrypt", info.encrypt()),
                    ("Decrypt", info.decrypt()),
                    ("Digest", info.digest()),
                    ("Sign", info.sign()),
                    ("Sign recover", info.sign_recover()),
                    ("Verify", info.verify()),
                    ("Verify recover", info.verify_recover()),
                    ("Generate", info.generate()),
                    ("Generate key pair", info.generate_key_pair()),
                    ("Wrap", info.wrap()),
                    ("Unwrap", info.unwrap()),
                    ("Derive", info.derive()),
                    ("EC prime field", info.ec_f_p()),
                    ("EC binary field", info.ec_f_2m()),
                    ("EC explicit parameters", info.ec_from_parameters()),
                    ("EC OID", info.ec_from_oid()),
                    ("EC uncompressed", info.ec_uncompressed()),
                    ("EC compressed", info.ec_compressed()),
                    ("Extension", info.extension()),
                    ("Message encrypt", info.message_encrypt()),
                    ("Message decrypt", info.message_decrypt()),
                    ("Multiple messages", info.multi_message()),
                    ("Encapsulate", info.encapsulate()),
                    ("Decapsulate", info.decapsulate()),
                ]
                .into_iter()
                .filter_map(|(name, enabled)| enabled.then_some(name))
                .collect();
                MechanismEntry {
                    id: entry.mechanism,
                    name: entry.mechanism.to_string(),
                    identifier: format!("{:#x}", *entry.mechanism),
                    minimum: info.min_key_size(),
                    maximum: info.max_key_size(),
                    flags,
                }
            })
            .collect::<Vec<_>>();
        mechanisms.sort_by_key(|entry| *entry.id);
        Ok(mechanisms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_inspection_never_requests_or_formats_values_or_private_key_material() {
        for class in [
            ObjectClass::DATA,
            ObjectClass::CERTIFICATE,
            ObjectClass::PUBLIC_KEY,
            ObjectClass::PRIVATE_KEY,
            ObjectClass::SECRET_KEY,
        ] {
            let types = detail_attributes(Some(class));
            assert!(types.len() <= 17);
            assert!(!types.iter().any(|(kind, _)| {
                [
                    AttributeType::Value,
                    AttributeType::PrivateExponent,
                    AttributeType::Prime1,
                    AttributeType::Prime2,
                    AttributeType::Seed,
                ]
                .contains(kind)
            }));
        }
        assert!(public_value(&Attribute::Value(b"secret-canary".to_vec())).is_none());
        assert!(public_value(&Attribute::PrivateExponent(b"secret-canary".to_vec())).is_none());
        assert!(public_value(&Attribute::Seed(b"secret-canary".to_vec())).is_none());
        for (status, expected) in [
            (AttributeInfo::Sensitive, "sensitive"),
            (AttributeInfo::TypeInvalid, "unsupported"),
            (AttributeInfo::Unavailable, "unavailable"),
            (AttributeInfo::Available(0), "unavailable"),
        ] {
            let read = AttributeRead {
                kind: AttributeType::Label,
                status,
                values: None,
            };
            let field = field(&read, "Label");
            assert_eq!(field.status, expected);
            assert!(field.value.is_none());
        }
        assert_eq!(
            public_value(&Attribute::Label(vec![255])).as_deref(),
            Some("hex: FF")
        );
    }
}
