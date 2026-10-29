// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::support::*;
use pkcs11_client::{
    Attribute, AttributeInfo, AttributeRead, AttributeType, KeyKind, ObjectClass, TokenSnapshot,
};
use pkcs11_locator::Pkcs11Uri;
use serde_json::{Map, Value, json};

pub(crate) fn token_info(token: &TokenSnapshot) -> Result<Value> {
    let info = &token.info;
    Ok(
        json!({"slot_id":token.slot_id,"uri":token.uri()?.to_string(),"label":info.label(),"serial":info.serial_number(),"manufacturer":info.manufacturer_id(),"model":info.model(),"initialized":info.token_initialized(),"login_required":info.login_required(),"user_pin_initialized":info.user_pin_initialized(),"protected_path":info.protected_authentication_path(),"write_protected":info.write_protected()}),
    )
}
pub(crate) fn key_kind(kind: KeyKind) -> Value {
    match kind {
        KeyKind::Rsa { bits } => json!({"algorithm":"rsa","bits":bits}),
        KeyKind::Ec(curve) => json!({"algorithm":"ec","curve":format!("{curve:?}")}),
    }
}
pub(crate) fn attribute_type(name: &str) -> Result<AttributeType> {
    Ok(match name {
        "class" => AttributeType::Class,
        "label" => AttributeType::Label,
        "id" => AttributeType::Id,
        "object-id" => AttributeType::ObjectId,
        "private" => AttributeType::Private,
        "sign" => AttributeType::Sign,
        "verify" => AttributeType::Verify,
        "encrypt" => AttributeType::Encrypt,
        "decrypt" => AttributeType::Decrypt,
        "wrap" => AttributeType::Wrap,
        "unwrap" => AttributeType::Unwrap,
        "derive" => AttributeType::Derive,
        "sensitive" => AttributeType::Sensitive,
        "extractable" => AttributeType::Extractable,
        "always-authenticate" => AttributeType::AlwaysAuthenticate,
        "key-type" => AttributeType::KeyType,
        "modulus" => AttributeType::Modulus,
        "exponent" => AttributeType::PublicExponent,
        "ec-params" => AttributeType::EcParams,
        "ec-point" => AttributeType::EcPoint,
        "value" => AttributeType::Value,
        "subject" => AttributeType::Subject,
        "issuer" => AttributeType::Issuer,
        "serial" => AttributeType::SerialNumber,
        _ => return Err(usage("unsupported attribute name")),
    })
}
fn class_name(class: ObjectClass) -> String {
    match class {
        ObjectClass::PRIVATE_KEY => "private".into(),
        ObjectClass::PUBLIC_KEY => "public".into(),
        ObjectClass::CERTIFICATE => "cert".into(),
        ObjectClass::DATA => "data".into(),
        ObjectClass::SECRET_KEY => "secret-key".into(),
        _ => format!("{class:?}"),
    }
}
pub(crate) fn template_metadata(report: &pkcs11_client::TemplateMetadata) -> Value {
    fn status(info: AttributeInfo) -> Value {
        match info {
            AttributeInfo::Available(length) => json!({"status":"available", "length":length}),
            AttributeInfo::Sensitive => json!({"status":"sensitive"}),
            AttributeInfo::TypeInvalid => json!({"status":"unsupported"}),
            AttributeInfo::Unavailable => json!({"status":"unavailable"}),
        }
    }
    fn members(entries: &[pkcs11_client::TemplateMember]) -> Vec<Value> {
        entries
            .iter()
            .map(|entry| {
                let mut value = status(entry.status);
                value["attribute_type"] = json!(format!("0x{:x}", entry.attribute_type));
                if let Some(template) = &entry.template {
                    value["members"] = json!(members(template));
                }
                value
            })
            .collect()
    }
    let mut value = status(report.status);
    value["attribute_type"] = json!(format!("0x{:x}", report.kind.id()));
    value["members"] = json!(members(&report.members));
    value
}
fn attr_value(attribute: &Attribute) -> Value {
    match attribute {
        Attribute::Class(v) => json!(class_name(*v)),
        Attribute::KeyType(v) => json!(format!("{v:?}")),
        Attribute::CertificateType(v) => json!(v.to_string()),
        Attribute::ProfileId(v) => {
            json!({"id":format!("0x{:x}", v.as_ref()), "name":v.to_string()})
        }
        Attribute::ValidationType(v) => json!({"id":format!("0x{:x}", **v), "name":v.to_string()}),
        Attribute::ValidationAuthorityType(v) => {
            json!({"id":format!("0x{:x}", **v), "name":v.to_string()})
        }
        Attribute::ValidationVersion(v) => json!(v.to_string()),
        Attribute::ObjectValidationFlags(v) | Attribute::ValidationFlag(v) => {
            json!(format!("0x{:x}", **v))
        }
        Attribute::ValidationLevel(v) => json!(v.to_string()),
        Attribute::UniqueId(v)
        | Attribute::ValidationModuleId(v)
        | Attribute::ValidationCountry(v)
        | Attribute::ValidationCertificateIdentifier(v)
        | Attribute::ValidationCertificateUri(v)
        | Attribute::ValidationVendorUri(v)
        | Attribute::ValidationProfile(v) => {
            json!({"hex":hex(v), "text":std::str::from_utf8(v).ok()})
        }
        Attribute::Label(v) => json!({"hex":hex(v),"text":std::str::from_utf8(v).ok()}),
        Attribute::Id(v)
        | Attribute::ObjectId(v)
        | Attribute::Value(v)
        | Attribute::Subject(v)
        | Attribute::Issuer(v)
        | Attribute::SerialNumber(v)
        | Attribute::Modulus(v)
        | Attribute::PublicExponent(v)
        | Attribute::EcParams(v)
        | Attribute::PublicKeyInfo(v)
        | Attribute::EcPoint(v) => json!({"hex":hex(v)}),
        Attribute::Token(v)
        | Attribute::Private(v)
        | Attribute::Sign(v)
        | Attribute::Verify(v)
        | Attribute::Encrypt(v)
        | Attribute::Decrypt(v)
        | Attribute::Wrap(v)
        | Attribute::Unwrap(v)
        | Attribute::Derive(v)
        | Attribute::Sensitive(v)
        | Attribute::Extractable(v)
        | Attribute::AlwaysAuthenticate(v) => json!(v),
        _ => Value::Null,
    }
}
pub(crate) fn attributes(reads: &[AttributeRead], names: &[&str]) -> Result<Value> {
    let mut result = Map::new();
    for (name, read) in names.iter().zip(reads) {
        let value = match read.status {
            AttributeInfo::Available(_) => {
                match read.values.as_ref().and_then(|v| v.expose_values().first()) {
                    Some(value) => json!({"status":"available","value":attr_value(value)}),
                    None => json!({"status":"unavailable"}),
                }
            }
            AttributeInfo::Unavailable => json!({"status":"unavailable"}),
            AttributeInfo::Sensitive => json!({"status":"sensitive"}),
            AttributeInfo::TypeInvalid => json!({"status":"unsupported"}),
        };
        result.insert((*name).into(), value);
    }
    Ok(Value::Object(result))
}
pub(crate) fn object_summary(object: &[AttributeRead], token: &Pkcs11Uri) -> Result<Value> {
    let attrs = attributes(object, &["class", "label", "id"])?;
    let uri = pkcs11_client::object_locator(token, object)?.map(|uri| uri.to_string());
    Ok(json!({"uri":uri,"attributes":attrs}))
}

pub(crate) fn public_metadata(reads: &[AttributeRead], token: &Pkcs11Uri) -> Result<Value> {
    let names = reads
        .iter()
        .map(|read| {
            pkcs11_client::PUBLIC_METADATA_FIELDS
                .iter()
                .find(|(kind, _)| *kind == read.kind)
                .map(|(_, name)| *name)
                .ok_or_else(|| usage("unknown public metadata field"))
        })
        .collect::<Result<Vec<_>>>()?;
    let attrs = attributes(reads, &names)?;
    let uri = pkcs11_client::object_locator(token, reads)?.map(|uri| uri.to_string());
    Ok(json!({"uri":uri, "attributes":attrs, "provider_reported":true, "trust_validated":false}))
}
