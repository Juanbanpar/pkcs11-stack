// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{inputs::Inputs, support::*};
use clap::ArgMatches;
use pkcs11_client::{AttributeType, ManagementSession, object_reference};
use serde_json::json;

use super::{Output, inspect, signing::ml_dsa};

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let value = match name {
        "objects" => {
            let token_uri = session.token_uri()?;
            let mut objects = vec![];
            for object in session.objects(&[
                AttributeType::Class,
                AttributeType::Label,
                AttributeType::Id,
            ])? {
                objects.push(inspect::object_summary(&object, &token_uri)?);
            }
            json!(objects)
        }
        "inspect" => {
            let reference = object_reference(uri(m, "object")?)?;
            let names = need(m, "attributes")?.split(',').collect::<Vec<_>>();
            let types = names
                .iter()
                .map(|name| inspect::attribute_type(name))
                .collect::<Result<Vec<_>>>()?;
            inspect::attributes(&session.inspect(&reference, &types)?, &names)?
        }
        "export" => {
            let reference = object_reference(uri(m, "object")?)?;
            let bytes = if get(m, "key-family") == Some("ml-kem") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_ml_kem_public_key(&key)?
            } else if get(m, "key-family") == Some("slh-dsa") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_slh_dsa_public_key(&key)?
            } else if get(m, "key-family") == Some("eddsa") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_eddsa_public_key(&key)?
            } else if get(m, "key-family") == Some("montgomery") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_montgomery_public_key(&key)?
            } else if ml_dsa::selected(m) {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_ml_dsa_public_key(&key)?
            } else if reference.uri().path_attribute("type") == Some(b"public") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_classical_public_key(&key)?
            } else {
                session.export_value(&reference)?
            };
            return Ok(Output::Binary(bytes));
        }
        "import" => {
            let id = unhex(need(m, "id")?)?;
            if need(m, "kind")? == "public-key" {
                let key = pkcs11_client::ClassicalPublicKey::from_spki_der(&inputs.bytes)?;
                let purpose = match need(m, "purpose")? {
                    "verification" => pkcs11_client::ClassicalPublicKeyPurpose::Verification,
                    "encryption" => pkcs11_client::ClassicalPublicKeyPurpose::Encryption,
                    _ => return Err(usage("invalid public-key purpose")),
                };
                session.import_public_key(&pkcs11_client::PublicKeyImportRequest {
                    key: &key,
                    purpose,
                    id: &id,
                    label: need(m, "label")?.as_bytes(),
                })?;
            } else if need(m, "kind")? == "ml-kem" {
                session.import_ml_kem_public_key(
                    inputs
                        .ml_kem_public_key
                        .as_ref()
                        .ok_or_else(|| usage("missing ML-KEM public key"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
            } else if need(m, "kind")? == "cert" {
                session.import_certificate(
                    inputs
                        .certificate_document
                        .as_ref()
                        .ok_or_else(|| usage("missing certificate document"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
            } else {
                session.import_data(&inputs.bytes, &id, need(m, "label")?.as_bytes())?;
            }
            json!({"imported":true})
        }
        "delete" | "set-label" => {
            let reference = object_reference(uri(m, "object")?)?;
            if name == "delete" {
                session.delete(&reference)?;
            } else {
                session.set_label(&reference, need(m, "label")?.as_bytes())?;
            }
            json!({"changed":true})
        }

        _ => unreachable!(),
    };
    Ok(Output::Structured(value))
}
