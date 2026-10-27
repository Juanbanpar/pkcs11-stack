// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AesKeyWrapAlgorithm, KeyOperation, ManagementSession, ObjectRef, SecretKeyIdentity,
    UnwrapRequest, WrapRequest, object_reference,
};
use serde_json::json;

pub fn selected(name: &str) -> bool {
    matches!(
        name,
        "key-wrap-capabilities" | "wrap-aes-key" | "unwrap-aes-key"
    )
}
fn key(m: &ArgMatches, field: &str) -> Result<ObjectRef> {
    let uri = uri(m, field)?;
    if uri.path_attribute("type") != Some(b"secret-key") {
        return Err(usage("AES wrapping requires type=secret-key URIs"));
    }
    Ok(object_reference(uri)?)
}
fn algorithm(m: &ArgMatches) -> Result<AesKeyWrapAlgorithm> {
    match get(m, "algorithm") {
        Some("kw") => Ok(AesKeyWrapAlgorithm::Kw),
        Some("kwp") => Ok(AesKeyWrapAlgorithm::Kwp),
        _ => Err(usage("select --algorithm kw|kwp")),
    }
}
pub fn validate(name: &str, m: &ArgMatches, bytes: &[u8]) -> Result<()> {
    key(m, "object")?;
    if name == "key-wrap-capabilities" {
        return Ok(());
    }
    algorithm(m)?;
    if name == "wrap-aes-key" {
        key(m, "target")?;
    } else {
        if ![24, 32, 40].contains(&bytes.len()) {
            return Err(usage("AES wrapped input must be 24, 32 or 40 bytes"));
        }
        if unhex(need(m, "id")?)?.len() > 128
            || need(m, "label")?.is_empty()
            || need(m, "label")?.len() > 128
        {
            return Err(usage("secret ID and label must be 1..=128 bytes"));
        }
    }
    Ok(())
}
pub fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    bytes: &[u8],
) -> Result<Output> {
    let wrapping = key(m, "object")?;
    if name == "key-wrap-capabilities" {
        let direction = if get(m, "operation") == Some("unwrap") {
            KeyOperation::Unwrap
        } else {
            KeyOperation::Wrap
        };
        let caps = session.aes_key_wrap_options(&wrapping, direction)?;
        let algorithms: Vec<_> = [("kw", caps.kw), ("kwp", caps.kwp)]
            .into_iter()
            .filter_map(|(name, supported)| supported.then_some(name))
            .collect();
        return Ok(Output::Structured(
            json!({"advisory":true, "key_bytes":caps.key_length, "operation":need(m,"operation")?, "algorithms":algorithms}),
        ));
    }
    let algorithm = algorithm(m)?;
    if name == "wrap-aes-key" {
        let target = key(m, "target")?;
        Ok(Output::Binary(session.wrap_with_algorithm(
            &wrapping,
            &WrapRequest { target: &target },
            algorithm,
        )?))
    } else {
        let id = unhex(need(m, "id")?)?;
        session.unwrap_with_algorithm(
            &wrapping,
            &UnwrapRequest {
                wrapped: bytes,
                identity: SecretKeyIdentity {
                    id: &id,
                    label: need(m, "label")?.as_bytes(),
                },
            },
            algorithm,
        )?;
        Ok(Output::Structured(
            json!({"unwrapped":true, "algorithm":need(m,"algorithm")?, "id_hex":hex(&id)}),
        ))
    }
}
