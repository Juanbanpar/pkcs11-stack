// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{HmacAlgorithm, MacOperation, ManagementSession, object_reference};
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "hmac-capabilities" | "mac-hmac" | "verify-hmac")
}
fn algorithm(m: &ArgMatches) -> Result<HmacAlgorithm> {
    crate::generation::hmac(need(m, "algorithm")?)
        .ok_or_else(|| usage("unsupported HMAC algorithm"))
}
pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Option<Vec<u8>>> {
    if !selected(name) {
        return Ok(None);
    }
    if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
        return Err(usage("HMAC requires type=secret-key"));
    }
    if name == "verify-hmac" {
        let algorithm = algorithm(m)?;
        let path = need(m, "tag-file")?;
        if path == "-" {
            return Err(usage("tag-file requires a file path"));
        }
        let tag = bounded_input(path, algorithm.tag_length())?;
        if tag.len() != algorithm.tag_length() {
            return Err(usage("HMAC requires a full-length tag"));
        }
        Ok(Some(tag))
    } else {
        Ok(None)
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    message: &[u8],
    tag: Option<&[u8]>,
) -> Result<Output> {
    let key = object_reference(uri(m, "object")?)?;
    match name {
        "hmac-capabilities" => {
            let direction = if need(m, "operation")? == "generate" {
                MacOperation::Generate
            } else {
                MacOperation::Verify
            };
            let caps = session.hmac_capabilities(&key, direction)?;
            Ok(Output::Structured(
                json!({"advisory":true,"key_length":caps.key_length,"operation":need(m,"operation")?,"algorithms":HmacAlgorithm::ALL.into_iter().filter(|a|caps.supports(*a)).map(|a|a.to_string()).collect::<Vec<_>>()}),
            ))
        }
        "mac-hmac" => Ok(Output::Binary(session.mac_hmac(
            &key,
            algorithm(m)?,
            message,
        )?)),
        "verify-hmac" => {
            let algorithm = algorithm(m)?;
            let tag = tag.ok_or_else(|| usage("missing HMAC tag"))?;
            session.verify_hmac(&key, algorithm, message, tag)?;
            Ok(Output::Structured(
                json!({"verified":true,"algorithm":algorithm.to_string()}),
            ))
        }
        _ => Err(usage("unknown HMAC command")),
    }
}
