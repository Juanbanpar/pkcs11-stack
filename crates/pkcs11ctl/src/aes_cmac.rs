// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{AesCmacProfile, MacOperation, ManagementSession, object_reference};
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "aes-cmac-capabilities" | "mac-aes-cmac" | "verify-aes-cmac"
    )
}
pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Option<Vec<u8>>> {
    if !selected(name) {
        return Ok(None);
    }
    if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
        return Err(usage("AES CMAC requires type=secret-key"));
    }
    let profile = profile(m)?;
    if name == "verify-aes-cmac" {
        let path = need(m, "tag-file")?;
        if path == "-" {
            return Err(usage("tag-file requires a file path"));
        }
        let tag = bounded_input(path, profile.tag_length())?;
        if tag.len() != profile.tag_length() {
            return Err(usage("AES CMAC tag must match the selected length"));
        }
        return Ok(Some(tag));
    }
    Ok(None)
}
fn profile(m: &ArgMatches) -> Result<AesCmacProfile> {
    let profile = if get(m, "tag-length").is_some() {
        AesCmacProfile::General {
            tag_length: number(m, "tag-length")?,
        }
    } else {
        AesCmacProfile::Full
    };
    profile.validate().map_err(pkcs11_client::Error::from)?;
    Ok(profile)
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    message: &[u8],
    tag: Option<&[u8]>,
) -> Result<Output> {
    let profile = profile(m)?;
    let key = object_reference(uri(m, "object")?)?;
    match name {
        "aes-cmac-capabilities" => {
            let operation = if need(m, "operation")? == "generate" {
                MacOperation::Generate
            } else {
                MacOperation::Verify
            };
            let caps = session.aes_cmac_capabilities_with_profile(&key, operation, profile)?;
            Ok(Output::Structured(
                json!({"advisory":true,"algorithm":"aes-cmac","key_bits":caps.key_size.length()*8,"tag_length":profile.tag_length(),"operation":need(m,"operation")?}),
            ))
        }
        "mac-aes-cmac" => Ok(Output::Binary(
            session.mac_aes_cmac_with_profile(&key, message, profile)?,
        )),
        "verify-aes-cmac" => {
            let tag = tag.ok_or_else(|| usage("missing AES CMAC tag"))?;
            session.verify_aes_cmac_with_profile(&key, message, tag, profile)?;
            Ok(Output::Structured(
                json!({"verified":true,"algorithm":"aes-cmac"}),
            ))
        }
        _ => Err(usage("unknown AES CMAC command")),
    }
}
