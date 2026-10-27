// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{AES_CMAC_TAG_LENGTH, MacOperation, ManagementSession, object_reference};
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "aes-cmac-capabilities" | "mac-aes-cmac" | "verify-aes-cmac"
    )
}
pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Option<[u8; AES_CMAC_TAG_LENGTH]>> {
    if !selected(name) {
        return Ok(None);
    }
    if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
        return Err(usage("AES CMAC requires type=secret-key"));
    }
    if name == "verify-aes-cmac" {
        let path = need(m, "tag-file")?;
        if path == "-" {
            return Err(usage("tag-file requires a file path"));
        }
        let tag = bounded_input(path, AES_CMAC_TAG_LENGTH)?
            .try_into()
            .map_err(|_| usage("AES CMAC requires a 16-byte tag"))?;
        return Ok(Some(tag));
    }
    Ok(None)
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    message: &[u8],
    tag: Option<&[u8; AES_CMAC_TAG_LENGTH]>,
) -> Result<Output> {
    let key = object_reference(uri(m, "object")?)?;
    match name {
        "aes-cmac-capabilities" => {
            let operation = if need(m, "operation")? == "generate" {
                MacOperation::Generate
            } else {
                MacOperation::Verify
            };
            let caps = session.aes_cmac_capabilities(&key, operation)?;
            Ok(Output::Structured(
                json!({"advisory":true,"algorithm":"aes-cmac","key_bits":caps.key_size.length()*8,"tag_length":AES_CMAC_TAG_LENGTH,"operation":need(m,"operation")?}),
            ))
        }
        "mac-aes-cmac" => Ok(Output::Binary(
            session.mac_aes_cmac(&key, message)?.to_vec(),
        )),
        "verify-aes-cmac" => {
            let tag = tag.ok_or_else(|| usage("missing AES CMAC tag"))?;
            session.verify_aes_cmac(&key, message, tag)?;
            Ok(Output::Structured(
                json!({"verified":true,"algorithm":"aes-cmac"}),
            ))
        }
        _ => Err(usage("unknown AES CMAC command")),
    }
}
