// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    HmacAlgorithm, HmacTagProfile, MacOperation, ManagementSession, object_reference,
};
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "hmac-capabilities" | "mac-hmac" | "verify-hmac")
}
fn algorithm(m: &ArgMatches) -> Result<HmacAlgorithm> {
    crate::generation::hmac(need(m, "algorithm")?)
        .ok_or_else(|| usage("unsupported HMAC algorithm"))
}
fn profile(m: &ArgMatches, algorithm: HmacAlgorithm) -> Result<HmacTagProfile> {
    let profile = if get(m, "tag-length").is_some() {
        HmacTagProfile::General {
            tag_length: number(m, "tag-length")?,
        }
    } else {
        HmacTagProfile::Full
    };
    profile.validate(algorithm).map_err(|_| {
        usage("HMAC tag length must be half the hash output through its full length")
    })?;
    Ok(profile)
}
pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Option<Vec<u8>>> {
    if !selected(name) {
        return Ok(None);
    }
    if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
        return Err(usage("HMAC requires type=secret-key"));
    }
    if name == "hmac-capabilities" {
        return Ok(None);
    }
    let algorithm = algorithm(m)?;
    let tag_length = profile(m, algorithm)?.tag_length(algorithm);
    if name == "verify-hmac" {
        let path = need(m, "tag-file")?;
        if path == "-" {
            return Err(usage("tag-file requires a file path"));
        }
        let tag = bounded_input(path, tag_length)?;
        if tag.len() != tag_length {
            return Err(usage("HMAC requires the exact selected tag length"));
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
    multipart: Option<&crate::mac_input::MultipartInput>,
) -> Result<Output> {
    let key = object_reference(uri(m, "object")?)?;
    match name {
        "hmac-capabilities" => {
            let direction = if need(m, "operation")? == "generate" {
                MacOperation::Generate
            } else {
                MacOperation::Verify
            };
            let general = flag(m, "general-tag");
            let caps = if general {
                session.hmac_general_capabilities(&key, direction)?
            } else {
                session.hmac_capabilities(&key, direction)?
            };
            Ok(Output::Structured(
                json!({"advisory":true,"general_tag":general,"key_length":caps.key_length,"operation":need(m,"operation")?,"algorithms":HmacAlgorithm::ALL.into_iter().filter(|a|caps.supports(*a)).map(|a|a.to_string()).collect::<Vec<_>>()}),
            ))
        }
        "mac-hmac" => {
            let algorithm = algorithm(m)?;
            let profile = profile(m, algorithm)?;
            let tag = if let Some(input) = multipart {
                input
                    .read(|mut reader| session.hmac_reader(&key, algorithm, profile, &mut reader))?
            } else {
                session.mac_hmac_with_profile(&key, algorithm, message, profile)?
            };
            Ok(Output::Binary(tag))
        }
        "verify-hmac" => {
            let algorithm = algorithm(m)?;
            let tag = tag.ok_or_else(|| usage("missing HMAC tag"))?;
            let profile = profile(m, algorithm)?;
            if let Some(input) = multipart {
                input.read(|mut reader| {
                    session.verify_hmac_reader(&key, algorithm, profile, &mut reader, tag)
                })?;
            } else {
                session.verify_hmac_with_profile(&key, algorithm, message, tag, profile)?;
            }
            Ok(Output::Structured(
                json!({"verified":true,"algorithm":algorithm.to_string(),"tag_length":profile.tag_length(algorithm),"general_tag":matches!(profile, HmacTagProfile::General { .. })}),
            ))
        }
        _ => Err(usage("unknown HMAC command")),
    }
}
