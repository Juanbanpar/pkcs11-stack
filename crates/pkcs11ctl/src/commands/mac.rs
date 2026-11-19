// SPDX-License-Identifier: MIT OR Apache-2.0
use super::Output;
use crate::support::*;
use clap::ArgMatches;
use pkcs11_client::{MacAlgorithm, ManagementSession, object_reference};

use serde_json::json;

fn mac(value: &str) -> Result<MacAlgorithm> {
    Ok(match value {
        "hmac-sha1" => MacAlgorithm::HmacSha1,
        "hmac-sha224" => MacAlgorithm::HmacSha224,
        "hmac-sha256" => MacAlgorithm::HmacSha256,
        "hmac-sha384" => MacAlgorithm::HmacSha384,
        "hmac-sha512" => MacAlgorithm::HmacSha512,
        "aes-cmac" => MacAlgorithm::AesCmac,
        _ => return Err(usage("unsupported MAC algorithm")),
    })
}

pub(crate) fn validate(m: &ArgMatches) -> Result<()> {
    mac(need(m, "algorithm")?)?;
    Ok(())
}

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    bytes: &[u8],
    tag: &[u8],
) -> Result<Output> {
    match name {
        "mac" => {
            let key = object_reference(uri(m, "object")?)?;
            let algorithm = mac(need(m, "algorithm")?)?;
            let output = if flag(m, "multipart") {
                session.mac_chunks(&key, algorithm, chunks(bytes))?
            } else {
                session.mac(&key, algorithm, bytes)?
            };
            Ok(Output::Binary(output))
        }
        "verify-mac" => {
            let key = object_reference(uri(m, "object")?)?;
            let algorithm = mac(need(m, "algorithm")?)?;
            if flag(m, "multipart") {
                session.verify_mac_chunks(&key, algorithm, chunks(bytes), tag)?;
            } else {
                session.verify_mac(&key, algorithm, bytes, tag)?;
            }
            Ok(Output::Structured(json!({"verified":true})))
        }

        _ => unreachable!(),
    }
}
