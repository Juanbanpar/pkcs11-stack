// SPDX-License-Identifier: MIT OR Apache-2.0
use super::Output;
use crate::support::*;
use clap::ArgMatches;
use pkcs11_client::{
    KbkdfMode, KbkdfOutput, KbkdfPrf, KbkdfRequest, ManagementSession, object_reference,
};

use serde_json::json;

fn prf(value: &str) -> Result<KbkdfPrf> {
    Ok(match value {
        "hmac-sha1" => KbkdfPrf::HmacSha1,
        "hmac-sha224" => KbkdfPrf::HmacSha224,
        "hmac-sha256" => KbkdfPrf::HmacSha256,
        "hmac-sha384" => KbkdfPrf::HmacSha384,
        "hmac-sha512" => KbkdfPrf::HmacSha512,
        "aes-cmac" => KbkdfPrf::AesCmac,
        _ => return Err(usage("unsupported SP 800-108 PRF")),
    })
}

fn kdf_mode(value: &str) -> Result<KbkdfMode> {
    Ok(match value {
        "counter" => KbkdfMode::Counter,
        "feedback" => KbkdfMode::Feedback,
        "double-pipeline" => KbkdfMode::DoublePipeline,
        _ => return Err(usage("unsupported SP 800-108 mode")),
    })
}

fn output(kind: &str, length: Option<usize>) -> Result<KbkdfOutput> {
    Ok(match kind {
        "aes128" => KbkdfOutput::Aes128,
        "aes192" => KbkdfOutput::Aes192,
        "aes256" => KbkdfOutput::Aes256,
        "derivation-secret" => KbkdfOutput::DerivationSecret {
            length: length.ok_or_else(|| usage("derivation-secret requires --length"))?,
        },
        _ => return Err(usage("unsupported KDF output kind")),
    })
}

pub(crate) struct Inputs {
    pub label: Vec<u8>,
    pub context: Vec<u8>,
    pub iv: Vec<u8>,
}

pub(crate) fn validate(m: &ArgMatches) -> Result<()> {
    prf(need(m, "prf")?)?;
    kdf_mode(need(m, "mode")?)?;
    output(
        need(m, "kind")?,
        get(m, "length").map(|_| number(m, "length")).transpose()?,
    )?;
    if get(m, "iv").is_some() {
        unhex(need(m, "iv")?)?;
    }

    Ok(())
}

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let base = object_reference(uri(m, "object")?)?;
    let id = unhex(need(m, "id")?)?;
    let request = KbkdfRequest {
        prf: prf(need(m, "prf")?)?,
        kdf_label: &inputs.label,
        context: &inputs.context,
        output: output(
            need(m, "kind")?,
            get(m, "length").map(|_| number(m, "length")).transpose()?,
        )?,
        id: &id,
        label: need(m, "label")?.as_bytes(),
    };
    session.derive_kbkdf(&base, &request, kdf_mode(need(m, "mode")?)?, &inputs.iv)?;
    Ok(Output::Structured(json!({"derived":true})))
}
