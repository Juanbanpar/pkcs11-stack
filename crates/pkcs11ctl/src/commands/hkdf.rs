// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{Output, signing::digest};
use crate::support::*;
use clap::ArgMatches;
use pkcs11_client::{HkdfOutput, HkdfRequest, ManagementSession, object_reference};
use serde_json::json;

pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "hkdf-capabilities" | "derive-hkdf" | "derive-hybrid")
}

pub(crate) fn mutation(name: &str) -> bool {
    matches!(name, "derive-hkdf" | "derive-hybrid")
}

fn hkdf_request<'a>(
    m: &'a ArgMatches,
    inputs: &'a Inputs,
    id: &'a [u8],
) -> Result<HkdfRequest<'a>> {
    let output = match need(m, "kind")? {
        "aes128" => HkdfOutput::Aes128,
        "aes192" => HkdfOutput::Aes192,
        "aes256" => HkdfOutput::Aes256,
        "derivation-secret" => HkdfOutput::DerivationSecret {
            length: number(m, "length")?,
        },
        _ => return Err(usage("unsupported HKDF output type")),
    };
    if !matches!(output, HkdfOutput::DerivationSecret { .. }) && get(m, "length").is_some() {
        return Err(usage("--length applies only to derivation-secret"));
    }
    Ok(HkdfRequest {
        digest: digest(need(m, "digest")?),
        salt: &inputs.salt,
        info: &inputs.info,
        output,
        id,
        label: need(m, "label")?.as_bytes(),
    })
}

#[derive(Default)]
pub(crate) struct Inputs {
    salt: Vec<u8>,
    info: Vec<u8>,
}

impl Inputs {
    pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        let mut inputs = Self::default();
        if selected(name) && uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
            return Err(usage(
                "object URI type does not match the selected key operation",
            ));
        }
        if matches!(name, "derive-hkdf" | "derive-hybrid") {
            for (name, target) in [
                ("salt-file", &mut inputs.salt),
                ("info-file", &mut inputs.info),
            ] {
                if let Some(path) = get(m, name) {
                    if path == "-" {
                        return Err(usage("HKDF salt/info require file paths"));
                    }
                    *target = bounded_input(path, 4096)?;
                }
            }
            let id = unhex(need(m, "id")?)?;
            let request = hkdf_request(m, &inputs, &id)?;
            if name == "derive-hybrid" {
                if uri(m, "post-quantum")?.path_attribute("type") != Some(b"secret-key") {
                    return Err(usage("post-quantum URI requires type=secret-key"));
                }
                request
                    .validate_hybrid()
                    .map_err(pkcs11_client::Error::from)?;
            } else {
                request.validate().map_err(pkcs11_client::Error::from)?;
            }
        }

        Ok(inputs)
    }
}

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let reference = object_reference(uri(m, "object")?)?;
    let value = match name {
        "hkdf-capabilities" => {
            let caps = session.hkdf_capabilities(&reference, digest(need(m, "digest")?))?;
            json!({"digest":need(m,"digest")?,"input_length":caps.input_length})
        }
        "derive-hkdf" | "derive-hybrid" => {
            let id = unhex(need(m, "id")?)?;
            let request = hkdf_request(m, inputs, &id)?;
            if name == "derive-hybrid" {
                session.derive_hybrid_hkdf(
                    &reference,
                    &object_reference(uri(m, "post-quantum")?)?,
                    &request,
                )?;
            } else {
                session.derive_hkdf(&reference, &request)?;
            }
            json!({"derived":true,"id_hex":hex(&id),"kind":need(m,"kind")?,"length":request.output.length(),"extractable":false})
        }

        _ => unreachable!(),
    };
    Ok(Output::Structured(value))
}
