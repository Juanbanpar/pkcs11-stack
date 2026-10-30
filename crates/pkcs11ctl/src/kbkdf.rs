// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Output, digest},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    DigestAlgorithm, KbkdfMode, KbkdfOutput, KbkdfPrf, KbkdfPrfRequest, ManagementSession,
    object_reference,
};
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "kbkdf-capabilities" | "derive-kbkdf")
}
#[derive(Default)]
pub(crate) struct Inputs {
    label: Vec<u8>,
    context: Vec<u8>,
    iv: Vec<u8>,
}
impl Inputs {
    pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        let mut inputs = Self::default();
        if !selected(name) {
            return Ok(inputs);
        }
        if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
            return Err(usage("SP800-108 requires type=secret-key"));
        }
        if get(m, "prf") == Some("aes-cmac") && get(m, "digest").is_some() {
            return Err(usage("AES-CMAC does not accept --digest"));
        }
        if name == "derive-kbkdf" {
            for (name, value) in [
                ("kdf-label-file", &mut inputs.label),
                ("kdf-context-file", &mut inputs.context),
            ] {
                if let Some(path) = get(m, name) {
                    if path == "-" {
                        return Err(usage("SP800-108 label/context require file paths"));
                    }
                    *value = bounded_input(path, 4096)?;
                }
            }
            if let Some(path) = get(m, "kdf-iv-file") {
                if mode(m)? != KbkdfMode::Feedback || path == "-" {
                    return Err(usage(
                        "--kdf-iv-file requires feedback mode and a file path",
                    ));
                }
                inputs.iv = bounded_input(path, 64)?;
            }
            let id = unhex(need(m, "id")?)?;
            inputs
                .request(m, &id)?
                .validate_with_mode(mode(m)?, &inputs.iv)
                .map_err(pkcs11_client::Error::from)?;
        }
        Ok(inputs)
    }
    fn request<'a>(&'a self, m: &'a ArgMatches, id: &'a [u8]) -> Result<KbkdfPrfRequest<'a>> {
        let output = match need(m, "kind")? {
            "aes128" => KbkdfOutput::Aes128,
            "aes192" => KbkdfOutput::Aes192,
            "aes256" => KbkdfOutput::Aes256,
            "derivation-secret" => KbkdfOutput::DerivationSecret {
                length: number(m, "length")?,
            },
            _ => return Err(usage("unsupported SP800-108 output")),
        };
        if !matches!(output, KbkdfOutput::DerivationSecret { .. }) && get(m, "length").is_some() {
            return Err(usage("--length applies only to derivation-secret"));
        }
        let prf = if get(m, "prf") == Some("aes-cmac") {
            KbkdfPrf::AesCmac
        } else {
            KbkdfPrf::try_from(digest(need(m, "digest")?)).map_err(pkcs11_client::Error::from)?
        };
        Ok(KbkdfPrfRequest {
            prf,
            kdf_label: &self.label,
            context: &self.context,
            output,
            id,
            label: need(m, "label")?.as_bytes(),
        })
    }
}
fn mode(m: &ArgMatches) -> Result<KbkdfMode> {
    match need(m, "mode")? {
        "counter" => Ok(KbkdfMode::Counter),
        "feedback" => Ok(KbkdfMode::Feedback),
        "double-pipeline" => Ok(KbkdfMode::DoublePipeline),
        _ => Err(usage("unsupported SP800-108 mode")),
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let base = object_reference(uri(m, "object")?)?;
    let value = if name == "kbkdf-capabilities" {
        if get(m, "prf") == Some("aes-cmac") {
            let caps = session.kbkdf_prf_capabilities(&base, KbkdfPrf::AesCmac, mode(m)?)?;
            return Ok(Output::Structured(
                json!({"advisory":true,"prf":"aes-cmac","mode":need(m,"mode")?,"input_length":caps.input_length,"prf_output_length":16,"counter_bits":32,"length_bits":32,"separator":true}),
            ));
        }
        let caps = session.kbkdf_capabilities_with_mode(&base, mode(m)?)?;
        let digests: Vec<_> = [
            (DigestAlgorithm::Sha256, "sha256"),
            (DigestAlgorithm::Sha384, "sha384"),
            (DigestAlgorithm::Sha512, "sha512"),
        ]
        .into_iter()
        .filter_map(|(digest, name)| caps.supports(digest).then_some(name))
        .collect();
        json!({"advisory":true,"mode":need(m,"mode")?,"input_length":caps.input_length,"digests":digests,"counter_bits":32,"length_bits":32,"separator":true})
    } else {
        let id = unhex(need(m, "id")?)?;
        let request = inputs.request(m, &id)?;
        session.derive_kbkdf_prf(&base, &request, mode(m)?, &inputs.iv)?;
        let mut value = json!({"derived":true,"mode":need(m,"mode")?,"kind":need(m,"kind")?,"length":request.output.length(),"id_hex":hex(&id),"extractable":false});
        if request.prf == KbkdfPrf::AesCmac {
            value["prf"] = json!("aes-cmac");
        } else {
            value["digest"] = json!(need(m, "digest")?);
        }
        value
    };
    Ok(Output::Structured(value))
}
