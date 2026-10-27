// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Output, digest},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    DigestAlgorithm, KbkdfMode, KbkdfOutput, KbkdfRequest, ManagementSession, object_reference,
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
    fn request<'a>(&'a self, m: &'a ArgMatches, id: &'a [u8]) -> Result<KbkdfRequest<'a>> {
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
        Ok(KbkdfRequest {
            digest: digest(need(m, "digest")?),
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
        session.derive_kbkdf_with_mode(&base, &request, mode(m)?, &inputs.iv)?;
        json!({"derived":true,"mode":need(m,"mode")?,"digest":need(m,"digest")?,"kind":need(m,"kind")?,"length":request.output.length(),"id_hex":hex(&id),"extractable":false})
    };
    Ok(Output::Structured(value))
}
