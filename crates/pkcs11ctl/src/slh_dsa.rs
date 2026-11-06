// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    ManagementSession, PrivateKeyRef, PublicKeyRef, SlhDsaHedging, SlhDsaKeyPairRequest,
    SlhDsaParameterSet, SlhDsaRequest, SlhDsaSigningPolicy,
};
use serde_json::json;
pub(crate) const NAMES: [&str; 12] = [
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-192f",
    "slh-dsa-sha2-256s",
    "slh-dsa-sha2-256f",
    "slh-dsa-shake-128s",
    "slh-dsa-shake-128f",
    "slh-dsa-shake-192s",
    "slh-dsa-shake-192f",
    "slh-dsa-shake-256s",
    "slh-dsa-shake-256f",
];
pub(crate) fn selected(command: &str) -> bool {
    matches!(
        command,
        "slh-dsa-generation-options"
            | "generate-slh-dsa"
            | "slh-dsa-capabilities"
            | "sign-slh-dsa"
            | "verify-slh-dsa"
            | "export-slh-dsa-public"
    )
}
pub(crate) fn name(parameter: SlhDsaParameterSet) -> &'static str {
    NAMES[SlhDsaParameterSet::ALL
        .iter()
        .position(|p| *p == parameter)
        .expect("standard parameter set")]
}
fn parameter(m: &ArgMatches) -> Result<SlhDsaParameterSet> {
    let value = need(m, "parameter-set")?;
    NAMES
        .iter()
        .position(|p| *p == value)
        .map(|i| SlhDsaParameterSet::ALL[i])
        .ok_or_else(|| usage("expected an SLH-DSA parameter set"))
}
pub(crate) fn signature_limit(m: &ArgMatches) -> Result<usize> {
    Ok(parameter(m)?.signature_length())
}
fn request<'a>(m: &ArgMatches, message: &'a [u8], context: &'a [u8]) -> Result<SlhDsaRequest<'a>> {
    Ok(SlhDsaRequest {
        parameter_set: parameter(m)?,
        message,
        context,
        hedging: match get(m, "hedging").unwrap_or("required") {
            "preferred" => SlhDsaHedging::Preferred,
            "deterministic" => SlhDsaHedging::Deterministic,
            _ => SlhDsaHedging::Required,
        },
    })
}
fn generation<'a>(m: &'a ArgMatches, id: &'a [u8]) -> Result<SlhDsaKeyPairRequest<'a>> {
    Ok(SlhDsaKeyPairRequest {
        parameter_set: parameter(m)?,
        id,
        label: need(m, "label")?.as_bytes(),
        always_authenticate: flag(m, "always-authenticate"),
    })
}
fn id(m: &ArgMatches) -> Result<Vec<u8>> {
    let value = need(m, "id")?;
    if value.len() > 256 {
        return Err(usage("SLH-DSA ID exceeds 128 bytes"));
    }
    unhex(value).map_err(|_| usage("ID requires even-length hexadecimal"))
}
pub(crate) fn validate(
    command: &str,
    m: &ArgMatches,
    bytes: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    if !selected(command) {
        return Ok(());
    }
    if command == "slh-dsa-generation-options" {
        return Ok(());
    }
    if command == "generate-slh-dsa" {
        generation(m, &id(m)?)?
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        return Ok(());
    }
    let public = matches!(command, "verify-slh-dsa" | "export-slh-dsa-public");
    if uri(m, "object")?.path_attribute("type")
        != Some(if public {
            b"public".as_slice()
        } else {
            b"private".as_slice()
        })
    {
        return Err(usage(
            "object URI type does not match the SLH-DSA operation",
        ));
    }
    if matches!(command, "sign-slh-dsa" | "verify-slh-dsa") {
        let request = request(m, bytes, context)?;
        request.validate().map_err(pkcs11_client::Error::from)?;
        if command == "verify-slh-dsa"
            && signature.len() != request.parameter_set.signature_length()
        {
            return Err(usage(
                "signature length does not match the SLH-DSA parameter set",
            ));
        }
    }
    Ok(())
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    command: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    if command == "generate-slh-dsa" {
        let id = id(m)?;
        let request = generation(m, &id)?;
        session.generate_slh_dsa_key_pair(&request)?;
        return Ok(Output::Structured(
            json!({"generated":true,"parameter_set":name(request.parameter_set),"id_hex":hex(&id)}),
        ));
    }
    if command == "export-slh-dsa-public" {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        return Ok(Output::Binary(session.export_slh_dsa_public_key(&key)?));
    }
    if command == "verify-slh-dsa" {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        session.verify_slh_dsa(
            &key,
            &request(m, &inputs.bytes, &inputs.domain_context)?,
            &inputs.signature,
        )?;
        return Ok(Output::Structured(
            json!({"verified":true,"verification":"token"}),
        ));
    }
    let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
    if command == "slh-dsa-capabilities" {
        let caps = session.slh_dsa_capabilities(&key)?;
        return Ok(Output::Structured(
            json!({"advisory":true,"parameter_set":name(caps.parameter_set),"can_sign":caps.can_sign,"always_authenticate":caps.always_authenticate}),
        ));
    }
    let signature = session.sign_slh_dsa(
        &key,
        &request(m, &inputs.bytes, &inputs.domain_context)?,
        &SlhDsaSigningPolicy::default(),
        inputs.context.pin(),
    )?;
    Ok(Output::Binary(signature))
}
