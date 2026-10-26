// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output, VerificationCertificate, verify},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{Client, MlDsaHedging, MlDsaParameterSet, MlDsaRequest, MlDsaSigningPolicy};
use serde_json::{Value, json};

pub(crate) fn parameter(value: Option<&str>) -> Option<MlDsaParameterSet> {
    match value {
        Some("ml-dsa-44") => Some(MlDsaParameterSet::MlDsa44),
        Some("ml-dsa-65") => Some(MlDsaParameterSet::MlDsa65),
        Some("ml-dsa-87") => Some(MlDsaParameterSet::MlDsa87),
        _ => None,
    }
}
pub(crate) fn selected(m: &ArgMatches) -> bool {
    parameter(get(m, "algorithm")).is_some() || get(m, "key-family") == Some("ml-dsa")
}
pub(crate) fn validate_options(m: &ArgMatches) -> Result<()> {
    if ["digest", "mgf-digest", "salt-length", "hashing"]
        .iter()
        .any(|name| get(m, name).is_some())
        || get(m, "input-kind") == Some("digest")
    {
        return Err(usage(
            "pure ML-DSA does not accept digests, prehash input, PSS parameters or hashing policies",
        ));
    }
    Ok(())
}
pub(crate) fn request<'a>(
    m: &ArgMatches,
    message: &'a [u8],
    context: &'a [u8],
) -> Result<MlDsaRequest<'a>> {
    let request = MlDsaRequest {
        parameter_set: parameter(get(m, "algorithm"))
            .ok_or_else(|| usage("expected an ML-DSA algorithm"))?,
        message,
        context,
        hedging: match get(m, "hedging").unwrap_or("required") {
            "preferred" => MlDsaHedging::Preferred,
            "deterministic" => MlDsaHedging::Deterministic,
            _ => MlDsaHedging::Required,
        },
    };
    request.validate().map_err(pkcs11_client::Error::from)?;
    Ok(request)
}
pub(crate) fn key_info(parameter: MlDsaParameterSet) -> Value {
    let name = match parameter {
        MlDsaParameterSet::MlDsa44 => "ml-dsa-44",
        MlDsaParameterSet::MlDsa65 => "ml-dsa-65",
        MlDsaParameterSet::MlDsa87 => "ml-dsa-87",
    };
    json!({"type":"ml-dsa", "parameter_set":name})
}
pub(crate) fn client_operation(
    client: &Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let auth = || inputs.credential.auth(false);
    if name == "verify" {
        let certificate = client.ml_dsa_certificate(uri(m, "certificate")?, auth())?;
        return verify(&VerificationCertificate::MlDsa(certificate), m, inputs)
            .map(Output::Structured);
    }
    if name == "certificate" {
        let certificate = client.ml_dsa_certificate(uri(m, "object")?, auth())?;
        return Ok(Output::Structured(
            json!({"key":key_info(certificate.parameter_set()), "der_length":certificate.der().len(), "spki_hex":hex(certificate.spki_der()), "trust_validated":false}),
        ));
    }
    let key = client.private_key(uri(m, "key")?, auth())?;
    let policy = MlDsaSigningPolicy::default();
    let value = match name {
        "capabilities" => {
            let caps = client.ml_dsa_capabilities(&key, auth())?;
            json!({"key":key_info(caps.parameter_set), "can_sign":caps.can_sign, "always_authenticate":caps.always_authenticate})
        }
        "plan" => {
            let request = request(m, &inputs.bytes, &inputs.domain_context)?;
            let caps = client.ml_dsa_capabilities(&key, auth())?;
            caps.validate(&request, &policy)
                .map_err(pkcs11_client::Error::from)?;
            json!({"key":key_info(caps.parameter_set), "context_length":request.context.len(), "hedging":get(m,"hedging").unwrap_or("required"), "context_authentication":caps.always_authenticate})
        }
        "bind" => {
            let certificate = client.ml_dsa_certificate(uri(m, "certificate")?, auth())?;
            let identity = client.bind_ml_dsa_identity(
                key,
                certificate,
                &policy,
                auth(),
                inputs.context.pin(),
            )?;
            json!({"bound":true, "key":key_info(identity.certificate().parameter_set()), "trust_validated":false})
        }
        "sign" => {
            let request = request(m, &inputs.bytes, &inputs.domain_context)?;
            let signature = if get(m, "certificate").is_some() {
                let certificate = client.ml_dsa_certificate(uri(m, "certificate")?, auth())?;
                certificate.validate_signing_request(&request)?;
                client
                    .ml_dsa_capabilities(&key, auth())?
                    .validate(&request, &policy)
                    .map_err(pkcs11_client::Error::from)?;
                let identity = client.bind_ml_dsa_identity(
                    key,
                    certificate,
                    &policy,
                    auth(),
                    inputs.context.pin(),
                )?;
                client.sign_ml_dsa_identity(
                    &identity,
                    &request,
                    &policy,
                    auth(),
                    inputs.context.pin(),
                )?
            } else {
                client.sign_ml_dsa(&key, &request, &policy, auth(), inputs.context.pin())?
            };
            return Ok(Output::Binary(signature));
        }
        _ => unreachable!(),
    };
    Ok(Output::Structured(value))
}
