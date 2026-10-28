// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output, VerificationCertificate, verify},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{Client, EdDsaCurve, EdDsaRequest};
use serde_json::{Value, json};

pub(crate) fn curve(value: Option<&str>) -> Option<EdDsaCurve> {
    match value {
        Some("ed25519") => Some(EdDsaCurve::Ed25519),
        Some("ed448") => Some(EdDsaCurve::Ed448),
        _ => None,
    }
}
pub(crate) fn selected(m: &ArgMatches) -> bool {
    curve(get(m, "algorithm")).is_some() || get(m, "key-family") == Some("eddsa")
}
pub(crate) fn validate_options(m: &ArgMatches) -> Result<()> {
    if [
        "digest",
        "mgf-digest",
        "salt-length",
        "hashing",
        "context-file",
        "hedging",
    ]
    .iter()
    .any(|name| get(m, name).is_some())
        || get(m, "input-kind") == Some("digest")
    {
        return Err(usage(
            "pure EdDSA does not accept digests, prehash input, PSS parameters or hashing policies",
        ));
    }
    Ok(())
}
pub(crate) fn request<'a>(m: &ArgMatches, message: &'a [u8]) -> Result<EdDsaRequest<'a>> {
    Ok(EdDsaRequest {
        curve: curve(get(m, "algorithm")).ok_or_else(|| usage("expected ed25519 or ed448"))?,
        message,
    })
}
pub(crate) fn key_info(curve: EdDsaCurve) -> Value {
    json!({"type":"eddsa", "curve":match curve { EdDsaCurve::Ed25519=>"ed25519", EdDsaCurve::Ed448=>"ed448" }})
}
pub(crate) fn client_operation(
    client: &Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let auth = || inputs.credential.auth(false);
    if name == "verify" {
        let certificate = client.eddsa_certificate(uri(m, "certificate")?, auth())?;
        return verify(&VerificationCertificate::EdDsa(certificate), m, inputs)
            .map(Output::Structured);
    }
    if name == "certificate" {
        let certificate = client.eddsa_certificate(uri(m, "object")?, auth())?;
        return Ok(Output::Structured(
            json!({"key":key_info(certificate.curve()), "der_length":certificate.der().len(), "spki_hex":hex(certificate.spki_der()), "trust_validated":false}),
        ));
    }
    if name == "verify-token" {
        let key =
            pkcs11_client::PublicKeyRef::new(uri(m, "key")?).map_err(pkcs11_client::Error::from)?;
        client.verify_eddsa(&key, &request(m, &inputs.bytes)?, &inputs.signature, auth())?;
        return Ok(Output::Structured(
            json!({"verified":true,"trust_validated":false}),
        ));
    }
    let key = client.private_key(uri(m, "key")?, auth())?;
    let value = match name {
        "capabilities" => {
            let caps = client.eddsa_capabilities(key.as_object_ref(), auth())?;
            json!({"key":key_info(caps.curve), "can_sign":caps.can_sign, "always_authenticate":caps.always_authenticate})
        }
        "plan" => {
            let request = request(m, &inputs.bytes)?;
            let caps = client.eddsa_capabilities(key.as_object_ref(), auth())?;
            if !caps.can_sign || caps.curve != request.curve {
                return Err(usage("EdDSA curve or permissions do not match"));
            }
            json!({"key":key_info(caps.curve), "context_authentication":caps.always_authenticate})
        }
        "bind" => {
            let certificate = client.eddsa_certificate(uri(m, "certificate")?, auth())?;
            let identity =
                client.bind_eddsa_identity(key, certificate, auth(), inputs.context.pin())?;
            json!({"bound":true, "key":key_info(identity.certificate().curve()), "trust_validated":false})
        }
        "sign" => {
            let request = request(m, &inputs.bytes)?;
            let signature = if get(m, "certificate").is_some() {
                let certificate = client.eddsa_certificate(uri(m, "certificate")?, auth())?;
                certificate.validate_signing_request(&request)?;
                let identity =
                    client.bind_eddsa_identity(key, certificate, auth(), inputs.context.pin())?;
                client.sign_eddsa_identity(&identity, &request, auth(), inputs.context.pin())?
            } else {
                client.sign_eddsa(&key, &request, auth(), inputs.context.pin())?
            };
            return Ok(Output::Binary(signature));
        }
        _ => unreachable!(),
    };
    Ok(Output::Structured(value))
}
