// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI EdDSA (Ed25519/Ed448) workflows.

use crate::{operations::Inputs, operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{Client, EdDsaCurve, EdDsaRequest};
use serde_json::json;

pub(crate) fn selected(m: &ArgMatches) -> bool {
    matches!(get(m, "algorithm"), Some("ed25519") | Some("ed448"))
}

fn curve(value: &str) -> Result<EdDsaCurve> {
    match value {
        "ed25519" => Ok(EdDsaCurve::Ed25519),
        "ed448" => Ok(EdDsaCurve::Ed448),
        _ => Err(usage("expected ed25519 or ed448")),
    }
}

pub(crate) fn request<'a>(m: &ArgMatches, message: &'a [u8]) -> Result<EdDsaRequest<'a>> {
    Ok(EdDsaRequest {
        curve: curve(need(m, "algorithm")?)?,
        message,
    })
}

pub(crate) fn validate_options(m: &ArgMatches) -> Result<()> {
    if ["digest", "mgf-digest", "salt-length", "hashing"]
        .iter()
        .any(|name| get(m, name).is_some())
        || get(m, "input-kind") == Some("digest")
        || flag(m, "allow-sha1")
    {
        return Err(usage(
            "pure EdDSA does not accept digests, prehash input, PSS parameters or hashing policies",
        ));
    }
    Ok(())
}

pub(crate) fn client_operation(
    client: &Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let auth = || inputs.credential.auth(false);
    if name == "verify" {
        if let Some(key_uri) = get(m, "key") {
            let key = client.public_key(
                key_uri.parse().map_err(|_| usage("invalid key URI"))?,
                auth(),
            )?;
            client.verify_eddsa(&key, &request(m, &inputs.bytes)?, &inputs.signature, auth())?;
            return Ok(Output::Structured(
                json!({"verified":true,"trust_validated":false,"verification":"token"}),
            ));
        }
        let certificate = client.eddsa_certificate(uri(m, "certificate")?, auth())?;
        certificate.verify_signature(&request(m, &inputs.bytes)?, &inputs.signature)?;
        return Ok(Output::Structured(
            json!({"verified":true,"trust_validated":false}),
        ));
    }
    if name == "certificate" {
        let certificate = client.eddsa_certificate(uri(m, "object")?, auth())?;
        return Ok(Output::Structured(json!({
            "key": {"algorithm":"eddsa","curve":certificate.curve().to_string()},
            "der_length": certificate.der().len(),
            "spki_hex": hex(certificate.spki_der()),
            "trust_validated": false,
        })));
    }
    let key = client.private_key(uri(m, "key")?, auth())?;
    let value = match name {
        "capabilities" => {
            let caps = client.eddsa_capabilities(&key, auth())?;
            json!({
                "key": {"algorithm":"eddsa","curve":caps.curve.to_string()},
                "can_sign": caps.can_sign,
                "always_authenticate": caps.always_authenticate,
            })
        }
        "plan" => {
            let request = request(m, &inputs.bytes)?;
            json!({
                "key": {"algorithm":"eddsa","curve":request.curve.to_string()},
                "message_length": request.message.len(),
            })
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
        _ => return Err(usage("unsupported EdDSA command")),
    };
    Ok(Output::Structured(value))
}
