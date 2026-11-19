// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::ArgMatches;
use serde_json::json;

use crate::support::*;

use super::super::{Output, inspect};
use super::{Inputs, VerificationCertificate, request, verify};

pub(super) fn client_operation(
    client: &pkcs11_client::Client<'_>,
    name: &str,
    m: &ArgMatches,
    credential: &Credential,
    bytes: &[u8],
    inputs: &Inputs,
) -> Result<Output> {
    let auth = || credential.auth(false);
    if name == "verify" {
        if let Some(key_uri) = get(m, "key") {
            let key = client.public_key(
                key_uri.parse().map_err(|_| usage("invalid key URI"))?,
                auth(),
            )?;
            client.verify(
                &key,
                &pkcs11_client::VerifyRequest {
                    parameters: request(m, bytes)?,
                    signature: &inputs.signature,
                },
                auth(),
            )?;
            return Ok(Output::Structured(
                json!({"verified":true,"trust_validated":false,"verification":"token"}),
            ));
        }
        return verify(
            &VerificationCertificate::Classical(
                client.certificate(uri(m, "certificate")?, auth())?,
            ),
            m,
            bytes,
            inputs,
        )
        .map(Output::Structured);
    }
    if name == "certificate" {
        let cert = client.certificate(uri(m, "object")?, auth())?;
        return Ok(Output::Structured(
            json!({"key":inspect::key_kind(cert.key_kind()),"der_length":cert.der().len(),"spki_hex":hex(cert.spki_der()),"trust_validated":false}),
        ));
    }
    let key = client.private_key(uri(m, "key")?, auth())?;
    let result = match name {
        "capabilities" => {
            let caps = client.capabilities(&key, auth())?;
            let metadata = client.public_metadata(&key, auth())?;
            json!({"key":inspect::key_kind(caps.key),"can_sign":caps.can_sign,"always_authenticate":caps.always_authenticate,"allowed_mechanisms":caps.allowed_mechanisms.map(|v|v.iter().map(|m|format!("{m:?}")).collect::<Vec<_>>()),"mechanisms":caps.mechanisms.iter().map(|m|json!({"name":format!("{:?}",m.mechanism),"can_sign":m.can_sign,"minimum_bits":m.minimum_bits,"maximum_bits":m.maximum_bits})).collect::<Vec<_>>(),"public_metadata":{"modulus_hex":metadata.modulus.as_deref().map(hex),"exponent_hex":metadata.public_exponent.as_deref().map(hex),"ec_params_hex":metadata.ec_params.as_deref().map(hex),"ec_point_hex":metadata.ec_point.as_deref().map(hex),"spki_hex":metadata.spki.as_deref().map(hex)}})
        }
        "plan" => {
            let request = request(m, bytes)?;
            let plan = client.plan(&key, &request, auth())?;
            json!({"mechanism":format!("{:?}",plan.mechanism()),"hash_location":format!("{:?}",plan.hash_location()),"context_authentication":plan.context_authentication()})
        }
        "bind" => {
            let certificate = client.certificate(uri(m, "certificate")?, auth())?;
            let identity = client.bind_identity(key, certificate, auth(), inputs.context.pin())?;
            json!({"bound":true,"key":inspect::key_kind(identity.certificate().key_kind()),"trust_validated":false})
        }
        "sign" => {
            let request = request(m, bytes)?;
            let signature = if get(m, "certificate").is_some() {
                let certificate = client.certificate(uri(m, "certificate")?, auth())?;
                certificate.validate_signing_request(&request)?;
                client.plan(&key, &request, auth())?;
                let identity =
                    client.bind_identity(key, certificate, auth(), inputs.context.pin())?;
                client.sign_identity(&identity, &request, auth(), inputs.context.pin())?
            } else {
                client.sign(&key, &request, auth(), inputs.context.pin())?
            };
            return Ok(Output::Binary(signature));
        }
        _ => unreachable!(),
    };
    Ok(Output::Structured(result))
}
