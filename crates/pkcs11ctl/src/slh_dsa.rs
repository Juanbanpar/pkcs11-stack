// SPDX-License-Identifier: MIT OR Apache-2.0
//! SLH-DSA CLI signing workflows over `pkcs11-client`.

use crate::{
    operations::{Inputs, Output},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    Client, SlhDsaHedging, SlhDsaParameterSet, SlhDsaRequest, SlhDsaSigningPolicy,
};
use serde_json::{Value, json};

pub(crate) fn parameter(value: Option<&str>) -> Option<SlhDsaParameterSet> {
    use SlhDsaParameterSet as P;
    Some(match value? {
        "slh-dsa-sha2-128s" => P::Sha2_128S,
        "slh-dsa-sha2-128f" => P::Sha2_128F,
        "slh-dsa-sha2-192s" => P::Sha2_192S,
        "slh-dsa-sha2-192f" => P::Sha2_192F,
        "slh-dsa-sha2-256s" => P::Sha2_256S,
        "slh-dsa-sha2-256f" => P::Sha2_256F,
        "slh-dsa-shake-128s" => P::Shake128S,
        "slh-dsa-shake-128f" => P::Shake128F,
        "slh-dsa-shake-192s" => P::Shake192S,
        "slh-dsa-shake-192f" => P::Shake192F,
        "slh-dsa-shake-256s" => P::Shake256S,
        "slh-dsa-shake-256f" => P::Shake256F,
        _ => return None,
    })
}

pub(crate) fn selected(m: &ArgMatches) -> bool {
    parameter(get(m, "algorithm")).is_some()
}

pub(crate) fn validate_options(m: &ArgMatches) -> Result<()> {
    if ["digest", "mgf-digest", "salt-length", "hashing"]
        .iter()
        .any(|name| get(m, name).is_some())
        || get(m, "input-kind") == Some("digest")
        || flag(m, "allow-sha224")
    {
        return Err(usage(
            "pure SLH-DSA does not accept digests, prehash input, PSS parameters or hashing policies",
        ));
    }
    Ok(())
}

pub(crate) fn request<'a>(
    m: &ArgMatches,
    message: &'a [u8],
    context: &'a [u8],
) -> Result<SlhDsaRequest<'a>> {
    let request = SlhDsaRequest {
        parameter_set: parameter(get(m, "algorithm"))
            .ok_or_else(|| usage("expected an SLH-DSA algorithm"))?,
        message,
        context,
        hedging: match get(m, "hedging").unwrap_or("required") {
            "preferred" => SlhDsaHedging::Preferred,
            "deterministic" => SlhDsaHedging::Deterministic,
            _ => SlhDsaHedging::Required,
        },
    };
    request.validate().map_err(pkcs11_client::Error::from)?;
    Ok(request)
}

fn key_info(parameter: SlhDsaParameterSet) -> Value {
    let name = match parameter {
        SlhDsaParameterSet::Sha2_128S => "slh-dsa-sha2-128s",
        SlhDsaParameterSet::Sha2_128F => "slh-dsa-sha2-128f",
        SlhDsaParameterSet::Sha2_192S => "slh-dsa-sha2-192s",
        SlhDsaParameterSet::Sha2_192F => "slh-dsa-sha2-192f",
        SlhDsaParameterSet::Sha2_256S => "slh-dsa-sha2-256s",
        SlhDsaParameterSet::Sha2_256F => "slh-dsa-sha2-256f",
        SlhDsaParameterSet::Shake128S => "slh-dsa-shake-128s",
        SlhDsaParameterSet::Shake128F => "slh-dsa-shake-128f",
        SlhDsaParameterSet::Shake192S => "slh-dsa-shake-192s",
        SlhDsaParameterSet::Shake192F => "slh-dsa-shake-192f",
        SlhDsaParameterSet::Shake256S => "slh-dsa-shake-256s",
        SlhDsaParameterSet::Shake256F => "slh-dsa-shake-256f",
    };
    json!({"type":"slh-dsa","parameter_set":name})
}

pub(crate) fn client_operation(
    client: &Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    if name == "verify" {
        return Err(usage(
            "SLH-DSA verification is not exposed through the certificate CLI; use the client API",
        ));
    }
    let auth = || inputs.credential.auth(false);
    let key = client.private_key(uri(m, "key")?, auth())?;
    let policy = SlhDsaSigningPolicy::default();
    let value = match name {
        "capabilities" => {
            let caps = client.slh_dsa_capabilities(&key, auth())?;
            json!({"key":key_info(caps.parameter_set), "can_sign":caps.can_sign, "always_authenticate":caps.always_authenticate})
        }
        "plan" => {
            let request = request(m, &inputs.bytes, &inputs.domain_context)?;
            let caps = client.slh_dsa_capabilities(&key, auth())?;
            caps.validate(&request, &policy)
                .map_err(pkcs11_client::Error::from)?;
            json!({"key":key_info(caps.parameter_set), "context_length":request.context.len(), "hedging":get(m,"hedging").unwrap_or("required"), "context_authentication":caps.always_authenticate})
        }
        "sign" => {
            let request = request(m, &inputs.bytes, &inputs.domain_context)?;
            return Ok(Output::Binary(client.sign_slh_dsa(
                &key,
                &request,
                &policy,
                auth(),
                inputs.context.pin(),
            )?));
        }
        _ => return Err(usage("unsupported SLH-DSA command")),
    };
    Ok(Output::Structured(value))
}
