// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI HashML-DSA and HashSLH-DSA signing workflows.

use crate::{operations::Inputs, operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    Client, HashInput, HashMlDsaRequest, HashMlDsaSigningPolicy, HashSlhDsaRequest,
    HashSlhDsaSigningPolicy, MlDsaHedging, MlDsaParameterSet, PrehashAlgorithm, SlhDsaHedging,
    SlhDsaParameterSet,
};
use serde_json::{Value, json};

pub(crate) fn selected(m: &ArgMatches) -> bool {
    matches!(
        get(m, "algorithm"),
        Some("hash-ml-dsa") | Some("hash-slh-dsa")
    )
}

fn prehash(value: &str) -> Result<PrehashAlgorithm> {
    Ok(match value {
        "sha224" => PrehashAlgorithm::Sha224,
        "sha256" => PrehashAlgorithm::Sha256,
        "sha384" => PrehashAlgorithm::Sha384,
        "sha512" => PrehashAlgorithm::Sha512,
        "sha3-224" => PrehashAlgorithm::Sha3_224,
        "sha3-256" => PrehashAlgorithm::Sha3_256,
        "sha3-384" => PrehashAlgorithm::Sha3_384,
        "sha3-512" => PrehashAlgorithm::Sha3_512,
        "shake128" => PrehashAlgorithm::Shake128,
        "shake256" => PrehashAlgorithm::Shake256,
        _ => return Err(usage("unsupported HashML-DSA/HashSLH-DSA prehash")),
    })
}

fn ml_parameter(value: &str) -> Result<MlDsaParameterSet> {
    Ok(match value {
        "ml-dsa-44" => MlDsaParameterSet::MlDsa44,
        "ml-dsa-65" => MlDsaParameterSet::MlDsa65,
        "ml-dsa-87" => MlDsaParameterSet::MlDsa87,
        _ => return Err(usage("unsupported ML-DSA parameter set")),
    })
}

fn slh_parameter(value: &str) -> Result<SlhDsaParameterSet> {
    crate::slh_dsa::parameter(Some(value)).ok_or_else(|| usage("unsupported SLH-DSA parameter set"))
}

fn hedging_ml(m: &ArgMatches) -> MlDsaHedging {
    match get(m, "hedging").unwrap_or("required") {
        "preferred" => MlDsaHedging::Preferred,
        "deterministic" => MlDsaHedging::Deterministic,
        _ => MlDsaHedging::Required,
    }
}

fn hedging_slh(m: &ArgMatches) -> SlhDsaHedging {
    match get(m, "hedging").unwrap_or("required") {
        "preferred" => SlhDsaHedging::Preferred,
        "deterministic" => SlhDsaHedging::Deterministic,
        _ => SlhDsaHedging::Required,
    }
}

fn input<'a>(m: &ArgMatches, bytes: &'a [u8]) -> Result<HashInput<'a>> {
    let hash = prehash(need(m, "digest")?)?;
    Ok(if get(m, "input-kind") == Some("digest") {
        HashInput::Digest { hash, bytes }
    } else {
        HashInput::Message {
            hash,
            message: bytes,
        }
    })
}

pub(crate) fn validate_options(m: &ArgMatches) -> Result<()> {
    if get(m, "parameter-set").is_none() {
        return Err(usage("hash-ml-dsa/hash-slh-dsa require --parameter-set"));
    }
    if get(m, "mgf-digest").is_some() || get(m, "salt-length").is_some() {
        return Err(usage("HashML-DSA/HashSLH-DSA do not accept PSS parameters"));
    }
    if get(m, "hashing").is_some() {
        return Err(usage(
            "HashML-DSA/HashSLH-DSA use the explicit --digest prehash; --hashing is not accepted",
        ));
    }
    let _ = input(m, b"")?;
    Ok(())
}

pub(crate) fn request_ml<'a>(
    m: &ArgMatches,
    bytes: &'a [u8],
    context: &'a [u8],
) -> Result<HashMlDsaRequest<'a>> {
    let request = HashMlDsaRequest {
        parameter_set: ml_parameter(need(m, "parameter-set")?)?,
        input: input(m, bytes)?,
        context,
        hedging: hedging_ml(m),
    };
    request.validate().map_err(pkcs11_client::Error::from)?;
    Ok(request)
}

pub(crate) fn request_slh<'a>(
    m: &ArgMatches,
    bytes: &'a [u8],
    context: &'a [u8],
) -> Result<HashSlhDsaRequest<'a>> {
    let request = HashSlhDsaRequest {
        parameter_set: slh_parameter(need(m, "parameter-set")?)?,
        input: input(m, bytes)?,
        context,
        hedging: hedging_slh(m),
    };
    request.validate().map_err(pkcs11_client::Error::from)?;
    Ok(request)
}

fn ml_key_info(request: &HashMlDsaRequest<'_>) -> Value {
    json!({
        "type": "hash-ml-dsa",
        "parameter_set": format!("{:?}", request.parameter_set),
        "hash": request.input.hash().to_string(),
        "prehashed": request.input.is_prehashed(),
    })
}

fn slh_key_info(request: &HashSlhDsaRequest<'_>) -> Value {
    json!({
        "type": "hash-slh-dsa",
        "parameter_set": format!("{:?}", request.parameter_set),
        "hash": request.input.hash().to_string(),
        "prehashed": request.input.is_prehashed(),
    })
}

pub(crate) fn client_operation(
    client: &Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    if name == "verify" {
        return Err(usage(
            "HashML-DSA/HashSLH-DSA certificate verification is not exposed by this CLI",
        ));
    }
    let auth = || inputs.credential.auth(false);
    let key = client.private_key(uri(m, "key")?, auth())?;
    let value = if get(m, "algorithm") == Some("hash-ml-dsa") {
        let request = request_ml(m, &inputs.bytes, &inputs.domain_context)?;
        let policy = HashMlDsaSigningPolicy::default();
        match name {
            "capabilities" => {
                let caps = client.hash_ml_dsa_capabilities(
                    &key,
                    request.input.hash(),
                    request.input.is_prehashed(),
                    auth(),
                )?;
                json!({"key": ml_key_info(&request), "can_sign": caps.can_sign, "always_authenticate": caps.always_authenticate})
            }
            "plan" => {
                policy
                    .validate(&request)
                    .map_err(pkcs11_client::Error::from)?;
                json!({"key": ml_key_info(&request), "context_length": request.context.len(), "hedging": get(m,"hedging").unwrap_or("required")})
            }
            "sign" => {
                return Ok(Output::Binary(client.sign_hash_ml_dsa(
                    &key,
                    &request,
                    &policy,
                    auth(),
                    inputs.context.pin(),
                )?));
            }
            _ => return Err(usage("unsupported HashML-DSA command")),
        }
    } else {
        let request = request_slh(m, &inputs.bytes, &inputs.domain_context)?;
        let policy = HashSlhDsaSigningPolicy::default();
        match name {
            "capabilities" => {
                let caps = client.hash_slh_dsa_capabilities(
                    &key,
                    request.input.hash(),
                    request.input.is_prehashed(),
                    auth(),
                )?;
                json!({"key": slh_key_info(&request), "can_sign": caps.can_sign, "always_authenticate": caps.always_authenticate})
            }
            "plan" => {
                policy
                    .validate(&request)
                    .map_err(pkcs11_client::Error::from)?;
                json!({"key": slh_key_info(&request), "context_length": request.context.len(), "hedging": get(m,"hedging").unwrap_or("required")})
            }
            "sign" => {
                return Ok(Output::Binary(client.sign_hash_slh_dsa(
                    &key,
                    &request,
                    &policy,
                    auth(),
                    inputs.context.pin(),
                )?));
            }
            _ => return Err(usage("unsupported HashSLH-DSA command")),
        }
    };
    Ok(Output::Structured(value))
}
