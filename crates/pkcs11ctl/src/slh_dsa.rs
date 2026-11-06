// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    DigestAlgorithm, HashSlhDsaInput, HashSlhDsaMode, HashSlhDsaRequest, HashSlhDsaSigningPolicy,
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
        "generate-hash-slh-dsa"
            | "hash-slh-dsa-capabilities"
            | "sign-hash-slh-dsa"
            | "verify-hash-slh-dsa"
            | "slh-dsa-generation-options"
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
fn hedging(m: &ArgMatches) -> SlhDsaHedging {
    match get(m, "hedging").unwrap_or("required") {
        "preferred" => SlhDsaHedging::Preferred,
        "deterministic" => SlhDsaHedging::Deterministic,
        _ => SlhDsaHedging::Required,
    }
}
fn request<'a>(m: &ArgMatches, message: &'a [u8], context: &'a [u8]) -> Result<SlhDsaRequest<'a>> {
    Ok(SlhDsaRequest {
        parameter_set: parameter(m)?,
        message,
        context,
        hedging: hedging(m),
    })
}
fn hash(m: &ArgMatches) -> Result<DigestAlgorithm> {
    Ok(crate::operations::digest(need(m, "digest")?))
}
fn hash_mode(m: &ArgMatches) -> Result<HashSlhDsaMode> {
    Ok(if get(m, "input-kind") == Some("digest") {
        HashSlhDsaMode::Prehashed(hash(m)?)
    } else {
        HashSlhDsaMode::Message(hash(m)?)
    })
}
pub(crate) fn input_limit(m: &ArgMatches) -> Result<usize> {
    Ok(if get(m, "input-kind") == Some("digest") {
        hash(m)?.output_len()
    } else {
        pkcs11_client::SLH_DSA_MAXIMUM_MESSAGE
    })
}
fn hash_request<'a>(
    m: &ArgMatches,
    bytes: &'a [u8],
    context: &'a [u8],
) -> Result<HashSlhDsaRequest<'a>> {
    Ok(HashSlhDsaRequest {
        parameter_set: parameter(m)?,
        context,
        hedging: hedging(m),
        input: if hash_mode(m)?.is_prehashed() {
            HashSlhDsaInput::Digest {
                hash: hash(m)?,
                bytes,
            }
        } else {
            HashSlhDsaInput::Message {
                hash: hash(m)?,
                message: bytes,
            }
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
    if matches!(command, "generate-slh-dsa" | "generate-hash-slh-dsa") {
        generation(m, &id(m)?)?
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        return Ok(());
    }
    let public = matches!(
        command,
        "verify-slh-dsa" | "verify-hash-slh-dsa" | "export-slh-dsa-public"
    );
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
    if matches!(
        command,
        "sign-slh-dsa" | "verify-slh-dsa" | "sign-hash-slh-dsa" | "verify-hash-slh-dsa"
    ) {
        if matches!(command, "sign-hash-slh-dsa" | "verify-hash-slh-dsa") {
            let request = hash_request(m, bytes, context)?;
            request.validate().map_err(pkcs11_client::Error::from)?;
            if command == "sign-hash-slh-dsa" {
                HashSlhDsaSigningPolicy {
                    allow_reduced_strength: flag(m, "allow-reduced-strength"),
                    ..Default::default()
                }
                .validate(&request)
                .map_err(pkcs11_client::Error::from)?;
            }
        } else {
            request(m, bytes, context)?
                .validate()
                .map_err(pkcs11_client::Error::from)?;
        }
        if matches!(command, "verify-slh-dsa" | "verify-hash-slh-dsa")
            && signature.len() != signature_limit(m)?
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
    if matches!(command, "generate-slh-dsa" | "generate-hash-slh-dsa") {
        let id = id(m)?;
        let request = generation(m, &id)?;
        if command == "generate-hash-slh-dsa" {
            session.generate_hash_slh_dsa_key_pair(&request)?;
        } else {
            session.generate_slh_dsa_key_pair(&request)?;
        }
        return Ok(Output::Structured(
            json!({"generated":true,"parameter_set":name(request.parameter_set),"id_hex":hex(&id)}),
        ));
    }
    if command == "export-slh-dsa-public" {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        return Ok(Output::Binary(session.export_slh_dsa_public_key(&key)?));
    }
    if matches!(command, "verify-slh-dsa" | "verify-hash-slh-dsa") {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        if command == "verify-hash-slh-dsa" {
            session.verify_hash_slh_dsa(
                &key,
                &hash_request(m, &inputs.bytes, &inputs.domain_context)?,
                &inputs.signature,
            )?;
        } else {
            session.verify_slh_dsa(
                &key,
                &request(m, &inputs.bytes, &inputs.domain_context)?,
                &inputs.signature,
            )?;
        }
        return Ok(Output::Structured(
            json!({"verified":true,"verification":"token"}),
        ));
    }
    let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
    if command == "hash-slh-dsa-capabilities" {
        let caps = session.hash_slh_dsa_capabilities(&key, hash_mode(m)?)?;
        return Ok(Output::Structured(
            json!({"advisory":true,"parameter_set":name(caps.parameter_set),"hash":need(m,"digest")?,"input_kind":get(m,"input-kind").unwrap_or("message"),"can_sign":caps.can_sign,"always_authenticate":caps.always_authenticate}),
        ));
    }
    if command == "sign-hash-slh-dsa" {
        return Ok(Output::Binary(session.sign_hash_slh_dsa(
            &key,
            &hash_request(m, &inputs.bytes, &inputs.domain_context)?,
            &HashSlhDsaSigningPolicy {
                allow_reduced_strength: flag(m, "allow-reduced-strength"),
                ..Default::default()
            },
            inputs.context.pin(),
        )?));
    }
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
