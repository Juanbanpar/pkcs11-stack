// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    HashMlDsaInput, HashMlDsaMode, HashMlDsaRequest, ManagementSession, MlDsaHedging,
    MlDsaSigningPolicy, PrivateKeyRef, PublicKeyRef,
};
use serde_json::json;

pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "hash-ml-dsa-capabilities" | "sign-hash-ml-dsa" | "verify-hash-ml-dsa"
    )
}
pub(crate) fn mode(m: &ArgMatches) -> HashMlDsaMode {
    if get(m, "input-kind") == Some("digest") {
        HashMlDsaMode::Prehashed
    } else {
        HashMlDsaMode::Message
    }
}
pub(crate) fn request<'a>(
    m: &ArgMatches,
    bytes: &'a [u8],
    context: &'a [u8],
) -> Result<HashMlDsaRequest<'a>> {
    let input = match mode(m) {
        HashMlDsaMode::Message => HashMlDsaInput::Message(bytes),
        HashMlDsaMode::Prehashed => {
            HashMlDsaInput::Sha512Digest(bytes.try_into().map_err(|_| {
                usage("HashML-DSA SHA-512 digest input must contain exactly 64 bytes")
            })?)
        }
    };
    let request = HashMlDsaRequest {
        parameter_set: crate::ml_dsa::parameter(get(m, "parameter-set"))
            .ok_or_else(|| usage("expected an ML-DSA parameter set"))?,
        input,
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
pub(crate) fn validate(
    name: &str,
    m: &ArgMatches,
    bytes: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    if !selected(name) {
        return Ok(());
    }
    let expected = if name == "verify-hash-ml-dsa" {
        b"public".as_slice()
    } else {
        b"private".as_slice()
    };
    if uri(m, "object")?.path_attribute("type") != Some(expected) {
        return Err(usage("object URI type does not match HashML-DSA operation"));
    }
    if name != "hash-ml-dsa-capabilities" {
        let request = request(m, bytes, context)?;
        if name == "verify-hash-ml-dsa"
            && signature.len() != request.parameter_set.signature_length()
        {
            return Err(usage(
                "signature length does not match ML-DSA parameter set",
            ));
        }
    }
    Ok(())
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    if name == "hash-ml-dsa-capabilities" {
        let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        let caps = session.hash_ml_dsa_capabilities(&key, mode(m))?;
        return Ok(Output::Structured(
            json!({"advisory":true,"key":crate::ml_dsa::key_info(caps.parameter_set),"hash":"sha512","input_kind":get(m,"input-kind").unwrap_or("message"),"can_sign":caps.can_sign,"always_authenticate":caps.always_authenticate}),
        ));
    }
    let request = request(m, &inputs.bytes, &inputs.domain_context)?;
    if name == "sign-hash-ml-dsa" {
        let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        Ok(Output::Binary(session.sign_hash_ml_dsa(
            &key,
            &request,
            &MlDsaSigningPolicy::default(),
            inputs.context.pin(),
        )?))
    } else {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        session.verify_hash_ml_dsa(&key, &request, &inputs.signature)?;
        Ok(Output::Structured(
            json!({"verified":true,"verification":"token","hash":"sha512","trust_validated":false}),
        ))
    }
}
