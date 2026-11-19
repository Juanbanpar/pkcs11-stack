// SPDX-License-Identifier: MIT OR Apache-2.0
pub(crate) mod eddsa;
pub(crate) mod ml_dsa;
pub(crate) mod prehash;
pub(crate) mod slh_dsa;

use crate::{inputs::Inputs as CommandInputs, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    DigestAlgorithm, HashingPolicy, Provider, PssParameters, SignInput, SignRequest,
    SignatureAlgorithm, SigningPolicy,
};
use serde_json::{Value, json};
use std::num::NonZeroUsize;

use super::{Output, inspect};

pub(crate) enum VerificationCertificate {
    Classical(pkcs11_client::Certificate),
    MlDsa(pkcs11_client::MlDsaCertificate),
}

pub(crate) struct Inputs {
    pub context: Credential,
    pub domain_context: Vec<u8>,
    pub signature: Vec<u8>,
    pub verification_certificate: Option<VerificationCertificate>,
}

pub(crate) fn digest(value: &str) -> DigestAlgorithm {
    match value {
        "sha1" => DigestAlgorithm::Sha1,
        "sha224" => DigestAlgorithm::Sha224,
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        _ => DigestAlgorithm::Sha512,
    }
}
fn policy(m: &ArgMatches) -> SigningPolicy {
    let mut policy = SigningPolicy {
        hashing: match get(m, "hashing").unwrap_or("token") {
            "software" => HashingPolicy::SoftwareOnly,
            "allow-software" => HashingPolicy::AllowSoftware,
            _ => HashingPolicy::TokenOnly,
        },
        ..SigningPolicy::default()
    };
    if flag(m, "allow-sha1") {
        policy.digests.push(DigestAlgorithm::Sha1);
    }
    if flag(m, "allow-sha224") {
        policy.digests.push(DigestAlgorithm::Sha224);
    }
    policy
}
pub(crate) fn request<'a>(m: &ArgMatches, bytes: &'a [u8]) -> Result<SignRequest<'a>> {
    let algorithm = match need(m, "algorithm")? {
        "rsa-pkcs1" => SignatureAlgorithm::RsaPkcs1,
        "rsa-pss" => SignatureAlgorithm::RsaPss,
        "ecdsa" => SignatureAlgorithm::Ecdsa,
        _ => return Err(usage("expected a classical signature algorithm")),
    };
    let pss = if algorithm == SignatureAlgorithm::RsaPss {
        Some(PssParameters {
            mgf_digest: digest(need(m, "mgf-digest")?),
            salt_len: number(m, "salt-length")?,
        })
    } else {
        if get(m, "mgf-digest").is_some() || get(m, "salt-length").is_some() {
            return Err(usage("PSS parameters require rsa-pss"));
        }
        None
    };
    let digest = digest(need(m, "digest")?);
    let input = if get(m, "input-kind") == Some("digest") {
        if bytes.len() != digest.output_len() {
            return Err(usage("input length does not match the selected digest"));
        }
        SignInput::Digest(bytes)
    } else {
        SignInput::Message(bytes)
    };
    Ok(SignRequest {
        algorithm,
        digest,
        input,
        pss,
    })
}

pub(crate) fn verify(
    certificate: &VerificationCertificate,
    m: &ArgMatches,
    bytes: &[u8],
    inputs: &Inputs,
) -> Result<Value> {
    match certificate {
        VerificationCertificate::Classical(certificate) => {
            certificate.verify_signature(&request(m, bytes)?, &inputs.signature)?;
        }
        VerificationCertificate::MlDsa(certificate) => {
            certificate.verify_signature(
                &ml_dsa::request(m, bytes, &inputs.domain_context)?,
                &inputs.signature,
            )?;
        }
    }
    Ok(json!({"verified":true,"trust_validated":false}))
}

pub(super) fn run(
    module: &Provider,
    name: &str,
    m: &ArgMatches,
    prepared: &CommandInputs,
) -> Result<Output> {
    let selector = if name == "certificate" {
        "object"
    } else if name == "verify" {
        if get(m, "key").is_some() {
            "key"
        } else {
            "certificate"
        }
    } else {
        "key"
    };
    let location = token_uri(uri(m, selector)?)?;
    let client = module.client(&location, NonZeroUsize::new(1).unwrap(), policy(m))?;
    let outcome = client_operation(
        &client,
        name,
        m,
        &prepared.credential,
        &prepared.bytes,
        &prepared.signing,
    );
    finish(outcome, client.close(), "client session closure")
}
fn client_operation(
    client: &pkcs11_client::Client<'_>,
    name: &str,
    m: &ArgMatches,
    credential: &Credential,
    bytes: &[u8],
    inputs: &Inputs,
) -> Result<Output> {
    if eddsa::selected(m) {
        return eddsa::client_operation(client, name, m, credential, bytes, inputs);
    }
    if prehash::selected(m) {
        return prehash::client_operation(client, name, m, credential, bytes, inputs);
    }
    if slh_dsa::selected(m) {
        return slh_dsa::client_operation(client, name, m, credential, bytes, inputs);
    }
    if ml_dsa::selected(m) {
        return ml_dsa::client_operation(client, name, m, credential, bytes, inputs);
    }
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
