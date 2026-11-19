// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::ArgMatches;
use pkcs11_client::{
    DigestAlgorithm, HashingPolicy, PssParameters, SignInput, SignRequest, SignatureAlgorithm,
    SigningPolicy,
};

use crate::support::*;

use super::VerificationCertificate;

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
pub(super) fn policy(m: &ArgMatches) -> SigningPolicy {
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
