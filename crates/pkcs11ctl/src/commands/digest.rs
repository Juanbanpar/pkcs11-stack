// SPDX-License-Identifier: MIT OR Apache-2.0
use super::Output;
use crate::support::*;
use clap::ArgMatches;
use pkcs11_client::{HashAlgorithm, ManagementSession};

fn hash(value: &str) -> Result<HashAlgorithm> {
    Ok(match value {
        "sha1" => HashAlgorithm::Sha1,
        "sha224" => HashAlgorithm::Sha224,
        "sha256" => HashAlgorithm::Sha256,
        "sha384" => HashAlgorithm::Sha384,
        "sha512" => HashAlgorithm::Sha512,
        _ => return Err(usage("unsupported digest algorithm")),
    })
}

pub(crate) fn validate(m: &ArgMatches) -> Result<()> {
    hash(need(m, "algorithm")?)?;
    Ok(())
}

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    m: &ArgMatches,
    bytes: &[u8],
) -> Result<Output> {
    let algorithm = hash(need(m, "algorithm")?)?;
    let output = if flag(m, "multipart") {
        session.digest_chunks(algorithm, chunks(bytes))?
    } else {
        session.digest(algorithm, bytes)?
    };
    Ok(Output::Binary(output))
}
