// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::ArgMatches;
use serde_json::{Value, json};

use crate::support::Result;

use super::{Inputs, ml_dsa, request};

pub(crate) enum VerificationCertificate {
    Classical(pkcs11_client::Certificate),
    MlDsa(pkcs11_client::MlDsaCertificate),
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
