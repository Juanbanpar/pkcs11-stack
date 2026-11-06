// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AES_CCM_MAXIMUM_AAD, AES_CCM_MAXIMUM_PLAINTEXT, AES_CCM_TAG_LENGTH, AesCcmDecryptRequest,
    AesCcmEncryptRequest, AesCcmOperation, ManagementSession, Plaintext, object_reference,
};
use secrecy::ExposeSecret;
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "aes-ccm-capabilities" | "encrypt-aes-ccm" | "decrypt-aes-ccm"
    )
}
pub(crate) struct Inputs {
    nonce: [u8; 12],
    aad: Vec<u8>,
    input: Plaintext,
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Option<Self>> {
        if !selected(name) {
            return Ok(None);
        }
        if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
            return Err(usage("AES CCM requires type=secret-key"));
        }
        if name == "aes-ccm-capabilities" {
            return Ok(None);
        }
        let value = need(m, "nonce")?;
        if value.len() != 24 {
            return Err(usage("nonce must contain exactly 24 hexadecimal digits"));
        }
        let nonce = unhex(value)
            .map_err(|_| usage("invalid CCM nonce"))?
            .try_into()
            .map_err(|_| usage("invalid CCM nonce"))?;
        let aad = match get(m, "aad-file") {
            Some("-") => return Err(usage("aad-file requires a file path")),
            Some(path) => bounded_input(path, AES_CCM_MAXIMUM_AAD)?,
            None => vec![],
        };
        let decrypt = name == "decrypt-aes-ccm";
        let input = secret_input(
            need(m, "input")?,
            AES_CCM_MAXIMUM_PLAINTEXT + if decrypt { AES_CCM_TAG_LENGTH } else { 0 },
        )?;
        if decrypt {
            AesCcmDecryptRequest {
                nonce: &nonce,
                aad: &aad,
                ciphertext: input.expose_secret(),
            }
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        } else {
            AesCcmEncryptRequest {
                nonce: &nonce,
                aad: &aad,
                plaintext: input.expose_secret(),
            }
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        }
        Ok(Some(Self { nonce, aad, input }))
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: Option<&Inputs>,
) -> Result<Output> {
    let key = object_reference(uri(m, "object")?)?;
    if name == "aes-ccm-capabilities" {
        let operation = if need(m, "operation")? == "encrypt" {
            AesCcmOperation::Encrypt
        } else {
            AesCcmOperation::Decrypt
        };
        let caps = session.aes_ccm_capabilities(&key, operation)?;
        return Ok(Output::Structured(
            json!({"advisory":true,"key_bits":caps.key_size.length()*8,"nonce_length":12,"tag_length":16,"maximum_plaintext":AES_CCM_MAXIMUM_PLAINTEXT,"maximum_aad":AES_CCM_MAXIMUM_AAD}),
        ));
    }
    let inputs = inputs.ok_or_else(|| usage("missing CCM input"))?;
    if name == "encrypt-aes-ccm" {
        Ok(Output::Binary(session.encrypt_aes_ccm(
            &key,
            &AesCcmEncryptRequest {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                plaintext: inputs.input.expose_secret(),
            },
        )?))
    } else {
        Ok(Output::SecretBinary(session.decrypt_aes_ccm(
            &key,
            &AesCcmDecryptRequest {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                ciphertext: inputs.input.expose_secret(),
            },
        )?))
    }
}
