// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    CHACHA20_POLY1305_MAXIMUM_AAD, CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,
    CHACHA20_POLY1305_TAG_LENGTH, ChaCha20Poly1305DecryptRequest, ChaCha20Poly1305EncryptRequest,
    ChaCha20Poly1305Operation, ManagementSession, Plaintext, object_reference,
};
use secrecy::ExposeSecret;
use serde_json::json;
pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "chacha20-poly1305-capabilities"
            | "encrypt-chacha20-poly1305"
            | "decrypt-chacha20-poly1305"
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
            return Err(usage("ChaCha20-Poly1305 requires type=secret-key"));
        }
        if name == "chacha20-poly1305-capabilities" {
            return Ok(None);
        }
        let value = need(m, "nonce")?;
        if value.len() != 24 {
            return Err(usage("nonce must contain exactly 24 hexadecimal digits"));
        }
        let nonce = unhex(value)
            .map_err(|_| usage("invalid ChaCha20-Poly1305 nonce"))?
            .try_into()
            .map_err(|_| usage("invalid ChaCha20-Poly1305 nonce"))?;
        let aad = match get(m, "aad-file") {
            Some("-") => return Err(usage("aad-file requires a file path")),
            Some(path) => bounded_input(path, CHACHA20_POLY1305_MAXIMUM_AAD)?,
            None => vec![],
        };
        let decrypt = name == "decrypt-chacha20-poly1305";
        let input = secret_input(
            need(m, "input")?,
            CHACHA20_POLY1305_MAXIMUM_PLAINTEXT
                + if decrypt {
                    CHACHA20_POLY1305_TAG_LENGTH
                } else {
                    0
                },
        )?;
        if decrypt {
            ChaCha20Poly1305DecryptRequest {
                nonce: &nonce,
                aad: &aad,
                ciphertext: input.expose_secret(),
            }
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        } else {
            ChaCha20Poly1305EncryptRequest {
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
    if name == "chacha20-poly1305-capabilities" {
        let operation = if need(m, "operation")? == "encrypt" {
            ChaCha20Poly1305Operation::Encrypt
        } else {
            ChaCha20Poly1305Operation::Decrypt
        };
        let caps = session.chacha20_poly1305_capabilities(&key, operation)?;
        return Ok(Output::Structured(
            json!({"advisory":true,"key_bits":caps.key_length*8,"nonce_length":12,"tag_length":16,"maximum_plaintext":CHACHA20_POLY1305_MAXIMUM_PLAINTEXT,"maximum_aad":CHACHA20_POLY1305_MAXIMUM_AAD}),
        ));
    }
    let inputs = inputs.ok_or_else(|| usage("missing ChaCha20-Poly1305 input"))?;
    if name == "encrypt-chacha20-poly1305" {
        Ok(Output::Binary(session.encrypt_chacha20_poly1305(
            &key,
            &ChaCha20Poly1305EncryptRequest {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                plaintext: inputs.input.expose_secret(),
            },
        )?))
    } else {
        Ok(Output::SecretBinary(session.decrypt_chacha20_poly1305(
            &key,
            &ChaCha20Poly1305DecryptRequest {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                ciphertext: inputs.input.expose_secret(),
            },
        )?))
    }
}
