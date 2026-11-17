// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_ENVELOPE, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_TAG_LENGTH,
    AesGcmDecryptRequest, AesGcmEncryptRequest, AesGcmEnvelope, AesGcmOperation, ManagementSession,
    NonceSequence, Plaintext, object_reference,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use serde_json::json;
use std::{fs::File, io::Read, path::PathBuf};

pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "aes-gcm-capabilities" | "encrypt-aes-gcm" | "decrypt-aes-gcm"
    )
}
enum GcmMode {
    Raw([u8; 12]),
    Envelope,
    Managed { state: PathBuf, initialize: bool },
}
pub(crate) struct Inputs {
    mode: GcmMode,
    aad: Vec<u8>,
    input: Plaintext,
}
fn secret_input(path: &str, maximum: usize) -> Result<Plaintext> {
    let mut reader: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(path)?)
    };
    // Allocate once so plaintext is never left in an abandoned growth buffer.
    let mut input = SecretBox::new(Box::new(vec![0; maximum + 1]));
    let mut length = 0;
    loop {
        let read = reader.read(&mut input.expose_secret_mut()[length..])?;
        if read == 0 {
            break;
        }
        length += read;
        if length > maximum {
            return Err(usage("AES GCM input exceeds the size limit"));
        }
    }
    input.expose_secret_mut().truncate(length);
    Ok(input)
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Option<Self>> {
        if !selected(name) {
            return Ok(None);
        }
        if uri(m, "object")?.path_attribute("type") != Some(b"secret-key") {
            return Err(usage("AES GCM requires an object URI with type=secret-key"));
        }
        if name == "aes-gcm-capabilities" {
            return Ok(None);
        }
        let mode = if let Some(value) = get(m, "nonce") {
            if value.len() != 24 {
                return Err(usage("nonce must contain exactly 24 hexadecimal digits"));
            }
            GcmMode::Raw(
                unhex(value)
                    .map_err(|_| usage("invalid AES GCM nonce"))?
                    .try_into()
                    .map_err(|_| usage("invalid AES GCM nonce"))?,
            )
        } else if name == "encrypt-aes-gcm" {
            let state = need(m, "nonce-state")?;
            if state == "-" {
                return Err(usage("nonce-state requires a file path"));
            }
            GcmMode::Managed {
                state: state.into(),
                initialize: flag(m, "initialize-nonce-state"),
            }
        } else {
            if get(m, "nonce-state").is_some() || flag(m, "initialize-nonce-state") {
                return Err(usage("nonce state applies only to encryption"));
            }
            GcmMode::Envelope
        };
        let aad = match get(m, "aad-file") {
            Some("-") => return Err(usage("aad-file requires a file path")),
            Some(path) => bounded_input(path, AES_GCM_MAXIMUM_AAD)?,
            None => Vec::new(),
        };
        let maximum = if name == "decrypt-aes-gcm" {
            if matches!(mode, GcmMode::Raw(_)) {
                AES_GCM_MAXIMUM_PLAINTEXT + AES_GCM_TAG_LENGTH
            } else {
                AES_GCM_MAXIMUM_ENVELOPE
            }
        } else {
            AES_GCM_MAXIMUM_PLAINTEXT
        };
        let input = secret_input(need(m, "input")?, maximum)?;
        match &mode {
            GcmMode::Raw(nonce) if name == "decrypt-aes-gcm" => {
                AesGcmDecryptRequest {
                    nonce,
                    aad: &aad,
                    ciphertext: input.expose_secret(),
                }
                .validate()
                .map_err(pkcs11_client::Error::from)?;
            }
            GcmMode::Envelope => {
                AesGcmEnvelope::parse(input.expose_secret())?;
            }
            _ => {}
        }
        Ok(Some(Self { mode, aad, input }))
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: Option<&Inputs>,
) -> Result<Output> {
    let key = object_reference(uri(m, "object")?)?;
    if name == "aes-gcm-capabilities" {
        let operation = if need(m, "operation")? == "encrypt" {
            AesGcmOperation::Encrypt
        } else {
            AesGcmOperation::Decrypt
        };
        let caps = session.aes_gcm_capabilities(&key, operation)?;
        return Ok(Output::Structured(
            json!({"advisory":true,"key_bits":caps.key_size.length()*8,"nonce_length":12,"tag_length":16,"maximum_plaintext":AES_GCM_MAXIMUM_PLAINTEXT,"maximum_aad":AES_GCM_MAXIMUM_AAD}),
        ));
    }
    let inputs = inputs.ok_or_else(|| usage("missing AES GCM input"))?;
    match &inputs.mode {
        GcmMode::Managed { state, initialize } => {
            let mut sequence = if *initialize {
                NonceSequence::create(state, &key)?
            } else {
                NonceSequence::open(state, &key)?
            };
            Ok(Output::Binary(session.encrypt_aes_gcm_envelope(
                &key,
                &mut sequence,
                &inputs.aad,
                inputs.input.expose_secret(),
            )?))
        }
        GcmMode::Envelope => Ok(Output::SecretBinary(session.decrypt_aes_gcm_envelope(
            &key,
            &inputs.aad,
            inputs.input.expose_secret(),
        )?)),
        GcmMode::Raw(nonce) if name == "encrypt-aes-gcm" => {
            Ok(Output::Binary(session.encrypt_aes_gcm(
                &key,
                &AesGcmEncryptRequest {
                    nonce,
                    aad: &inputs.aad,
                    plaintext: inputs.input.expose_secret(),
                },
            )?))
        }
        GcmMode::Raw(nonce) => Ok(Output::SecretBinary(session.decrypt_aes_gcm(
            &key,
            &AesGcmDecryptRequest {
                nonce,
                aad: &inputs.aad,
                ciphertext: inputs.input.expose_secret(),
            },
        )?)),
    }
}
