// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AES_GCM_MAXIMUM_AAD, AES_GCM_MAXIMUM_PLAINTEXT, AES_GCM_TAG_LENGTH, AesGcmDecryptRequest,
    AesGcmEncryptRequest, AesGcmOperation, AesGcmStreamParameters, ManagementSession, Plaintext,
    object_reference,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use serde_json::json;
use std::{fs::File, io::Read};

pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "aes-gcm-capabilities" | "encrypt-aes-gcm" | "decrypt-aes-gcm"
    )
}
pub(crate) struct Inputs {
    nonce: [u8; 12],
    aad: Vec<u8>,
    input: Input,
}
enum Input {
    Buffered(Plaintext),
    Multipart(Option<File>),
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
        let value = need(m, "nonce")?;
        if value.len() != 24 {
            return Err(usage("nonce must contain exactly 24 hexadecimal digits"));
        }
        let nonce = unhex(value)
            .map_err(|_| usage("invalid AES GCM nonce"))?
            .try_into()
            .map_err(|_| usage("invalid AES GCM nonce"))?;
        let aad = match get(m, "aad-file") {
            Some("-") => return Err(usage("aad-file requires a file path")),
            Some(path) => bounded_input(path, AES_GCM_MAXIMUM_AAD)?,
            None => Vec::new(),
        };
        let decrypt = name == "decrypt-aes-gcm";
        let maximum = AES_GCM_MAXIMUM_PLAINTEXT + if decrypt { AES_GCM_TAG_LENGTH } else { 0 };
        let path = need(m, "input")?;
        let input = if flag(m, "multipart") {
            let file = if path == "-" {
                None
            } else {
                Some(File::open(path)?)
            };
            if let Some(file) = &file {
                let metadata = file.metadata()?;
                if metadata.is_file()
                    && (metadata.len() > maximum as u64
                        || (decrypt && metadata.len() < AES_GCM_TAG_LENGTH as u64))
                {
                    return Err(usage("AES GCM input length is outside the allowed range"));
                }
            }
            Input::Multipart(file)
        } else {
            let input = secret_input(path, maximum)?;
            if decrypt {
                AesGcmDecryptRequest {
                    nonce: &nonce,
                    aad: &aad,
                    ciphertext: input.expose_secret(),
                }
                .validate()
                .map_err(pkcs11_client::Error::from)?;
            } else {
                AesGcmEncryptRequest {
                    nonce: &nonce,
                    aad: &aad,
                    plaintext: input.expose_secret(),
                }
                .validate()
                .map_err(pkcs11_client::Error::from)?;
            }
            Input::Buffered(input)
        };
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
    if name == "aes-gcm-capabilities" {
        let operation = if need(m, "operation")? == "encrypt" {
            AesGcmOperation::Encrypt
        } else {
            AesGcmOperation::Decrypt
        };
        let multipart = flag(m, "multipart");
        let caps = if multipart {
            session.aes_gcm_streaming_capabilities(&key, operation)?
        } else {
            session.aes_gcm_capabilities(&key, operation)?
        };
        return Ok(Output::Structured(
            json!({"advisory":true,"multipart":multipart,"key_bits":caps.key_size.length()*8,"nonce_length":12,"tag_length":16,"maximum_plaintext":AES_GCM_MAXIMUM_PLAINTEXT,"maximum_aad":AES_GCM_MAXIMUM_AAD}),
        ));
    }
    let inputs = inputs.ok_or_else(|| usage("missing AES GCM input"))?;
    match &inputs.input {
        Input::Multipart(file) => {
            let mut reader: Box<dyn Read + '_> = match file {
                Some(file) => Box::new(file),
                None => Box::new(std::io::stdin().lock()),
            };
            let parameters = AesGcmStreamParameters {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                maximum_plaintext: AES_GCM_MAXIMUM_PLAINTEXT,
            };
            if name == "encrypt-aes-gcm" {
                Ok(Output::Binary(session.encrypt_aes_gcm_reader(
                    &key,
                    parameters,
                    &mut reader,
                )?))
            } else {
                Ok(Output::SecretBinary(session.decrypt_aes_gcm_reader(
                    &key,
                    parameters,
                    &mut reader,
                )?))
            }
        }
        Input::Buffered(input) if name == "encrypt-aes-gcm" => {
            Ok(Output::Binary(session.encrypt_aes_gcm(
                &key,
                &AesGcmEncryptRequest {
                    nonce: &inputs.nonce,
                    aad: &inputs.aad,
                    plaintext: input.expose_secret(),
                },
            )?))
        }
        Input::Buffered(input) => Ok(Output::SecretBinary(session.decrypt_aes_gcm(
            &key,
            &AesGcmDecryptRequest {
                nonce: &inputs.nonce,
                aad: &inputs.aad,
                ciphertext: input.expose_secret(),
            },
        )?)),
    }
}
