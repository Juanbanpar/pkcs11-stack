// SPDX-License-Identifier: MIT OR Apache-2.0
use super::Output;
use crate::support::*;
use clap::ArgMatches;
use pkcs11_client::{
    AesDecryptRequest, AesDirection, AesEncryptRequest, AesMode, ManagementSession,
    object_reference,
};

use serde_json::json;

fn mode(value: &str) -> Result<AesMode> {
    Ok(match value {
        "ecb" => AesMode::Ecb,
        "cbc" => AesMode::Cbc,
        "cbc-pad" => AesMode::CbcPad,
        _ => return Err(usage("unsupported AES mode")),
    })
}

fn iv(m: &ArgMatches) -> Result<Option<[u8; 16]>> {
    let Some(value) = get(m, "iv") else {
        return Ok(None);
    };
    let bytes = unhex(value)?;
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| usage("AES IV must be exactly 16 bytes"))?;
    Ok(Some(array))
}

pub(crate) fn validate(name: &str, m: &ArgMatches) -> Result<()> {
    match name {
        "encrypt-aes" | "decrypt-aes" => {
            let mode = mode(need(m, "mode")?)?;
            let iv = iv(m)?;
            if mode.requires_iv() != iv.is_some() {
                return Err(usage("CBC modes require --iv and ECB forbids it"));
            }
        }
        "aes-cipher-capabilities" => {
            mode(need(m, "mode")?)?;
            if !matches!(need(m, "operation")?, "encrypt" | "decrypt") {
                return Err(usage("expected encrypt or decrypt"));
            }
        }

        _ => unreachable!(),
    }
    Ok(())
}

pub(super) fn run(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    bytes: &[u8],
) -> Result<Output> {
    match name {
        "encrypt-aes" => {
            let key = object_reference(uri(m, "object")?)?;
            let mode = mode(need(m, "mode")?)?;
            let iv = iv(m)?;
            if flag(m, "multipart") {
                if !matches!(mode, AesMode::CbcPad) && bytes.len() % 16 != 0 {
                    return Err(usage("AES input is not block aligned"));
                }
                Ok(Output::Binary(session.encrypt_aes_chunks(
                    &key,
                    mode,
                    iv.as_ref(),
                    chunks(bytes),
                )?))
            } else {
                let request = AesEncryptRequest {
                    mode,
                    iv: iv.as_ref(),
                    plaintext: bytes,
                };
                Ok(Output::Binary(session.encrypt_aes(&key, &request)?))
            }
        }
        "decrypt-aes" => {
            let key = object_reference(uri(m, "object")?)?;
            let mode = mode(need(m, "mode")?)?;
            let iv = iv(m)?;
            if flag(m, "multipart") {
                if !matches!(mode, AesMode::CbcPad) && bytes.len() % 16 != 0 {
                    return Err(usage("AES input is not block aligned"));
                }
                Ok(Output::SecretBinary(session.decrypt_aes_chunks(
                    &key,
                    mode,
                    iv.as_ref(),
                    chunks(bytes),
                )?))
            } else {
                let request = AesDecryptRequest {
                    mode,
                    iv: iv.as_ref(),
                    ciphertext: bytes,
                };
                Ok(Output::SecretBinary(session.decrypt_aes(&key, &request)?))
            }
        }
        "aes-cipher-capabilities" => aes_capabilities(session, m).map(Output::Structured),

        _ => unreachable!(),
    }
}

/// Inspect one key's AES permissions for a direction.
fn aes_capabilities(
    session: &mut ManagementSession<'_>,
    m: &ArgMatches,
) -> Result<serde_json::Value> {
    let key = object_reference(uri(m, "object")?)?;
    let mode = mode(need(m, "mode")?)?;
    let direction = match need(m, "operation")? {
        "encrypt" => AesDirection::Encrypt,
        "decrypt" => AesDirection::Decrypt,
        _ => return Err(usage("expected encrypt or decrypt")),
    };
    let capabilities = session.aes_capabilities(&key, mode, direction)?;
    Ok(json!({
        "key_size_bits": capabilities.key_size.length() * 8,
        "mode": mode.to_string(),
    }))
}
