// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token digest, MAC, AES and SP 800-108 CLI workflows.

use crate::{operations::Inputs, operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AesDecryptRequest, AesDirection, AesEncryptRequest, AesMode, HashAlgorithm, KbkdfMode,
    KbkdfOutput, KbkdfPrf, KbkdfRequest, MacAlgorithm, ManagementSession, object_reference,
};
use serde_json::json;

pub(crate) const COMMANDS: &[&str] = &[
    "digest",
    "mac",
    "verify-mac",
    "encrypt-aes",
    "decrypt-aes",
    "derive-kbkdf",
    "aes-cipher-capabilities",
];

pub(crate) fn selected(name: &str) -> bool {
    COMMANDS.contains(&name)
}

/// Commands that change persistent token state.
pub(crate) fn mutation(name: &str) -> bool {
    name == "derive-kbkdf"
}

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

fn mac(value: &str) -> Result<MacAlgorithm> {
    Ok(match value {
        "hmac-sha1" => MacAlgorithm::HmacSha1,
        "hmac-sha224" => MacAlgorithm::HmacSha224,
        "hmac-sha256" => MacAlgorithm::HmacSha256,
        "hmac-sha384" => MacAlgorithm::HmacSha384,
        "hmac-sha512" => MacAlgorithm::HmacSha512,
        "aes-cmac" => MacAlgorithm::AesCmac,
        _ => return Err(usage("unsupported MAC algorithm")),
    })
}

fn mode(value: &str) -> Result<AesMode> {
    Ok(match value {
        "ecb" => AesMode::Ecb,
        "cbc" => AesMode::Cbc,
        "cbc-pad" => AesMode::CbcPad,
        _ => return Err(usage("unsupported AES mode")),
    })
}

fn prf(value: &str) -> Result<KbkdfPrf> {
    Ok(match value {
        "hmac-sha1" => KbkdfPrf::HmacSha1,
        "hmac-sha224" => KbkdfPrf::HmacSha224,
        "hmac-sha256" => KbkdfPrf::HmacSha256,
        "hmac-sha384" => KbkdfPrf::HmacSha384,
        "hmac-sha512" => KbkdfPrf::HmacSha512,
        "aes-cmac" => KbkdfPrf::AesCmac,
        _ => return Err(usage("unsupported SP 800-108 PRF")),
    })
}

fn kdf_mode(value: &str) -> Result<KbkdfMode> {
    Ok(match value {
        "counter" => KbkdfMode::Counter,
        "feedback" => KbkdfMode::Feedback,
        "double-pipeline" => KbkdfMode::DoublePipeline,
        _ => return Err(usage("unsupported SP 800-108 mode")),
    })
}

fn output(kind: &str, length: Option<usize>) -> Result<KbkdfOutput> {
    Ok(match kind {
        "aes128" => KbkdfOutput::Aes128,
        "aes192" => KbkdfOutput::Aes192,
        "aes256" => KbkdfOutput::Aes256,
        "derivation-secret" => KbkdfOutput::DerivationSecret {
            length: length.ok_or_else(|| usage("derivation-secret requires --length"))?,
        },
        _ => return Err(usage("unsupported KDF output kind")),
    })
}

fn chunks(bytes: &[u8]) -> std::slice::Chunks<'_, u8> {
    bytes.chunks(64 * 1024)
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
        "digest" => {
            hash(need(m, "algorithm")?)?;
        }
        "mac" | "verify-mac" => {
            mac(need(m, "algorithm")?)?;
        }
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
        "derive-kbkdf" => {
            prf(need(m, "prf")?)?;
            kdf_mode(need(m, "mode")?)?;
            output(
                need(m, "kind")?,
                get(m, "length").map(|_| number(m, "length")).transpose()?,
            )?;
            if get(m, "iv").is_some() {
                unhex(need(m, "iv")?)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    match name {
        "digest" => {
            let algorithm = hash(need(m, "algorithm")?)?;
            let output = if flag(m, "multipart") {
                session.digest_chunks(algorithm, chunks(&inputs.bytes))?
            } else {
                session.digest(algorithm, &inputs.bytes)?
            };
            Ok(Output::Binary(output))
        }
        "mac" => {
            let key = object_reference(uri(m, "object")?)?;
            let algorithm = mac(need(m, "algorithm")?)?;
            let output = if flag(m, "multipart") {
                session.mac_chunks(&key, algorithm, chunks(&inputs.bytes))?
            } else {
                session.mac(&key, algorithm, &inputs.bytes)?
            };
            Ok(Output::Binary(output))
        }
        "verify-mac" => {
            let key = object_reference(uri(m, "object")?)?;
            let algorithm = mac(need(m, "algorithm")?)?;
            if flag(m, "multipart") {
                session.verify_mac_chunks(&key, algorithm, chunks(&inputs.bytes), &inputs.tag)?;
            } else {
                session.verify_mac(&key, algorithm, &inputs.bytes, &inputs.tag)?;
            }
            Ok(Output::Structured(json!({"verified":true})))
        }
        "encrypt-aes" => {
            let key = object_reference(uri(m, "object")?)?;
            let mode = mode(need(m, "mode")?)?;
            let iv = iv(m)?;
            if flag(m, "multipart") {
                if !matches!(mode, AesMode::CbcPad) && inputs.bytes.len() % 16 != 0 {
                    return Err(usage("AES input is not block aligned"));
                }
                Ok(Output::Binary(session.encrypt_aes_chunks(
                    &key,
                    mode,
                    iv.as_ref(),
                    chunks(&inputs.bytes),
                )?))
            } else {
                let request = AesEncryptRequest {
                    mode,
                    iv: iv.as_ref(),
                    plaintext: &inputs.bytes,
                };
                Ok(Output::Binary(session.encrypt_aes(&key, &request)?))
            }
        }
        "decrypt-aes" => {
            let key = object_reference(uri(m, "object")?)?;
            let mode = mode(need(m, "mode")?)?;
            let iv = iv(m)?;
            if flag(m, "multipart") {
                if !matches!(mode, AesMode::CbcPad) && inputs.bytes.len() % 16 != 0 {
                    return Err(usage("AES input is not block aligned"));
                }
                Ok(Output::SecretBinary(session.decrypt_aes_chunks(
                    &key,
                    mode,
                    iv.as_ref(),
                    chunks(&inputs.bytes),
                )?))
            } else {
                let request = AesDecryptRequest {
                    mode,
                    iv: iv.as_ref(),
                    ciphertext: &inputs.bytes,
                };
                Ok(Output::SecretBinary(session.decrypt_aes(&key, &request)?))
            }
        }
        "aes-cipher-capabilities" => aes_capabilities(session, m).map(Output::Structured),
        "derive-kbkdf" => {
            let base = object_reference(uri(m, "object")?)?;
            let id = unhex(need(m, "id")?)?;
            let request = KbkdfRequest {
                prf: prf(need(m, "prf")?)?,
                kdf_label: &inputs.kdf_label,
                context: &inputs.kdf_context,
                output: output(
                    need(m, "kind")?,
                    get(m, "length").map(|_| number(m, "length")).transpose()?,
                )?,
                id: &id,
                label: need(m, "label")?.as_bytes(),
            };
            session.derive_kbkdf(&base, &request, kdf_mode(need(m, "mode")?)?, &inputs.kdf_iv)?;
            Ok(Output::Structured(json!({"derived":true})))
        }
        _ => Err(usage("unknown OASIS command")),
    }
}

/// Map a CLI key kind to an SLH-DSA parameter set.
pub(crate) fn slh_parameter(value: &str) -> Option<pkcs11_client::SlhDsaParameterSet> {
    crate::slh_dsa::parameter(Some(value))
}

/// Stable JSON description of an SLH-DSA parameter set.
pub(crate) fn slh_key_info(parameter: pkcs11_client::SlhDsaParameterSet) -> serde_json::Value {
    use pkcs11_client::SlhDsaParameterSet as P;
    let name = match parameter {
        P::Sha2_128S => "slh-dsa-sha2-128s",
        P::Sha2_128F => "slh-dsa-sha2-128f",
        P::Sha2_192S => "slh-dsa-sha2-192s",
        P::Sha2_192F => "slh-dsa-sha2-192f",
        P::Sha2_256S => "slh-dsa-sha2-256s",
        P::Sha2_256F => "slh-dsa-sha2-256f",
        P::Shake128S => "slh-dsa-shake-128s",
        P::Shake128F => "slh-dsa-shake-128f",
        P::Shake192S => "slh-dsa-shake-192s",
        P::Shake192F => "slh-dsa-shake-192f",
        P::Shake256S => "slh-dsa-shake-256s",
        P::Shake256F => "slh-dsa-shake-256f",
    };
    json!({"type":"slh-dsa","parameter_set":name})
}

/// Inspect one key's AES permissions for a direction.
pub(crate) fn aes_capabilities(
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
