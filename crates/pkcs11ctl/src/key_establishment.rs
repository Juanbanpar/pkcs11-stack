// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Output, digest},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    AesKeySize, EcdhKdf, EcdhOutput, EcdhPeer, EcdhRequest, HkdfOutput, HkdfRequest,
    ManagementSession, MlKemOperation, MlKemParameterSet, MlKemPublicKey, MlKemRequest,
    PrivateKeyRef, PublicKeyRef, SecretKeyIdentity, object_reference,
};
use serde_json::{Value, json};

pub(crate) fn parameter(value: Option<&str>) -> Option<MlKemParameterSet> {
    match value {
        Some("ml-kem-512") => Some(MlKemParameterSet::MlKem512),
        Some("ml-kem-768") => Some(MlKemParameterSet::MlKem768),
        Some("ml-kem-1024") => Some(MlKemParameterSet::MlKem1024),
        _ => None,
    }
}
fn selected_parameter(m: &ArgMatches) -> Result<MlKemParameterSet> {
    parameter(get(m, "parameter-set")).ok_or_else(|| usage("expected an ML-KEM parameter set"))
}
pub(crate) fn key_info(parameter: MlKemParameterSet) -> Value {
    let name = match parameter {
        MlKemParameterSet::MlKem512 => "ml-kem-512",
        MlKemParameterSet::MlKem768 => "ml-kem-768",
        MlKemParameterSet::MlKem1024 => "ml-kem-1024",
    };
    json!({"type":"ml-kem", "parameter_set":name})
}
pub(crate) fn selected(name: &str) -> bool {
    matches!(
        name,
        "kem-capabilities"
            | "encapsulate"
            | "decapsulate"
            | "hkdf-capabilities"
            | "derive-hkdf"
            | "derive-hybrid"
            | "derive-ecdh"
    )
}
pub(crate) fn mutation(name: &str) -> bool {
    matches!(
        name,
        "encapsulate" | "decapsulate" | "derive-hkdf" | "derive-hybrid" | "derive-ecdh"
    )
}
pub(crate) fn input_limit(name: &str, m: &ArgMatches) -> Result<Option<usize>> {
    Ok(if name == "decapsulate" {
        Some(selected_parameter(m)?.ciphertext_length())
    } else if name == "derive-ecdh" {
        Some(1024)
    } else if name == "import" && get(m, "kind") == Some("public-key") {
        Some(4096)
    } else if name == "import" && get(m, "kind") == Some("ml-kem") {
        Some(2048)
    } else {
        None
    })
}
fn direction(m: &ArgMatches) -> MlKemOperation {
    if get(m, "operation") == Some("decapsulate") {
        MlKemOperation::Decapsulate
    } else {
        MlKemOperation::Encapsulate
    }
}
fn kem_request<'a>(m: &'a ArgMatches, id: &'a [u8]) -> Result<MlKemRequest<'a>> {
    Ok(MlKemRequest {
        parameter_set: selected_parameter(m)?,
        id,
        label: need(m, "label")?.as_bytes(),
    })
}
fn hkdf_request<'a>(
    m: &'a ArgMatches,
    inputs: &'a Inputs,
    id: &'a [u8],
) -> Result<HkdfRequest<'a>> {
    let output = match need(m, "kind")? {
        "aes128" => HkdfOutput::Aes128,
        "aes192" => HkdfOutput::Aes192,
        "aes256" => HkdfOutput::Aes256,
        "derivation-secret" => HkdfOutput::DerivationSecret {
            length: number(m, "length")?,
        },
        _ => return Err(usage("unsupported HKDF output type")),
    };
    if !matches!(output, HkdfOutput::DerivationSecret { .. }) && get(m, "length").is_some() {
        return Err(usage("--length applies only to derivation-secret"));
    }
    Ok(HkdfRequest {
        digest: digest(need(m, "digest")?),
        salt: &inputs.salt,
        info: &inputs.info,
        output,
        id,
        label: need(m, "label")?.as_bytes(),
    })
}
fn ecdh_request<'a>(
    m: &'a ArgMatches,
    inputs: &'a Inputs,
    id: &'a [u8],
) -> Result<EcdhRequest<'a>> {
    let kdf = match need(m, "kdf")? {
        "null" => EcdhKdf::Null,
        "x963-sha256" => EcdhKdf::X963(pkcs11_client::DigestAlgorithm::Sha256),
        "x963-sha384" => EcdhKdf::X963(pkcs11_client::DigestAlgorithm::Sha384),
        "x963-sha512" => EcdhKdf::X963(pkcs11_client::DigestAlgorithm::Sha512),
        "sp800-sha256" => EcdhKdf::Sp80056a(pkcs11_client::DigestAlgorithm::Sha256),
        "sp800-sha384" => EcdhKdf::Sp80056a(pkcs11_client::DigestAlgorithm::Sha384),
        "sp800-sha512" => EcdhKdf::Sp80056a(pkcs11_client::DigestAlgorithm::Sha512),
        _ => return Err(usage("unsupported ECDH KDF")),
    };
    let output = match need(m, "kind")? {
        "raw-secret" => EcdhOutput::RawSecret,
        "derivation-secret" => EcdhOutput::DerivationSecret {
            length: number(m, "length")?,
        },
        "aes128" => EcdhOutput::Aes(AesKeySize::Bits128),
        "aes192" => EcdhOutput::Aes(AesKeySize::Bits192),
        "aes256" => EcdhOutput::Aes(AesKeySize::Bits256),
        _ => return Err(usage("unsupported ECDH output")),
    };
    if !matches!(output, EcdhOutput::DerivationSecret { .. }) && get(m, "length").is_some() {
        return Err(usage("--length applies only to derivation-secret"));
    }
    Ok(EcdhRequest {
        peer: inputs
            .ecdh_peer
            .as_ref()
            .ok_or_else(|| usage("missing ECDH peer"))?,
        kdf,
        shared_info: &inputs.info,
        output,
        identity: SecretKeyIdentity {
            id,
            label: need(m, "label")?.as_bytes(),
        },
    })
}
#[derive(Default)]
pub(crate) struct Inputs {
    pub public_key: Option<MlKemPublicKey>,
    ecdh_peer: Option<EcdhPeer>,
    salt: Vec<u8>,
    info: Vec<u8>,
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches, bytes: &[u8]) -> Result<Self> {
        let mut inputs = Self::default();
        if name == "import" && get(m, "kind") == Some("ml-kem") {
            inputs.public_key = Some(MlKemPublicKey::from_spki_der(bytes)?);
        }
        if name == "export"
            && get(m, "key-family") == Some("ml-kem")
            && uri(m, "object")?.path_attribute("type") != Some(b"public")
        {
            return Err(usage("ML-KEM SPKI export requires type=public"));
        }
        if !selected(name) {
            return Ok(inputs);
        }
        let kind = match name {
            "encapsulate" => "public",
            "decapsulate" | "derive-ecdh" => "private",
            "kem-capabilities" => {
                if direction(m) == MlKemOperation::Encapsulate {
                    "public"
                } else {
                    "private"
                }
            }
            _ => "secret-key",
        };
        if uri(m, "object")?.path_attribute("type") != Some(kind.as_bytes()) {
            return Err(usage(
                "object URI type does not match the selected key operation",
            ));
        }
        if matches!(name, "encapsulate" | "decapsulate") {
            let id = unhex(need(m, "id")?)?;
            let request = kem_request(m, &id)?;
            request.validate().map_err(pkcs11_client::Error::from)?;
            if name == "decapsulate" && bytes.len() != request.parameter_set.ciphertext_length() {
                return Err(usage(
                    "ciphertext length does not match the ML-KEM parameter set",
                ));
            }
        }
        if name == "derive-ecdh" {
            inputs.ecdh_peer = Some(EcdhPeer::from_spki_der(bytes)?);
            if let Some(path) = get(m, "shared-info-file") {
                if path == "-" {
                    return Err(usage("shared-info-file requires a file path"));
                }
                inputs.info = bounded_input(path, 4096)?;
            }
            let id = unhex(need(m, "id")?)?;
            ecdh_request(m, &inputs, &id)?.validate()?;
        }
        if matches!(name, "derive-hkdf" | "derive-hybrid") {
            for (name, target) in [
                ("salt-file", &mut inputs.salt),
                ("info-file", &mut inputs.info),
            ] {
                if let Some(path) = get(m, name) {
                    if path == "-" {
                        return Err(usage("HKDF salt/info require file paths"));
                    }
                    *target = bounded_input(path, 4096)?;
                }
            }
            let id = unhex(need(m, "id")?)?;
            let request = hkdf_request(m, &inputs, &id)?;
            if name == "derive-hybrid" {
                if uri(m, "post-quantum")?.path_attribute("type") != Some(b"secret-key") {
                    return Err(usage("post-quantum URI requires type=secret-key"));
                }
                request
                    .validate_hybrid()
                    .map_err(pkcs11_client::Error::from)?;
            } else {
                request.validate().map_err(pkcs11_client::Error::from)?;
            }
        }
        Ok(inputs)
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &crate::operations::Inputs,
) -> Result<Output> {
    let reference = object_reference(uri(m, "object")?)?;
    let value = match name {
        "derive-ecdh" => {
            let id = unhex(need(m, "id")?)?;
            let request = ecdh_request(m, &inputs.establishment, &id)?;
            session.derive_ecdh(&reference, &request)?;
            json!({"derived":true,"id_hex":hex(&id),"kdf":need(m,"kdf")?,"kind":need(m,"kind")?,"length":request.output.length(request.peer.curve()),"extractable":false})
        }
        "kem-capabilities" => {
            let caps = session.ml_kem_capabilities(&reference, direction(m))?;
            json!({"key":key_info(caps.parameter_set),"operation":need(m,"operation")?,"ciphertext_length":caps.parameter_set.ciphertext_length()})
        }
        "hkdf-capabilities" => {
            let caps = session.hkdf_capabilities(&reference, digest(need(m, "digest")?))?;
            json!({"digest":need(m,"digest")?,"input_length":caps.input_length})
        }
        "encapsulate" => {
            let id = unhex(need(m, "id")?)?;
            let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
            return Ok(Output::Binary(
                session.encapsulate_ml_kem(&key, &kem_request(m, &id)?)?,
            ));
        }
        "decapsulate" => {
            let id = unhex(need(m, "id")?)?;
            let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
            session.decapsulate_ml_kem(&key, &kem_request(m, &id)?, &inputs.bytes)?;
            json!({"decapsulated":true,"id_hex":hex(&id),"extractable":false})
        }
        "derive-hkdf" | "derive-hybrid" => {
            let id = unhex(need(m, "id")?)?;
            let request = hkdf_request(m, &inputs.establishment, &id)?;
            if name == "derive-hybrid" {
                session.derive_hybrid_hkdf(
                    &reference,
                    &object_reference(uri(m, "post-quantum")?)?,
                    &request,
                )?;
            } else {
                session.derive_hkdf(&reference, &request)?;
            }
            json!({"derived":true,"id_hex":hex(&id),"kind":need(m,"kind")?,"length":request.output.length(),"extractable":false})
        }
        _ => return Err(usage("unknown key establishment command")),
    };
    Ok(Output::Structured(value))
}
