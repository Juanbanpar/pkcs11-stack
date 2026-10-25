// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{inspect, key_establishment, ml_dsa, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AesKeyPurpose, AesKeyRequest, AesKeySize, EcdhKeyPairRequest, KeyKind, ManagementSession,
    NamedCurve, Provider,
};
use serde_json::{Value, json};

fn curve(kind: &str) -> Option<NamedCurve> {
    match kind {
        "ecdh-p256" => Some(NamedCurve::P256),
        "ecdh-p384" => Some(NamedCurve::P384),
        "ecdh-p521" => Some(NamedCurve::P521),
        _ => None,
    }
}
fn aes(kind: &str) -> Option<AesKeySize> {
    match kind {
        "aes128" => Some(AesKeySize::Bits128),
        "aes192" => Some(AesKeySize::Bits192),
        "aes256" => Some(AesKeySize::Bits256),
        _ => None,
    }
}
fn purpose(m: &ArgMatches) -> Result<AesKeyPurpose> {
    match need(m, "purpose")? {
        "encryption" => Ok(AesKeyPurpose::Encryption),
        "wrapping" => Ok(AesKeyPurpose::Wrapping),
        _ => Err(usage("invalid AES purpose")),
    }
}
fn signing(m: &ArgMatches) -> Result<KeyKind> {
    Ok(match need(m, "kind")? {
        "rsa" => {
            let bits = if get(m, "bits").is_some() {
                number(m, "bits")?
            } else {
                2048
            };
            if !(2048..=16384).contains(&bits) || bits % 8 != 0 {
                return Err(usage("RSA size must be 2048..=16384 and divisible by 8"));
            }
            KeyKind::Rsa { bits }
        }
        "p256" => KeyKind::Ec(NamedCurve::P256),
        "p384" => KeyKind::Ec(NamedCurve::P384),
        "p521" => KeyKind::Ec(NamedCurve::P521),
        _ => return Err(usage("invalid signing key kind")),
    })
}
/// Validate before loading a provider or authenticating.
pub(crate) fn validate(m: &ArgMatches) -> Result<()> {
    let kind = need(m, "kind")?;
    if kind != "rsa" && get(m, "bits").is_some() {
        return Err(usage("--bits applies only to RSA"));
    }
    let id = unhex(need(m, "id")?)?;
    let label = need(m, "label")?.as_bytes();
    let non_signing = curve(kind).is_some()
        || aes(kind).is_some()
        || key_establishment::parameter(Some(kind)).is_some();
    if non_signing && flag(m, "always-authenticate") {
        return Err(usage("always-authenticate applies only to signing keys"));
    }
    if aes(kind).is_none() && get(m, "purpose").is_some() {
        return Err(usage("--purpose applies only to AES"));
    }
    if let Some(curve) = curve(kind) {
        EcdhKeyPairRequest {
            curve,
            id: &id,
            label,
        }
        .validate()
        .map_err(|_| usage("ECDH ID and label must each contain 1..=128 bytes"))?;
    } else if let Some(size) = aes(kind) {
        AesKeyRequest {
            size,
            purpose: purpose(m)?,
            id: &id,
            label,
        }
        .validate()
        .map_err(|_| usage("AES ID and label must each contain 1..=128 bytes"))?;
    } else if key_establishment::parameter(Some(kind)).is_none()
        && ml_dsa::parameter(Some(kind)).is_none()
    {
        signing(m)?;
    }
    Ok(())
}
pub(crate) fn generate(session: &mut ManagementSession<'_>, m: &ArgMatches) -> Result<Value> {
    let kind = need(m, "kind")?;
    let id = unhex(need(m, "id")?)?;
    let label = need(m, "label")?.as_bytes();
    let key = if let Some(curve) = curve(kind) {
        session.generate_ecdh_key_pair(&EcdhKeyPairRequest {
            curve,
            id: &id,
            label,
        })?;
        let mut metadata = inspect::key_kind(KeyKind::Ec(curve));
        metadata["purpose"] = json!("derivation");
        metadata
    } else if let Some(size) = aes(kind) {
        session.generate_aes_key(&AesKeyRequest {
            size,
            purpose: purpose(m)?,
            id: &id,
            label,
        })?;
        json!({"algorithm":"aes","bits":size.length()*8,"purpose":need(m,"purpose")?})
    } else if let Some(parameter) = key_establishment::parameter(Some(kind)) {
        session.generate_ml_kem_key_pair(parameter, &id, label)?;
        key_establishment::key_info(parameter)
    } else if let Some(parameter) = ml_dsa::parameter(Some(kind)) {
        session.generate_ml_dsa_key_pair(parameter, &id, label, flag(m, "always-authenticate"))?;
        ml_dsa::key_info(parameter)
    } else {
        let kind = signing(m)?;
        session.generate_signing_key_pair(kind, &id, label, flag(m, "always-authenticate"))?;
        inspect::key_kind(kind)
    };
    Ok(
        json!({"generated":true,"key":key,"id_hex":hex(&id),"label":need(m,"label")?,"extractable":false}),
    )
}
pub(crate) fn options(provider: &Provider, m: &ArgMatches) -> Result<Value> {
    let options = provider.generation_capabilities(&uri(m, "token")?)?;
    Ok(json!({
        "advisory":true,
        "signing":options.signing.into_iter().map(inspect::key_kind).collect::<Vec<_>>(),
        "ecdh":options.ecdh.into_iter().map(|curve| match curve {
            NamedCurve::P256=>"ecdh-p256", NamedCurve::P384=>"ecdh-p384", NamedCurve::P521=>"ecdh-p521"
        }).collect::<Vec<_>>(),
        "aes":options.aes.into_iter().map(|size| match size {
            AesKeySize::Bits128=>"aes128", AesKeySize::Bits192=>"aes192", AesKeySize::Bits256=>"aes256"
        }).collect::<Vec<_>>(),
        "aes_purposes":["encryption","wrapping"],
        "ml_dsa":options.ml_dsa.into_iter().map(ml_dsa::key_info).collect::<Vec<_>>(),
        "ml_kem":options.ml_kem.into_iter().map(key_establishment::key_info).collect::<Vec<_>>()
    }))
}
