// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI X25519/X448 derivation workflows.

use crate::{operations::Inputs, operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AesKeySize, ClassicalPublicKey, ManagementSession, MontgomeryCurve, MontgomeryDerivation,
    MontgomeryKdf, MontgomeryOutput, MontgomeryPublicKey, object_reference,
};
use serde_json::json;

pub(crate) fn selected(name: &str) -> bool {
    name == "derive-montgomery"
}

pub(crate) fn mutation(name: &str) -> bool {
    selected(name)
}

fn curve(value: &str) -> Result<MontgomeryCurve> {
    match value {
        "x25519" => Ok(MontgomeryCurve::X25519),
        "x448" => Ok(MontgomeryCurve::X448),
        _ => Err(usage("expected x25519 or x448")),
    }
}

fn kdf(value: &str) -> Result<MontgomeryKdf> {
    Ok(match value {
        "null" => MontgomeryKdf::Null,
        "x963-sha256" => MontgomeryKdf::X963Sha256,
        "x963-sha384" => MontgomeryKdf::X963Sha384,
        "x963-sha512" => MontgomeryKdf::X963Sha512,
        "sp800-56a-sha256" => MontgomeryKdf::Sp80056aSha256,
        "sp800-56a-sha384" => MontgomeryKdf::Sp80056aSha384,
        "sp800-56a-sha512" => MontgomeryKdf::Sp80056aSha512,
        _ => return Err(usage("unsupported Montgomery KDF")),
    })
}

fn output(kind: &str, length: Option<usize>) -> Result<MontgomeryOutput> {
    Ok(match kind {
        "aes128" => MontgomeryOutput::Aes(AesKeySize::Bits128),
        "aes192" => MontgomeryOutput::Aes(AesKeySize::Bits192),
        "aes256" => MontgomeryOutput::Aes(AesKeySize::Bits256),
        "derivation-secret" => MontgomeryOutput::DerivationSecret {
            length: length.ok_or_else(|| usage("derivation-secret requires --length"))?,
        },
        _ => return Err(usage("unsupported Montgomery output kind")),
    })
}

pub(crate) fn validate(name: &str, m: &ArgMatches) -> Result<()> {
    if !selected(name) {
        return Ok(());
    }
    curve(need(m, "curve")?)?;
    kdf(need(m, "kdf")?)?;
    output(
        need(m, "kind")?,
        get(m, "length").map(|_| number(m, "length")).transpose()?,
    )?;
    Ok(())
}

pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    if !selected(name) {
        return Err(usage("unknown Montgomery command"));
    }
    let base = object_reference(uri(m, "object")?)?;
    let curve = curve(need(m, "curve")?)?;
    let peer = match MontgomeryPublicKey::from_bytes(curve, &inputs.peer) {
        Ok(peer) => peer,
        Err(_) => {
            let parsed = ClassicalPublicKey::from_spki_der(&inputs.peer)?;
            let peer = parsed.montgomery_public_key()?;
            if peer.curve() != curve {
                return Err(usage("peer public key curve does not match --curve"));
            }
            peer
        }
    };
    let id = unhex(need(m, "id")?)?;
    let request = MontgomeryDerivation {
        peer: &peer,
        kdf: kdf(need(m, "kdf")?)?,
        shared_info: &inputs.montgomery_info,
        output: output(
            need(m, "kind")?,
            get(m, "length").map(|_| number(m, "length")).transpose()?,
        )?,
        id: &id,
        label: need(m, "label")?.as_bytes(),
    };
    session.derive_montgomery(&base, &request)?;
    Ok(Output::Structured(json!({
        "derived": true,
        "curve": curve.to_string(),
    })))
}
