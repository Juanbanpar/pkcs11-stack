// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    operations::{Inputs, Output},
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    EdDsaCurve, EdDsaNamedRequest, EdDsaNamedScheme, ManagementSession, PrivateKeyRef, PublicKeyRef,
};
use serde_json::{Value, json};
pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "sign-eddsa-named" | "verify-eddsa-named")
}
pub(crate) fn curve(value: Option<&str>) -> Option<EdDsaCurve> {
    match value {
        Some("edwards25519") => Some(EdDsaCurve::Ed25519),
        Some("edwards448") => Some(EdDsaCurve::Ed448),
        _ => None,
    }
}
pub(crate) fn key_info(curve: EdDsaCurve) -> Value {
    json!({"type":"eddsa","profile":"rfc8032","curve":match curve {EdDsaCurve::Ed25519=>"edwards25519",EdDsaCurve::Ed448=>"edwards448"}})
}
pub(crate) fn input_limit(name: &str, m: &ArgMatches) -> Option<usize> {
    if selected(name) {
        Some(64 * 1024 * 1024)
    } else if name == "import" {
        curve(get(m, "kind")).map(|c| c.public_key_length())
    } else {
        None
    }
}
pub(crate) fn request<'a>(
    m: &ArgMatches,
    message: &'a [u8],
    context: &'a [u8],
) -> Result<EdDsaNamedRequest<'a>> {
    let scheme = match need(m, "scheme")? {
        "ed25519" => EdDsaNamedScheme::Ed25519,
        "ed25519ctx" => EdDsaNamedScheme::Ed25519ctx,
        "ed25519ph" => EdDsaNamedScheme::Ed25519ph,
        "ed448" => EdDsaNamedScheme::Ed448,
        "ed448ph" => EdDsaNamedScheme::Ed448ph,
        _ => return Err(usage("unsupported RFC 8032 scheme")),
    };
    let request = EdDsaNamedRequest {
        scheme,
        message,
        context,
    };
    request.validate().map_err(pkcs11_client::Error::from)?;
    Ok(request)
}
pub(crate) fn validate(
    name: &str,
    m: &ArgMatches,
    bytes: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<()> {
    if name == "export"
        && curve(get(m, "key-family")).is_some()
        && uri(m, "object")?.path_attribute("type") != Some(b"public")
    {
        return Err(usage("RFC 8032 raw export requires type=public"));
    }
    if name == "import" && curve(get(m, "kind")).is_some() {
        let id = unhex(need(m, "id")?)?;
        let label = need(m, "label")?.as_bytes();
        if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
            return Err(usage("key ID and label must each contain 1..=128 bytes"));
        }
        pkcs11_client::EdDsaNamedPublicKey::from_bytes(
            curve(get(m, "kind")).ok_or_else(|| usage("missing Edwards curve"))?,
            bytes,
        )?;
    }
    if !selected(name) {
        return Ok(());
    }
    let request = request(m, bytes, context)?;
    let class = if name == "sign-eddsa-named" {
        b"private".as_slice()
    } else {
        b"public".as_slice()
    };
    if uri(m, "object")?.path_attribute("type") != Some(class) {
        return Err(usage("object URI type does not match EdDSA operation"));
    }
    if name == "verify-eddsa-named" {
        if signature.len() != request.scheme.curve().signature_length() {
            return Err(usage("signature length does not match EdDSA scheme"));
        }
        if get(m, "context-pin-file").is_some() || flag(m, "context-protected-path") {
            return Err(usage("context authentication applies only to signing"));
        }
    }
    Ok(())
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let request = request(m, &inputs.bytes, &inputs.domain_context)?;
    if name == "sign-eddsa-named" {
        let key = PrivateKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        Ok(Output::Binary(session.sign_named_eddsa(
            &key,
            &request,
            inputs.context.pin(),
        )?))
    } else {
        let key = PublicKeyRef::new(uri(m, "object")?).map_err(pkcs11_client::Error::from)?;
        session.verify_named_eddsa(&key, &request, &inputs.signature)?;
        Ok(Output::Structured(
            json!({"verified":true,"trust_validated":false}),
        ))
    }
}
