// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{inspect, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    AttributeType, DigestAlgorithm, HashingPolicy, KeyKind, NamedCurve, Provider, PssParameters,
    SessionMode, SignInput, SignRequest, SignatureAlgorithm, SigningPolicy, object_reference,
    validate_token_uri,
};
use serde_json::{Value, json};
use std::num::NonZeroUsize;

pub(crate) enum Output {
    Structured(Value),
    Binary(Vec<u8>),
}
fn digest(value: &str) -> DigestAlgorithm {
    match value {
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        _ => DigestAlgorithm::Sha512,
    }
}
fn policy(m: &ArgMatches) -> SigningPolicy {
    SigningPolicy {
        hashing: match get(m, "hashing").unwrap_or("token") {
            "software" => HashingPolicy::SoftwareOnly,
            "allow-software" => HashingPolicy::AllowSoftware,
            _ => HashingPolicy::TokenOnly,
        },
        ..SigningPolicy::default()
    }
}
fn request<'a>(m: &ArgMatches, bytes: &'a [u8]) -> Result<SignRequest<'a>> {
    let algorithm = match need(m, "algorithm")? {
        "rsa-pkcs1" => SignatureAlgorithm::RsaPkcs1,
        "rsa-pss" => SignatureAlgorithm::RsaPss,
        _ => SignatureAlgorithm::Ecdsa,
    };
    let pss = if algorithm == SignatureAlgorithm::RsaPss {
        Some(PssParameters {
            mgf_digest: digest(need(m, "mgf-digest")?),
            salt_len: number(m, "salt-length")?,
        })
    } else {
        if get(m, "mgf-digest").is_some() || get(m, "salt-length").is_some() {
            return Err(usage("PSS parameters require rsa-pss"));
        }
        None
    };
    let digest = digest(need(m, "digest")?);
    let input = if get(m, "input-kind") == Some("digest") {
        if bytes.len() != digest.output_len() {
            return Err(usage("input length does not match the selected digest"));
        }
        SignInput::Digest(bytes)
    } else {
        SignInput::Message(bytes)
    };
    Ok(SignRequest {
        algorithm,
        digest,
        input,
        pss,
    })
}
// Validate non-provider inputs and load files before initializing a library or logging in.
pub(crate) struct Inputs {
    pub credential: Credential,
    pub context: Credential,
    pub new_pin: Option<secrecy::SecretString>,
    pub bytes: Vec<u8>,
    pub certificate_document: Option<pkcs11_client::CertificateDocument>,
    pub so: bool,
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        let credential = Credential::load(m, "pin-file", "protected-path")?;
        let context = Credential::load(m, "context-pin-file", "context-protected-path")?;
        let so = get(m, "role") == Some("so");
        if so
            && matches!(
                name,
                "certificate" | "capabilities" | "plan" | "bind" | "sign" | "generate"
            )
        {
            return Err(usage("this command uses the USER role"));
        }
        if so && credential.pin().is_none() {
            return Err(usage("SO role requires explicit authentication"));
        }
        if matches!(name, "init-pin" | "set-pin") {
            credential.host()?;
        }
        if name == "init-pin" && !so {
            return Err(usage("init-pin requires --role so"));
        }
        let new_pin = if get(m, "new-pin-file").is_some() {
            Some(Credential::host_file(m, "new-pin-file")?)
        } else if name == "init-token" {
            Some(Credential::host_file(m, "so-pin-file")?)
        } else {
            None
        };
        let bytes = if let Some(path) = get(m, "input") {
            input(path)?
        } else {
            vec![]
        };
        if matches!(name, "sign" | "plan") {
            request(m, &bytes)?;
        }
        let certificate_document = if name == "import" && get(m, "kind") == Some("cert") {
            Some(pkcs11_client::CertificateDocument::from_der(bytes.clone())?)
        } else {
            None
        };
        if let Some(id) = get(m, "id") {
            unhex(id)?;
        }
        if name == "generate" {
            generation_kind(m)?;
        }
        if name == "diagnose" && !(1..=64).contains(&number(m, "pool-size")?) {
            return Err(usage("pool size must be 1..=64"));
        }
        if name == "inspect" {
            for n in need(m, "attributes")?.split(',') {
                inspect::attribute_type(n)?;
            }
        }
        for selector in ["token", "object", "key", "certificate"] {
            if get(m, selector).is_some() {
                let parsed = uri(m, selector)?;
                if selector == "key" && parsed.path_attribute("type") != Some(b"private") {
                    return Err(usage("key URI requires type=private"));
                }
                if (selector == "certificate" || (name == "certificate" && selector == "object"))
                    && parsed.path_attribute("type") != Some(b"cert")
                {
                    return Err(usage("certificate URI requires type=cert"));
                }
                if selector == "token" {
                    validate_token_uri(&parsed)?;
                } else {
                    object_reference(parsed)?;
                }
            }
        }
        if name == "init-token" {
            need(m, "slot")?
                .parse::<u64>()
                .map_err(|_| usage("invalid slot ID"))?;
            expected_token(m)?;
            if need(m, "label")?.len() > 32 {
                return Err(usage("token label exceeds 32 UTF-8 bytes"));
            }
        }
        Ok(Self {
            credential,
            context,
            new_pin,
            bytes,
            certificate_document,
            so,
        })
    }
}
fn expected_token(m: &ArgMatches) -> Result<pkcs11_client::Pkcs11Uri> {
    let expected = uri(m, "expected-token")?;
    if expected.path_attributes().count() != 4
        || expected.query_names().next().is_some()
        || ["token", "manufacturer", "model", "serial"]
            .iter()
            .any(|name| expected.path_attribute(name).is_none())
    {
        return Err(usage(
            "--expected-token requires exactly token, manufacturer, model and serial; copy the URI from tokens",
        ));
    }
    Ok(expected)
}
fn generation_kind(m: &ArgMatches) -> Result<KeyKind> {
    let kind = need(m, "kind")?;
    if kind != "rsa" && get(m, "bits").is_some() {
        return Err(usage("--bits applies only to RSA"));
    }
    Ok(match kind {
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
        _ => KeyKind::Ec(NamedCurve::P521),
    })
}
pub(crate) fn run(
    module: &mut Provider,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let value = match name {
        "info" => {
            let info = module.info();
            json!({"manufacturer":info.manufacturer_id(),"description":info.library_description(),"version":format!("{}.{}",info.library_version().major(),info.library_version().minor()),"cryptoki_version":format!("{}.{}",info.cryptoki_version().major(),info.cryptoki_version().minor())})
        }
        "slots" => {
            let mut slots = vec![];
            for slot in module.slots(false)? {
                let info = slot.info;
                slots.push(json!({"slot_id":slot.id,"description":info.slot_description(),"manufacturer":info.manufacturer_id(),"token_present":info.token_present()}));
            }
            json!(slots)
        }
        "tokens" => {
            let mut tokens = vec![];
            for token in module.tokens()? {
                tokens.push(inspect::token_info(&token)?);
            }
            json!(tokens)
        }
        "init-token" => {
            let id = need(m, "slot")?
                .parse::<u64>()
                .map_err(|_| usage("invalid slot ID"))?;
            let expected = expected_token(m)?;
            let current = module
                .tokens()?
                .into_iter()
                .find(|token| token.slot_id == id)
                .ok_or_else(|| usage("selected slot has no token; enumerate tokens again"))?;
            if current.uri()?.to_string() != expected.to_string() {
                return Err(usage(
                    "token metadata does not match --expected-token; enumerate tokens again",
                ));
            }
            module.initialize_token_checked(
                &current.initialization_target(),
                inputs
                    .new_pin
                    .as_ref()
                    .ok_or_else(|| usage("missing SO PIN"))?,
                need(m, "label")?,
            )?;
            json!({"initialized":true})
        }
        "certificate" | "capabilities" | "plan" | "bind" | "sign" => {
            return client_command(module, name, m, inputs);
        }
        _ => return management_command(module, name, m, inputs),
    };
    Ok(Output::Structured(value))
}
fn client_command(
    module: &Provider,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let selector = if name == "certificate" {
        "object"
    } else {
        "key"
    };
    let location = token_uri(uri(m, selector)?)?;
    let client = module.client(&location, NonZeroUsize::new(1).unwrap(), policy(m))?;
    let outcome = client_operation(&client, name, m, inputs);
    finish(outcome, client.close(), "client session closure")
}
fn client_operation(
    client: &pkcs11_client::Client<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let auth = || inputs.credential.auth(false);
    if name == "certificate" {
        let cert = client.certificate(uri(m, "object")?, auth())?;
        return Ok(Output::Structured(
            json!({"key":inspect::key_kind(cert.key_kind()),"der_length":cert.der().len(),"spki_hex":hex(cert.spki_der()),"trust_validated":false}),
        ));
    }
    let key = client.private_key(uri(m, "key")?, auth())?;
    let result = match name {
        "capabilities" => {
            let caps = client.capabilities(&key, auth())?;
            let metadata = client.public_metadata(&key, auth())?;
            json!({"key":inspect::key_kind(caps.key),"can_sign":caps.can_sign,"always_authenticate":caps.always_authenticate,"allowed_mechanisms":caps.allowed_mechanisms.map(|v|v.iter().map(|m|format!("{m:?}")).collect::<Vec<_>>()),"mechanisms":caps.mechanisms.iter().map(|m|json!({"name":format!("{:?}",m.mechanism),"can_sign":m.can_sign,"minimum_bits":m.minimum_bits,"maximum_bits":m.maximum_bits})).collect::<Vec<_>>(),"public_metadata":{"modulus_hex":metadata.modulus.as_deref().map(hex),"exponent_hex":metadata.public_exponent.as_deref().map(hex),"ec_params_hex":metadata.ec_params.as_deref().map(hex),"ec_point_hex":metadata.ec_point.as_deref().map(hex),"spki_hex":metadata.spki.as_deref().map(hex)}})
        }
        "plan" => {
            let request = request(m, &inputs.bytes)?;
            let plan = client.plan(&key, &request, auth())?;
            json!({"mechanism":format!("{:?}",plan.mechanism()),"hash_location":format!("{:?}",plan.hash_location()),"context_authentication":plan.context_authentication()})
        }
        "bind" => {
            let certificate = client.certificate(uri(m, "certificate")?, auth())?;
            let identity = client.bind_identity(key, certificate, auth(), inputs.context.pin())?;
            json!({"bound":true,"key":inspect::key_kind(identity.certificate().key_kind()),"trust_validated":false})
        }
        "sign" => {
            let request = request(m, &inputs.bytes)?;
            let signature = if get(m, "certificate").is_some() {
                let certificate = client.certificate(uri(m, "certificate")?, auth())?;
                certificate.validate_signing_request(&request)?;
                client.plan(&key, &request, auth())?;
                let identity =
                    client.bind_identity(key, certificate, auth(), inputs.context.pin())?;
                client.sign_identity(&identity, &request, auth(), inputs.context.pin())?
            } else {
                client.sign(&key, &request, auth(), inputs.context.pin())?
            };
            return Ok(Output::Binary(signature));
        }
        _ => unreachable!(),
    };
    Ok(Output::Structured(result))
}
fn management_command(
    module: &Provider,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let location = if get(m, "token").is_some() {
        uri(m, "token")?
    } else {
        token_uri(uri(m, "object")?)?
    };
    if name == "mechanisms" {
        let mut items = vec![];
        for entry in module.mechanisms(&location)? {
            let mechanism = entry.mechanism;
            let info = entry.info;
            items.push(json!({"name":format!("{mechanism:?}"),"min_key_size":info.min_key_size(),"max_key_size":info.max_key_size(),"sign":info.sign(),"verify":info.verify(),"encrypt":info.encrypt(),"decrypt":info.decrypt(),"generate":info.generate(),"generate_key_pair":info.generate_key_pair(),"wrap":info.wrap(),"unwrap":info.unwrap(),"derive":info.derive(),"hardware":info.hardware()}));
        }
        return Ok(Output::Structured(json!(items)));
    }
    if name == "diagnose" {
        let size = number(m, "pool-size")?;
        let diagnostic = module.diagnose(
            &location,
            if inputs.so {
                SessionMode::ReadWrite
            } else {
                SessionMode::ReadOnly
            },
            NonZeroUsize::new(size).unwrap(),
            || inputs.credential.auth(inputs.so),
        )?;
        return Ok(Output::Structured(
            json!({"capacity":diagnostic.capacity,"exhaustion_verified":diagnostic.exhaustion_verified,"reuse_verified":diagnostic.reuse_verified,"session_state":format!("{:?}",diagnostic.session_state)}),
        ));
    }
    let mutation = matches!(
        name,
        "init-pin" | "set-pin" | "generate" | "import" | "delete" | "set-label"
    );
    let mut session = module.management(
        &location,
        if mutation || inputs.so {
            SessionMode::ReadWrite
        } else {
            SessionMode::ReadOnly
        },
        pkcs11_client::Authentication::None,
    )?;
    let outcome = (|| {
        session.authenticate(inputs.credential.auth(inputs.so))?;
        management_operation(&mut session, name, m, inputs)
    })();
    finish(outcome, session.close(), "session closure")
}
fn management_operation(
    session: &mut pkcs11_client::ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let value = match name {
        "objects" => {
            let token_uri = session.token_uri()?;
            let mut objects = vec![];
            for object in session.objects(&[
                AttributeType::Class,
                AttributeType::Label,
                AttributeType::Id,
            ])? {
                objects.push(inspect::object_summary(&object, &token_uri)?);
            }
            json!(objects)
        }
        "inspect" => {
            let reference = object_reference(uri(m, "object")?)?;
            let names = need(m, "attributes")?.split(',').collect::<Vec<_>>();
            let types = names
                .iter()
                .map(|name| inspect::attribute_type(name))
                .collect::<Result<Vec<_>>>()?;
            inspect::attributes(&session.inspect(&reference, &types)?, &names)?
        }
        "export" => {
            let reference = object_reference(uri(m, "object")?)?;
            let bytes = if reference.uri().path_attribute("type") == Some(b"public") {
                session.export_public(&reference)?
            } else {
                session.export_value(&reference)?
            };
            return Ok(Output::Binary(bytes));
        }
        "init-pin" => {
            session.initialize_pin(
                inputs
                    .new_pin
                    .as_ref()
                    .ok_or_else(|| usage("missing new PIN"))?,
            )?;
            json!({"pin_initialized":true})
        }
        "set-pin" => {
            session.change_pin(
                inputs.credential.host()?,
                inputs
                    .new_pin
                    .as_ref()
                    .ok_or_else(|| usage("missing new PIN"))?,
            )?;
            json!({"pin_changed":true})
        }
        "generate" => {
            let id = unhex(need(m, "id")?)?;
            let kind = generation_kind(m)?;
            session.generate_signing_key_pair(
                kind,
                &id,
                need(m, "label")?.as_bytes(),
                flag(m, "always-authenticate"),
            )?;
            json!({"generated":true,"key":inspect::key_kind(kind),"id_hex":hex(&id),"label":need(m,"label")?,"extractable":false})
        }
        "import" => {
            let id = unhex(need(m, "id")?)?;
            if need(m, "kind")? == "cert" {
                session.import_certificate(
                    inputs
                        .certificate_document
                        .as_ref()
                        .ok_or_else(|| usage("missing certificate document"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
            } else {
                session.import_data(&inputs.bytes, &id, need(m, "label")?.as_bytes())?;
            }
            json!({"imported":true})
        }
        "delete" | "set-label" => {
            let reference = object_reference(uri(m, "object")?)?;
            if name == "delete" {
                session.delete(&reference)?;
            } else {
                session.set_label(&reference, need(m, "label")?.as_bytes())?;
            }
            json!({"changed":true})
        }
        _ => return Err(usage("unknown command")),
    };
    Ok(Output::Structured(value))
}
