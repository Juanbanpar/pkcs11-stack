// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    aes_ccm, aes_cmac, aes_gcm, aes_key_wrap, chacha20_poly1305, eddsa, eddsa_named, generation,
    hash_ml_dsa, hmac, inspect, kbkdf, key_establishment, ml_dsa, pbkdf2, slh_dsa,
    stream_input::MultipartInput, support::*,
};
use clap::ArgMatches;
use pkcs11_client::{
    AttributeType, DigestAlgorithm, HashingPolicy, Provider, PssParameters, RandomRequest,
    SessionMode, SignInput, SignRequest, SignatureAlgorithm, SigningPolicy, object_reference,
    validate_token_uri,
};
use serde_json::{Value, json};
use std::num::NonZeroUsize;

pub(crate) enum Output {
    Structured(Value),
    Binary(Vec<u8>),
    SecretBinary(pkcs11_client::RandomBytes),
}
pub(crate) fn digest(value: &str) -> DigestAlgorithm {
    match value {
        "sha224" => DigestAlgorithm::Sha224,
        "sha3-224" => DigestAlgorithm::Sha3_224,
        "sha3-256" => DigestAlgorithm::Sha3_256,
        "sha3-384" => DigestAlgorithm::Sha3_384,
        "sha3-512" => DigestAlgorithm::Sha3_512,
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        _ => DigestAlgorithm::Sha512,
    }
}
fn policy(m: &ArgMatches) -> SigningPolicy {
    let mut policy = SigningPolicy {
        hashing: match get(m, "hashing").unwrap_or("token") {
            "software" => HashingPolicy::SoftwareOnly,
            "allow-software" => HashingPolicy::AllowSoftware,
            _ => HashingPolicy::TokenOnly,
        },
        ..SigningPolicy::default()
    };
    for key in ["digest", "mgf-digest"] {
        if let Some(value) = get(m, key) {
            let selected = digest(value);
            if !policy.digests.contains(&selected) {
                policy.digests.push(selected);
            }
        }
    }
    policy
}
fn request<'a>(m: &ArgMatches, bytes: &'a [u8]) -> Result<SignRequest<'a>> {
    let algorithm = match need(m, "algorithm")? {
        "rsa-pkcs1" => SignatureAlgorithm::RsaPkcs1,
        "rsa-pss" => SignatureAlgorithm::RsaPss,
        "ecdsa" => SignatureAlgorithm::Ecdsa,
        _ => return Err(usage("expected a classical signature algorithm")),
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
fn parameters(m: &ArgMatches) -> Result<pkcs11_client::SignatureParameters> {
    let request = request(m, &[])?;
    Ok(pkcs11_client::SignatureParameters {
        algorithm: request.algorithm,
        digest: request.digest,
        pss: request.pss,
    })
}
pub(crate) enum VerificationCertificate {
    Classical(pkcs11_client::Certificate),
    MlDsa(pkcs11_client::MlDsaCertificate),
    EdDsa(pkcs11_client::EdDsaCertificate),
}
// Validate non-provider inputs and load files before initializing a library or logging in.
pub(crate) struct Inputs {
    pub aes_gcm: Option<aes_gcm::Inputs>,
    pub aes_ccm: Option<aes_ccm::Inputs>,
    pub chacha20_poly1305: Option<chacha20_poly1305::Inputs>,
    pub hmac_tag: Option<Vec<u8>>,
    pub cmac_tag: Option<Vec<u8>>,
    pub stream_input: Option<MultipartInput>,
    pub digest_file: Option<std::fs::File>,
    pub credential: Credential,
    pub context: Credential,
    pub new_pin: Option<secrecy::SecretString>,
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
    pub certificate_document: Option<pkcs11_client::CertificateDocument>,
    pub public_key: Option<pkcs11_client::ClassicalPublicKey>,
    pub eddsa_key: Option<pkcs11_client::EdDsaVerifyingKey>,
    pub x25519_key: Option<pkcs11_client::X25519Peer>,
    pub x448_key: Option<pkcs11_client::X448Peer>,
    pub oaep_label: Vec<u8>,
    pub verification_certificate: Option<VerificationCertificate>,
    pub domain_context: Vec<u8>,
    pub signature: Vec<u8>,
    pub random: Option<RandomRequest>,
    pub so: bool,
    pub establishment: key_establishment::Inputs,
    pub kbkdf: kbkdf::Inputs,
    pub pbkdf2: pbkdf2::Inputs,
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        hash_ml_dsa::validate_options(name, m)?;
        let ml_dsa = ml_dsa::selected(m);
        let eddsa = eddsa::selected(m);
        if matches!(name, "sign" | "verify" | "verify-token") && flag(m, "multipart") {
            if eddsa || get(m, "input-kind") == Some("digest") {
                return Err(usage(
                    "multipart signature input requires an original RSA/ECDSA/ML-DSA message",
                ));
            }
            if !ml_dsa {
                request(m, &[])?;
            }
        }
        if eddsa {
            eddsa::validate_options(m)?;
        } else if ml_dsa {
            ml_dsa::validate_options(m)?;
        } else if !eddsa_named::selected(name)
            && !hash_ml_dsa::selected(name)
            && !slh_dsa::selected(name)
            && (get(m, "context-file").is_some() || get(m, "hedging").is_some())
        {
            return Err(usage(
                "context-file and hedging require an ML-DSA algorithm",
            ));
        }
        if name == "export"
            && (ml_dsa || eddsa)
            && uri(m, "object")?.path_attribute("type") != Some(b"public")
        {
            return Err(usage("ML-DSA/EdDSA SPKI export requires type=public"));
        }
        let credential = Credential::load(m, "pin-file", "protected-path")?;
        let context = Credential::load(m, "context-pin-file", "context-protected-path")?;
        let so = get(m, "role") == Some("so");
        if so
            && (slh_dsa::selected(name)
                || pbkdf2::selected(name)
                || kbkdf::selected(name)
                || hmac::selected(name)
                || aes_cmac::selected(name)
                || aes_gcm::selected(name)
                || aes_ccm::selected(name)
                || chacha20_poly1305::selected(name)
                || aes_key_wrap::selected(name)
                || key_establishment::selected(name)
                || eddsa_named::selected(name)
                || hash_ml_dsa::selected(name)
                || matches!(
                    name,
                    "certificate"
                        | "capabilities"
                        | "plan"
                        | "bind"
                        | "sign"
                        | "verify"
                        | "verify-token"
                        | "encrypt-rsa-oaep"
                        | "decrypt-rsa-oaep"
                        | "generate"
                ))
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
        if matches!(
            name,
            "verify"
                | "verify-token"
                | "verify-eddsa-named"
                | "verify-hash-ml-dsa"
                | "verify-slh-dsa"
                | "verify-hash-slh-dsa"
        ) && get(m, "input") == Some("-")
            && get(m, "signature") == Some("-")
        {
            return Err(usage("only one verification input may read stdin"));
        }
        let hmac_tag = hmac::load(name, m)?;
        let cmac_tag = aes_cmac::load(name, m)?;
        let stream_input = MultipartInput::load(name, m)?;
        let aes_gcm = aes_gcm::Inputs::load(name, m)?;
        let aes_ccm = aes_ccm::Inputs::load(name, m)?;
        let chacha20_poly1305 = chacha20_poly1305::Inputs::load(name, m)?;
        let oaep_label = match get(m, "label-hex") {
            Some(value) if value.len() > 8192 => {
                return Err(usage("OAEP label exceeds 4096 bytes"));
            }
            Some("") | None => vec![],
            Some(value) => {
                unhex(value).map_err(|_| usage("OAEP label must be even-length hexadecimal"))?
            }
        };
        let digest_file = if name == "digest" && get(m, "input") != Some("-") {
            Some(std::fs::File::open(need(m, "input")?)?)
        } else {
            None
        };
        let bytes = if chacha20_poly1305::selected(name)
            || aes_ccm::selected(name)
            || aes_gcm::selected(name)
            || name == "digest"
            || stream_input.is_some()
        {
            vec![]
        } else if let Some(path) = get(m, "input") {
            if slh_dsa::selected(name) {
                bounded_input(path, slh_dsa::input_limit(m)?)?
            } else if hash_ml_dsa::selected(name) {
                bounded_input(
                    path,
                    if hash_ml_dsa::mode(m).is_prehashed() {
                        hash_ml_dsa::mode(m).hash().output_len()
                    } else {
                        64 * 1024 * 1024
                    },
                )?
            } else if let Some(limit) = eddsa_named::input_limit(name, m) {
                bounded_input(path, limit)?
            } else if let Some(limit) = key_establishment::input_limit(name, m)? {
                bounded_input(path, limit)?
            } else if hmac::selected(name) {
                bounded_input(path, pkcs11_client::HMAC_MAXIMUM_MESSAGE)?
            } else if aes_cmac::selected(name) {
                bounded_input(path, pkcs11_client::AES_CMAC_MAXIMUM_MESSAGE)?
            } else if name == "unwrap-aes-key" {
                bounded_input(path, 40)?
            } else if matches!(name, "encrypt-rsa-oaep" | "decrypt-rsa-oaep") {
                bounded_input(path, 2048)?
            } else if name == "import" && get(m, "kind") == Some("eddsa") {
                bounded_input(path, 4096)?
            } else if matches!(name, "verify" | "verify-token") || ml_dsa || eddsa {
                bounded_input(path, 64 * 1024 * 1024)?
            } else {
                input(path)?
            }
        } else {
            vec![]
        };
        let domain_context = match get(m, "context-file") {
            Some("-") => return Err(usage("context-file requires a file path")),
            Some(path) => bounded_input(path, 255)?,
            None => vec![],
        };
        if matches!(name, "sign" | "plan" | "verify" | "verify-token") {
            if eddsa {
                eddsa::request(m, &bytes)?;
            } else if ml_dsa {
                ml_dsa::request(m, &bytes, &domain_context)?;
            } else {
                request(m, &bytes)?;
            }
        }
        let signature = if matches!(
            name,
            "verify"
                | "verify-token"
                | "verify-eddsa-named"
                | "verify-hash-ml-dsa"
                | "verify-slh-dsa"
                | "verify-hash-slh-dsa"
        ) {
            bounded_input(
                need(m, "signature")?,
                if matches!(name, "verify-slh-dsa" | "verify-hash-slh-dsa") {
                    slh_dsa::signature_limit(m)?
                } else {
                    16 * 1024
                },
            )?
        } else {
            vec![]
        };
        let verification_certificate = if let Some(path) = get(m, "certificate-file") {
            if path == "-" {
                return Err(usage("certificate-file requires a file path"));
            }
            let der = bounded_input(path, 1024 * 1024)?;
            let certificate = if eddsa {
                let certificate = pkcs11_client::EdDsaCertificate::from_der(der)?;
                certificate.validate_signing_request(&eddsa::request(m, &bytes)?)?;
                VerificationCertificate::EdDsa(certificate)
            } else if ml_dsa {
                let certificate = pkcs11_client::MlDsaCertificate::from_der(der)?;
                certificate.validate_signing_request(&ml_dsa::request(
                    m,
                    &bytes,
                    &domain_context,
                )?)?;
                VerificationCertificate::MlDsa(certificate)
            } else {
                let certificate = pkcs11_client::Certificate::from_der(der)?;
                certificate.validate_signing_request(&request(m, &bytes)?)?;
                VerificationCertificate::Classical(certificate)
            };
            Some(certificate)
        } else {
            None
        };
        let random = if name == "random" {
            Some(RandomRequest::new(number(m, "length")?)?)
        } else {
            None
        };
        let certificate_document = if name == "import" && get(m, "kind") == Some("cert") {
            Some(pkcs11_client::CertificateDocument::from_der(bytes.clone())?)
        } else {
            None
        };
        let public_key = if name == "import" && get(m, "kind") == Some("public-key") {
            let key = pkcs11_client::ClassicalPublicKey::from_spki_der(&bytes)
                .map_err(|_| usage("invalid RSA/EC SPKI DER public key"))?;
            pkcs11_client::PublicKeyImportRequest {
                key: &key,
                purpose: public_key_purpose(m)?,
                id: &unhex(need(m, "id")?)?,
                label: need(m, "label")?.as_bytes(),
            }
            .validate()?;
            Some(key)
        } else {
            if name == "import" && get(m, "kind") != Some("eddsa") && get(m, "purpose").is_some() {
                return Err(usage("--purpose applies only to public-key import"));
            }
            None
        };
        let eddsa_key = if name == "import" && get(m, "kind") == Some("eddsa") {
            if get(m, "purpose") != Some("verification") {
                return Err(usage("EdDSA import requires --purpose verification"));
            }
            let id = unhex(need(m, "id")?)?;
            let label = need(m, "label")?;
            if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
                return Err(usage("EdDSA ID and label must each contain 1..=128 bytes"));
            }
            Some(pkcs11_client::EdDsaVerifyingKey::from_spki_der(&bytes)?)
        } else {
            None
        };
        let x25519_key = if name == "import" && get(m, "kind") == Some("x25519") {
            let id = unhex(need(m, "id")?)?;
            let label = need(m, "label")?.as_bytes();
            if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
                return Err(usage("X25519 ID and label must each contain 1..=128 bytes"));
            }
            Some(pkcs11_client::X25519Peer::from_spki_der(&bytes)?)
        } else {
            None
        };
        let x448_key = if name == "import" && get(m, "kind") == Some("x448") {
            let id = unhex(need(m, "id")?)?;
            let label = need(m, "label")?.as_bytes();
            if id.is_empty() || id.len() > 128 || label.is_empty() || label.len() > 128 {
                return Err(usage("X448 ID and label must each contain 1..=128 bytes"));
            }
            Some(pkcs11_client::X448Peer::from_spki_der(&bytes)?)
        } else {
            None
        };
        if let Some(id) = get(m, "id") {
            unhex(id)?;
        }
        if name == "generate" {
            generation::validate(m)?;
        }
        if name == "diagnose" && !(1..=64).contains(&number(m, "pool-size")?) {
            return Err(usage("pool size must be 1..=64"));
        }
        if name == "inspect" {
            for n in need(m, "attributes")?.split(',') {
                inspect::attribute_type(n)?;
            }
        }
        for selector in ["token", "object", "key", "certificate", "post-quantum"] {
            if get(m, selector).is_some() {
                let parsed = uri(m, selector)?;
                if selector == "key" {
                    let required: &[u8] = if name == "verify-token" {
                        b"public"
                    } else {
                        b"private"
                    };
                    if parsed.path_attribute("type") != Some(required) {
                        return Err(usage(if name == "verify-token" {
                            "key URI requires type=public"
                        } else {
                            "key URI requires type=private"
                        }));
                    }
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
        if matches!(name, "encrypt-rsa-oaep" | "decrypt-rsa-oaep") {
            let expected: &[u8] = if name == "encrypt-rsa-oaep" {
                b"public"
            } else {
                b"private"
            };
            if uri(m, "object")?.path_attribute("type") != Some(expected) {
                return Err(usage("RSA cipher object URI has the wrong class"));
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
        eddsa_named::validate(name, m, &bytes, &domain_context, &signature)?;
        hash_ml_dsa::validate(name, m, &bytes, &domain_context, &signature)?;
        slh_dsa::validate(name, m, &bytes, &domain_context, &signature)?;
        let establishment = key_establishment::Inputs::load(name, m, &bytes)?;
        let kbkdf = kbkdf::Inputs::load(name, m)?;
        let pbkdf2 = pbkdf2::Inputs::load(name, m)?;
        if aes_key_wrap::selected(name) {
            aes_key_wrap::validate(name, m, &bytes)?;
        }
        Ok(Self {
            aes_gcm,
            aes_ccm,
            chacha20_poly1305,
            cmac_tag,
            stream_input,
            hmac_tag,
            digest_file,
            establishment,
            kbkdf,
            pbkdf2,
            credential,
            context,
            new_pin,
            bytes: zeroize::Zeroizing::new(bytes),
            certificate_document,
            public_key,
            eddsa_key,
            x25519_key,
            x448_key,
            oaep_label,
            verification_certificate,
            domain_context,
            signature,
            random,
            so,
        })
    }
}
pub(crate) fn verify(
    certificate: &VerificationCertificate,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Value> {
    match certificate {
        VerificationCertificate::Classical(certificate) => {
            if let Some(input) = &inputs.stream_input {
                let parameters = parameters(m)?;
                input.read(|mut reader| {
                    certificate.verify_reader(parameters, &mut reader, &inputs.signature)
                })?;
            } else {
                certificate.verify_signature(&request(m, &inputs.bytes)?, &inputs.signature)?;
            }
        }
        VerificationCertificate::EdDsa(certificate) => {
            certificate.verify_signature(&eddsa::request(m, &inputs.bytes)?, &inputs.signature)?;
        }
        VerificationCertificate::MlDsa(certificate) => {
            if let Some(input) = &inputs.stream_input {
                let parameters = ml_dsa::parameters(m, &inputs.domain_context)?;
                input.read(|mut reader| {
                    certificate.verify_reader(parameters, &mut reader, &inputs.signature)
                })?;
            } else {
                certificate.verify_signature(
                    &ml_dsa::request(m, &inputs.bytes, &inputs.domain_context)?,
                    &inputs.signature,
                )?;
            }
        }
    }
    Ok(json!({"verified":true,"trust_validated":false}))
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
fn public_key_purpose(m: &ArgMatches) -> Result<pkcs11_client::ClassicalPublicKeyPurpose> {
    match get(m, "purpose") {
        Some("verification") => Ok(pkcs11_client::ClassicalPublicKeyPurpose::Verification),
        Some("encryption") => Ok(pkcs11_client::ClassicalPublicKeyPurpose::Encryption),
        _ => Err(usage(
            "public-key import requires --purpose verification|encryption",
        )),
    }
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
            let interface = module.interface();
            json!({"manufacturer":info.manufacturer_id(),"description":info.library_description(),"version":format!("{}.{}",info.library_version().major(),info.library_version().minor()),"cryptoki_version":format!("{}.{}",info.cryptoki_version().major(),info.cryptoki_version().minor()),"interface":{"version":interface.version.to_string(),"reported_version":interface.reported_version.to_string(),"flags":interface.flags,"legacy":interface.legacy}})
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
        "certificate" | "capabilities" | "plan" | "bind" | "sign" | "verify" | "verify-token" => {
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
    } else if name == "verify" {
        "certificate"
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
    if eddsa::selected(m) {
        return eddsa::client_operation(client, name, m, inputs);
    }
    if ml_dsa::selected(m) {
        return ml_dsa::client_operation(client, name, m, inputs);
    }
    let auth = || inputs.credential.auth(false);
    if name == "verify-token" {
        let key =
            pkcs11_client::PublicKeyRef::new(uri(m, "key")?).map_err(pkcs11_client::Error::from)?;
        if let Some(input) = &inputs.stream_input {
            let parameters = parameters(m)?;
            input.read(|mut reader| {
                client.verify_token_reader(&key, parameters, auth(), &mut reader, &inputs.signature)
            })?;
        } else {
            client.verify_token(
                &key,
                &pkcs11_client::VerifyRequest {
                    parameters: request(m, &inputs.bytes)?,
                    signature: &inputs.signature,
                },
                auth(),
            )?;
        }
        return Ok(Output::Structured(
            json!({"verified":true,"verification":"token"}),
        ));
    }
    if name == "verify" {
        return verify(
            &VerificationCertificate::Classical(
                client.certificate(uri(m, "certificate")?, auth())?,
            ),
            m,
            inputs,
        )
        .map(Output::Structured);
    }
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
            if let Some(input) = &inputs.stream_input {
                let parameters = parameters(m)?;
                let signature = if get(m, "certificate").is_some() {
                    let certificate = client.certificate(uri(m, "certificate")?, auth())?;
                    certificate
                        .validate_signing_request(&parameters.request(SignInput::Message(&[])))?;
                    client.streaming_plan(&key, parameters, auth())?;
                    let identity =
                        client.bind_identity(key, certificate, auth(), inputs.context.pin())?;
                    input.read(|mut reader| {
                        client.sign_identity_reader(
                            &identity,
                            parameters,
                            auth(),
                            inputs.context.pin(),
                            &mut reader,
                        )
                    })?
                } else {
                    input.read(|mut reader| {
                        client.sign_reader(
                            &key,
                            parameters,
                            auth(),
                            inputs.context.pin(),
                            &mut reader,
                        )
                    })?
                };
                return Ok(Output::Binary(signature));
            }
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
    if name == "slh-dsa-generation-options" {
        return Ok(Output::Structured(
            json!({"advisory":true,"parameter_sets":module.slh_dsa_generation_options(&location)?.into_iter().map(slh_dsa::name).collect::<Vec<_>>()}),
        ));
    }
    if name == "generation-options" {
        return generation::options(module, m).map(Output::Structured);
    }
    if name == "mechanisms" {
        let mut items = vec![];
        for entry in module.mechanisms(&location)? {
            let mechanism = entry.mechanism;
            let info = entry.info;
            items.push(json!({"name":format!("{mechanism:?}"),"min_key_size":info.min_key_size(),"max_key_size":info.max_key_size(),"sign":info.sign(),"verify":info.verify(),"encrypt":info.encrypt(),"decrypt":info.decrypt(),"generate":info.generate(),"generate_key_pair":info.generate_key_pair(),"wrap":info.wrap(),"unwrap":info.unwrap(),"derive":info.derive(),"encapsulate":info.encapsulate(),"decapsulate":info.decapsulate(),"hardware":info.hardware()}));
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
    let mutation = matches!(name, "generate-slh-dsa" | "generate-hash-slh-dsa")
        || name == "generate-pbkdf2"
        || name == "derive-kbkdf"
        || key_establishment::mutation(name)
        || matches!(
            name,
            "init-pin"
                | "set-pin"
                | "generate"
                | "import"
                | "delete"
                | "set-label"
                | "unwrap-aes-key"
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
    if slh_dsa::selected(name) {
        return slh_dsa::operation(session, name, m, inputs);
    }
    if hash_ml_dsa::selected(name) {
        return hash_ml_dsa::operation(session, name, m, inputs);
    }
    if eddsa_named::selected(name) {
        return eddsa_named::operation(session, name, m, inputs);
    }
    if pbkdf2::selected(name) {
        return pbkdf2::operation(session, name, m, &inputs.pbkdf2);
    }
    if kbkdf::selected(name) {
        return kbkdf::operation(session, name, m, &inputs.kbkdf);
    }
    if hmac::selected(name) {
        return hmac::operation(
            session,
            name,
            m,
            &inputs.bytes,
            inputs.hmac_tag.as_deref(),
            inputs.stream_input.as_ref(),
        );
    }
    if aes_cmac::selected(name) {
        return aes_cmac::operation(
            session,
            name,
            m,
            &inputs.bytes,
            inputs.cmac_tag.as_deref(),
            inputs.stream_input.as_ref(),
        );
    }
    if chacha20_poly1305::selected(name) {
        return chacha20_poly1305::operation(session, name, m, inputs.chacha20_poly1305.as_ref());
    }
    if aes_ccm::selected(name) {
        return aes_ccm::operation(session, name, m, inputs.aes_ccm.as_ref());
    }
    if aes_gcm::selected(name) {
        return aes_gcm::operation(session, name, m, inputs.aes_gcm.as_ref());
    }
    if aes_key_wrap::selected(name) {
        return aes_key_wrap::operation(session, name, m, &inputs.bytes);
    }
    if key_establishment::selected(name) {
        return key_establishment::operation(session, name, m, inputs);
    }
    let value = match name {
        "session-validation" => {
            let flags = session.session_validation_flags()?;
            json!({"status":if flags.is_some() {"available"} else {"unavailable"}, "flags":flags.map(|v|format!("0x{v:x}")), "type":"CKS_LAST_VALIDATION_OK", "fresh_session":true, "provider_reported":true, "trust_validated":false})
        }
        "public-metadata" => {
            let token = session.token_uri()?;
            let mut objects = Vec::new();
            for reads in session.public_object_metadata()? {
                objects.push(inspect::public_metadata(&reads, &token)?);
            }
            json!(objects)
        }
        "digest-algorithms" => {
            json!({"advisory":true, "mode":"multipart", "algorithms": session.digest_algorithms(pkcs11_client::DigestMode::Multipart)?.into_iter().map(|a| a.to_string()).collect::<Vec<_>>()})
        }
        "digest" => {
            let name = need(m, "algorithm")?;
            let algorithm = pkcs11_client::HashAlgorithm::ALL
                .into_iter()
                .find(|a| a.to_string() == name)
                .ok_or_else(|| usage("unsupported digest algorithm"))?;
            let bytes = if let Some(file) = &inputs.digest_file {
                let mut reader = file;
                session.digest_reader(algorithm, &mut reader)?
            } else {
                session.digest_reader(algorithm, &mut std::io::stdin().lock())?
            };
            json!({"algorithm":algorithm.to_string(),"digest_hex":hex(&bytes)})
        }
        "encrypt-rsa-oaep" => {
            let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                .map_err(pkcs11_client::Error::from)?;
            return Ok(Output::Binary(session.encrypt_oaep(
                &key,
                &pkcs11_client::RsaOaepParameters {
                    digest: digest(need(m, "digest")?),
                    mgf_digest: digest(get(m, "mgf-digest").unwrap_or(need(m, "digest")?)),
                    label: &inputs.oaep_label,
                },
                &inputs.bytes,
            )?));
        }
        "decrypt-rsa-oaep" => {
            let key = pkcs11_client::PrivateKeyRef::new(uri(m, "object")?)
                .map_err(pkcs11_client::Error::from)?;
            return Ok(Output::SecretBinary(session.decrypt_oaep(
                &key,
                &pkcs11_client::RsaOaepParameters {
                    digest: digest(need(m, "digest")?),
                    mgf_digest: digest(get(m, "mgf-digest").unwrap_or(need(m, "digest")?)),
                    label: &inputs.oaep_label,
                },
                &inputs.bytes,
                inputs.context.pin(),
            )?));
        }
        "random" => {
            return Ok(Output::SecretBinary(
                session.generate_random(
                    inputs
                        .random
                        .ok_or_else(|| usage("missing random request"))?,
                )?,
            ));
        }
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
        "template-metadata" => {
            let reference = object_reference(uri(m, "object")?)?;
            let kind = match need(m, "template")? {
                "wrap" => pkcs11_client::TemplateAttribute::Wrap,
                "unwrap" => pkcs11_client::TemplateAttribute::Unwrap,
                "derive" => pkcs11_client::TemplateAttribute::Derive,
                _ => return Err(usage("unsupported template attribute")),
            };
            inspect::template_metadata(&session.template_metadata(&reference, kind)?)
        }
        "export" => {
            let reference = object_reference(uri(m, "object")?)?;
            let bytes = if eddsa_named::curve(get(m, "key-family")).is_some() {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                let bytes = session.export_named_eddsa_public_key(&key)?;
                if Some(bytes.len())
                    != eddsa_named::curve(get(m, "key-family"))
                        .map(|curve| curve.public_key_length())
                {
                    return Err(usage("Edwards curve does not match export profile"));
                }
                bytes
            } else if let Some(curve) = key_establishment::named_curve(get(m, "key-family")) {
                session.export_named_montgomery_public_key(&reference, curve)?
            } else if get(m, "key-family") == Some("x25519") {
                session.export_x25519_public_key(&reference)?
            } else if get(m, "key-family") == Some("x448") {
                session.export_x448_public_key(&reference)?
            } else if get(m, "key-family") == Some("ml-kem") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_ml_kem_public_key(&key)?
            } else if eddsa::selected(m) {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_eddsa_public_key(&key)?
            } else if ml_dsa::selected(m) {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_ml_dsa_public_key(&key)?
            } else if reference.uri().path_attribute("type") == Some(b"public") {
                let key = pkcs11_client::PublicKeyRef::new(uri(m, "object")?)
                    .map_err(pkcs11_client::Error::from)?;
                session.export_classical_public_key(&key)?
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
        "generate" => generation::generate(session, m)?,
        "import" => {
            let id = unhex(need(m, "id")?)?;
            if let Some(curve) = eddsa_named::curve(get(m, "kind")) {
                let key = pkcs11_client::EdDsaNamedPublicKey::from_bytes(curve, &inputs.bytes)?;
                session.import_named_eddsa_public_key(&key, &id, need(m, "label")?.as_bytes())?;
                return Ok(Output::Structured(
                    json!({"imported":true,"key":eddsa_named::key_info(curve),"id_hex":hex(&id)}),
                ));
            }
            if let Some(curve) = key_establishment::named_curve(get(m, "kind")) {
                let peer = inputs
                    .establishment
                    .named_peer
                    .as_ref()
                    .ok_or_else(|| usage("missing raw curveName public key"))?;
                session.import_named_montgomery_public_key(
                    peer,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
                return Ok(Output::Structured(
                    json!({"imported":true,"key":key_establishment::named_key_info(curve),"id_hex":hex(&id)}),
                ));
            }
            if need(m, "kind")? == "x25519" {
                session.import_x25519_public_key(
                    inputs
                        .x25519_key
                        .as_ref()
                        .ok_or_else(|| usage("missing X25519 public key"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
                return Ok(Output::Structured(
                    json!({"imported":true,"key":{"type":"x25519","bits":255},"id_hex":hex(&id)}),
                ));
            }
            if need(m, "kind")? == "x448" {
                session.import_x448_public_key(
                    inputs
                        .x448_key
                        .as_ref()
                        .ok_or_else(|| usage("missing X448 public key"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
                return Ok(Output::Structured(
                    json!({"imported":true,"key":{"type":"x448","bits":448},"id_hex":hex(&id)}),
                ));
            }
            if need(m, "kind")? == "eddsa" {
                let key = inputs
                    .eddsa_key
                    .as_ref()
                    .ok_or_else(|| usage("missing EdDSA public key"))?;
                session.import_eddsa_public_key(key, &id, need(m, "label")?.as_bytes())?;
                return Ok(Output::Structured(
                    json!({"imported":true,"purpose":"verification","key":eddsa::key_info(key.curve()),"id_hex":hex(&id)}),
                ));
            }
            if need(m, "kind")? == "public-key" {
                session.import_classical_public_key(&pkcs11_client::PublicKeyImportRequest {
                    key: inputs
                        .public_key
                        .as_ref()
                        .ok_or_else(|| usage("missing public key"))?,
                    purpose: public_key_purpose(m)?,
                    id: &id,
                    label: need(m, "label")?.as_bytes(),
                })?;
                return Ok(Output::Structured(
                    json!({"imported":true,"purpose":need(m,"purpose")?,"key":inspect::key_kind(inputs.public_key.as_ref().ok_or_else(|| usage("missing public key"))?.key_kind()),"id_hex":hex(&id)}),
                ));
            } else if need(m, "kind")? == "ml-kem" {
                session.import_ml_kem_public_key(
                    inputs
                        .establishment
                        .public_key
                        .as_ref()
                        .ok_or_else(|| usage("missing ML-KEM public key"))?,
                    &id,
                    need(m, "label")?.as_bytes(),
                )?;
            } else if need(m, "kind")? == "cert" {
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
