// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    commands::{
        aes, aes_gcm, digest, generation, hkdf, inspect, kbkdf, key_establishment, mac, montgomery,
        signing::{self, VerificationCertificate, eddsa, ml_dsa, prehash, slh_dsa},
        token::expected_token,
    },
    support::*,
};
use clap::ArgMatches;
use pkcs11_client::{RandomRequest, object_reference, validate_token_uri};

// Validate non-provider inputs and load files before initializing a library or logging in.
pub(crate) struct Inputs {
    pub aes_gcm: Option<aes_gcm::Inputs>,
    pub credential: Credential,
    pub signing: signing::Inputs,
    pub new_pin: Option<pkcs11_client::SecretText>,
    pub bytes: Vec<u8>,
    pub certificate_document: Option<pkcs11_client::CertificateDocument>,
    pub tag: Vec<u8>,
    pub kbkdf: kbkdf::Inputs,
    pub montgomery: montgomery::Inputs,
    pub random: Option<RandomRequest>,
    pub so: bool,
    pub hkdf: hkdf::Inputs,
    pub ml_kem_public_key: Option<pkcs11_client::MlKemPublicKey>,
}
impl Inputs {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        let ml_dsa = ml_dsa::selected(m);
        let slh_dsa = slh_dsa::selected(m);
        let prehash = prehash::selected(m);
        let eddsa = eddsa::selected(m);
        if ml_dsa {
            ml_dsa::validate_options(m)?;
        } else if slh_dsa {
            slh_dsa::validate_options(m)?;
        } else if prehash {
            prehash::validate_options(m)?;
        } else if eddsa {
            eddsa::validate_options(m)?;
        } else if get(m, "context-file").is_some() || get(m, "hedging").is_some() {
            return Err(usage(
                "context-file and hedging require an ML-DSA algorithm",
            ));
        }
        if name == "export" && ml_dsa && uri(m, "object")?.path_attribute("type") != Some(b"public")
        {
            return Err(usage("ML-DSA SPKI export requires type=public"));
        }
        let credential = Credential::load(m, "pin-file", "protected-path")?;
        let context = Credential::load(m, "context-pin-file", "context-protected-path")?;
        let so = get(m, "role") == Some("so");
        if so
            && (aes_gcm::selected(name)
                || key_establishment::selected(name)
                || hkdf::selected(name)
                || matches!(
                    name,
                    "certificate"
                        | "capabilities"
                        | "plan"
                        | "bind"
                        | "sign"
                        | "verify"
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
        if name == "verify" && get(m, "input") == Some("-") && get(m, "signature") == Some("-") {
            return Err(usage("only one verification input may read stdin"));
        }
        if name == "verify-mac" && get(m, "input") == Some("-") && get(m, "tag") == Some("-") {
            return Err(usage("only one MAC verification input may read stdin"));
        }
        if !flag(m, "allow-sha1")
            && (get(m, "digest") == Some("sha1") || get(m, "mgf-digest") == Some("sha1"))
        {
            return Err(usage("SHA-1 requires --allow-sha1"));
        }
        if !flag(m, "allow-sha224")
            && (get(m, "digest") == Some("sha224") || get(m, "mgf-digest") == Some("sha224"))
        {
            return Err(usage("SHA-224 requires --allow-sha224"));
        }
        montgomery::validate(name, m)?;
        match name {
            "digest" => digest::validate(m)?,
            "mac" | "verify-mac" => mac::validate(m)?,
            "encrypt-aes" | "decrypt-aes" | "aes-cipher-capabilities" => aes::validate(name, m)?,
            "derive-kbkdf" => kbkdf::validate(m)?,
            _ => {}
        }
        let aes_gcm = aes_gcm::Inputs::load(name, m)?;
        let bytes = if aes_gcm::selected(name) {
            vec![]
        } else if let Some(path) = get(m, "input") {
            if let Some(limit) = key_establishment::input_limit(name, m)? {
                bounded_input(path, limit)?
            } else if name == "verify" || ml_dsa || matches!(name, "digest" | "mac" | "verify-mac")
            {
                bounded_input(path, 64 * 1024 * 1024)?
            } else if matches!(name, "encrypt-aes" | "decrypt-aes") {
                bounded_input(path, 16 * 1024 * 1024)?
            } else if name == "import" && get(m, "kind") == Some("public-key") {
                bounded_input(path, 4096)?
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
        if matches!(name, "sign" | "plan" | "verify") {
            if ml_dsa {
                ml_dsa::request(m, &bytes, &domain_context)?;
            } else if slh_dsa {
                slh_dsa::request(m, &bytes, &domain_context)?;
            } else if prehash {
                if get(m, "algorithm") == Some("hash-ml-dsa") {
                    prehash::request_ml(m, &bytes, &domain_context)?;
                } else {
                    prehash::request_slh(m, &bytes, &domain_context)?;
                }
            } else if eddsa {
                eddsa::request(m, &bytes)?;
            } else {
                signing::request(m, &bytes)?;
            }
        }
        let signature = if name == "verify" {
            bounded_input(need(m, "signature")?, 64 * 1024)?
        } else {
            vec![]
        };
        let tag = if name == "verify-mac" {
            bounded_input(need(m, "tag")?, 16 * 1024)?
        } else {
            vec![]
        };
        let kdf_label = if name == "derive-kbkdf" {
            match get(m, "kdf-label-file") {
                Some("-") => return Err(usage("kdf-label-file requires a file path")),
                Some(path) => bounded_input(path, 4096)?,
                None => vec![],
            }
        } else {
            vec![]
        };
        let kdf_context = if name == "derive-kbkdf" {
            match get(m, "kdf-context-file") {
                Some("-") => return Err(usage("kdf-context-file requires a file path")),
                Some(path) => bounded_input(path, 4096)?,
                None => vec![],
            }
        } else {
            vec![]
        };
        let peer = if name == "derive-montgomery" {
            bounded_input(need(m, "peer")?, 4096)?
        } else {
            vec![]
        };
        let montgomery_info = if name == "derive-montgomery" {
            match get(m, "shared-info-file") {
                Some("-") => return Err(usage("shared-info-file requires a file path")),
                Some(path) => bounded_input(path, 4096)?,
                None => vec![],
            }
        } else {
            vec![]
        };
        let kdf_iv = if name == "derive-kbkdf" {
            match get(m, "iv") {
                Some(value) => unhex(value)?,
                None => vec![],
            }
        } else {
            vec![]
        };
        let verification_certificate = if let Some(path) = get(m, "certificate-file") {
            if path == "-" {
                return Err(usage("certificate-file requires a file path"));
            }
            let der = bounded_input(path, 1024 * 1024)?;
            if slh_dsa {
                return Err(usage(
                    "SLH-DSA certificate verification is not exposed by this CLI",
                ));
            }
            if prehash {
                return Err(usage(
                    "HashML-DSA/HashSLH-DSA certificate verification is not exposed by this CLI",
                ));
            }
            if eddsa {
                return Err(usage(
                    "EdDSA certificate-file verification is not exposed; use a token certificate URI",
                ));
            }
            let certificate = if ml_dsa {
                let certificate = pkcs11_client::MlDsaCertificate::from_der(der)?;
                certificate.validate_signing_request(&ml_dsa::request(
                    m,
                    &bytes,
                    &domain_context,
                )?)?;
                VerificationCertificate::MlDsa(certificate)
            } else {
                let certificate = pkcs11_client::Certificate::from_der(der)?;
                certificate.validate_signing_request(&signing::request(m, &bytes)?)?;
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
        if let Some(id) = get(m, "id") {
            unhex(id)?;
        }
        if name == "generate" {
            generation::validate(m)?;
        }
        if name == "import"
            && get(m, "kind") != Some("public-key")
            && get(m, "purpose") != Some("verification")
        {
            return Err(usage("--purpose applies only to public-key import"));
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
                if selector == "key"
                    && parsed.path_attribute("type") != Some(b"private")
                    && !(name == "verify" && parsed.path_attribute("type") == Some(b"public"))
                {
                    return Err(usage(
                        "key URI requires type=private, or type=public for verify",
                    ));
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
        let ml_kem_public_key = key_establishment::prepare(name, m, &bytes)?;
        let hkdf = hkdf::Inputs::load(name, m)?;
        Ok(Self {
            aes_gcm,
            hkdf,
            ml_kem_public_key,
            credential,
            new_pin,
            bytes,
            certificate_document,
            signing: signing::Inputs {
                context,
                verification_certificate,
                domain_context,
                signature,
            },
            tag,
            kbkdf: kbkdf::Inputs {
                label: kdf_label,
                context: kdf_context,
                iv: kdf_iv,
            },
            montgomery: montgomery::Inputs {
                peer,
                shared_info: montgomery_info,
            },
            random,
            so,
        })
    }
}
