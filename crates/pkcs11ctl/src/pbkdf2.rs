// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{operations::Output, support::*};
use clap::ArgMatches;
use pkcs11_client::{
    ManagementSession, PBKDF2_MAXIMUM_LENGTH, Pbkdf2Output, Pbkdf2Prf, Pbkdf2Request,
};
use secrecy::{ExposeSecretMut, SecretSlice};
use serde_json::json;
use std::{fs::File, io::Read};
use zeroize::Zeroizing;

pub(crate) fn selected(name: &str) -> bool {
    matches!(name, "pbkdf2-capabilities" | "generate-pbkdf2")
}
#[derive(Default)]
pub(crate) struct Inputs {
    password: Option<SecretSlice<u8>>,
    salt: Vec<u8>,
}
impl Inputs {
    pub(crate) fn load(name: &str, m: &ArgMatches) -> Result<Self> {
        let mut inputs = Self::default();
        if name != "generate-pbkdf2" {
            return Ok(inputs);
        }
        let path = need(m, "password-file")?;
        if path == "-" || need(m, "salt-file")? == "-" {
            return Err(usage("PBKDF2 password/salt require file paths"));
        }
        // Read without reallocating secret bytes, including on partial/oversized input.
        let mut password = Zeroizing::new(vec![0; PBKDF2_MAXIMUM_LENGTH + 1]);
        let mut file = File::open(path)?;
        let mut length = 0;
        loop {
            let read = match file.read(&mut password[length..]) {
                Ok(read) => read,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if read == 0 {
                break;
            }
            length += read;
            if length > PBKDF2_MAXIMUM_LENGTH {
                return Err(usage("PBKDF2 password exceeds 4096 bytes"));
            }
        }
        // Allocate before copying so boxing cannot free an unwiped password buffer.
        let mut secret = SecretSlice::from(vec![0; length]);
        secret
            .expose_secret_mut()
            .copy_from_slice(&password[..length]);
        inputs.password = Some(secret);
        inputs.salt = bounded_input(need(m, "salt-file")?, PBKDF2_MAXIMUM_LENGTH)?;
        let id = unhex(need(m, "id")?)?;
        inputs
            .request(m, &id)?
            .validate()
            .map_err(pkcs11_client::Error::from)?;
        Ok(inputs)
    }
    fn request<'a>(&'a self, m: &'a ArgMatches, id: &'a [u8]) -> Result<Pbkdf2Request<'a>> {
        let output = match need(m, "kind")? {
            "aes128" => Pbkdf2Output::Aes128,
            "aes192" => Pbkdf2Output::Aes192,
            "aes256" => Pbkdf2Output::Aes256,
            "derivation-secret" => Pbkdf2Output::DerivationSecret {
                length: number(m, "length")?,
            },
            _ => return Err(usage("unsupported PBKDF2 output")),
        };
        if !matches!(output, Pbkdf2Output::DerivationSecret { .. }) && get(m, "length").is_some() {
            return Err(usage("--length applies only to derivation-secret"));
        }
        let prf = match need(m, "digest")? {
            "sha224" => Pbkdf2Prf::HmacSha224,
            "sha256" => Pbkdf2Prf::HmacSha256,
            "sha384" => Pbkdf2Prf::HmacSha384,
            "sha512" => Pbkdf2Prf::HmacSha512,
            "sha512-224" => Pbkdf2Prf::HmacSha512_224,
            "sha512-256" => Pbkdf2Prf::HmacSha512_256,
            _ => return Err(usage("unsupported PBKDF2 PRF")),
        };
        Ok(Pbkdf2Request {
            password: self
                .password
                .as_ref()
                .ok_or_else(|| usage("missing PBKDF2 password"))?,
            salt: &self.salt,
            prf,
            iterations: need(m, "iterations")?
                .parse()
                .map_err(|_| usage("invalid PBKDF2 iterations"))?,
            output,
            id,
            label: need(m, "label")?.as_bytes(),
        })
    }
}
pub(crate) fn operation(
    session: &mut ManagementSession<'_>,
    name: &str,
    m: &ArgMatches,
    inputs: &Inputs,
) -> Result<Output> {
    let value = if name == "pbkdf2-capabilities" {
        json!({"advisory":true,"generate":session.pbkdf2_supported()?})
    } else {
        let id = unhex(need(m, "id")?)?;
        let request = inputs.request(m, &id)?;
        session.generate_pbkdf2(&request)?;
        json!({"generated":true,"digest":need(m,"digest")?,"iterations":request.iterations,"kind":need(m,"kind")?,"length":request.output.length(),"id_hex":hex(&id),"extractable":false})
    };
    Ok(Output::Structured(value))
}
