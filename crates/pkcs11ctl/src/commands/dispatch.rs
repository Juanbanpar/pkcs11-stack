// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{
    aes, aes_gcm, digest, generation, hkdf, inspect, kbkdf, key_establishment, mac, montgomery,
    objects, signing, token,
};

use crate::{inputs::Inputs, support::*};
use clap::ArgMatches;
use pkcs11_client::{Provider, SessionMode};
use serde_json::json;
use std::num::NonZeroUsize;

use super::Output;

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
        "init-token" => token::initialize(module, m, inputs)?,
        "certificate" | "capabilities" | "plan" | "bind" | "sign" | "verify" => {
            return signing::run(module, name, m, inputs);
        }
        _ => return management_command(module, name, m, inputs),
    };
    Ok(Output::Structured(value))
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
    if name == "generation-options" {
        return generation::options(module, m).map(Output::Structured);
    }
    if name == "function-support" {
        return Ok(Output::Structured(json!(
            module
                .function_availability()?
                .into_iter()
                .map(|entry| json!({
                    "function": format!("{:?}", entry.function),
                    "supported": entry.supported,
                }))
                .collect::<Vec<_>>()
        )));
    }
    if name == "mechanisms" {
        let mut items = vec![];
        for entry in module.mechanism_capabilities(&location)? {
            items.push(json!({
                "name": entry.name,
                "identifier": *entry.mechanism,
                "family": entry.family.as_str(),
                "operations": entry.operations.iter().map(|operation| operation.as_str()).collect::<Vec<_>>(),
                "executable": entry.executable,
                "min_key_size": entry.minimum_key_size,
                "max_key_size": entry.maximum_key_size,
                "hardware": entry.hardware,
            }));
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
    let mutation = key_establishment::mutation(name)
        || hkdf::mutation(name)
        || name == "derive-kbkdf"
        || montgomery::mutation(name)
        || matches!(
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
    if aes_gcm::selected(name) {
        return aes_gcm::operation(session, name, m, inputs.aes_gcm.as_ref());
    }
    if key_establishment::selected(name) {
        return key_establishment::operation(session, name, m, &inputs.bytes);
    }
    if hkdf::selected(name) {
        return hkdf::run(session, name, m, &inputs.hkdf);
    }
    if montgomery::selected(name) {
        return montgomery::operation(session, name, m, &inputs.montgomery);
    }
    let value = match name {
        "random" => {
            return Ok(Output::SecretBinary(
                session.generate_random(
                    inputs
                        .random
                        .ok_or_else(|| usage("missing random request"))?,
                )?,
            ));
        }
        "objects" | "inspect" | "export" | "import" | "delete" | "set-label" => {
            return objects::run(session, name, m, inputs);
        }
        "init-pin" | "set-pin" => token::change_pin(session, name, inputs)?,
        "digest" => return digest::run(session, m, &inputs.bytes),
        "mac" | "verify-mac" => return mac::run(session, name, m, &inputs.bytes, &inputs.tag),
        "encrypt-aes" | "decrypt-aes" | "aes-cipher-capabilities" => {
            return aes::run(session, name, m, &inputs.bytes);
        }
        "derive-kbkdf" => return kbkdf::run(session, m, &inputs.kbkdf),
        "generate" => generation::generate(session, m)?,
        _ => return Err(usage("unknown command")),
    };
    Ok(Output::Structured(value))
}
