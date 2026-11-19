// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{inputs::Inputs, support::*};
use clap::ArgMatches;
use pkcs11_client::{ManagementSession, Provider};
use serde_json::{Value, json};

pub(crate) fn expected_token(m: &ArgMatches) -> Result<pkcs11_client::Pkcs11Uri> {
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

pub(super) fn initialize(module: &mut Provider, m: &ArgMatches, inputs: &Inputs) -> Result<Value> {
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
    Ok(json!({"initialized":true}))
}

pub(super) fn change_pin(
    session: &mut ManagementSession<'_>,
    name: &str,
    inputs: &Inputs,
) -> Result<Value> {
    let result = match name {
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

        _ => unreachable!(),
    };
    Ok(result)
}
