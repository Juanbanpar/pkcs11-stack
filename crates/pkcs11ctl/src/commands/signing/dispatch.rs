// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::ArgMatches;
use pkcs11_client::Provider;
use std::num::NonZeroUsize;

use crate::{inputs::Inputs as CommandInputs, support::*};

use super::super::Output;
use super::{Inputs, classical, eddsa, ml_dsa, prehash, request::policy, slh_dsa};

pub(in crate::commands) fn run(
    module: &Provider,
    name: &str,
    m: &ArgMatches,
    prepared: &CommandInputs,
) -> Result<Output> {
    let selector = if name == "certificate" {
        "object"
    } else if name == "verify" {
        if get(m, "key").is_some() {
            "key"
        } else {
            "certificate"
        }
    } else {
        "key"
    };
    let location = token_uri(uri(m, selector)?)?;
    let client = module.client(&location, NonZeroUsize::new(1).unwrap(), policy(m))?;
    let outcome = client_operation(
        &client,
        name,
        m,
        &prepared.credential,
        &prepared.bytes,
        &prepared.signing,
    );
    finish(outcome, client.close(), "client session closure")
}
fn client_operation(
    client: &pkcs11_client::Client<'_>,
    name: &str,
    m: &ArgMatches,
    credential: &Credential,
    bytes: &[u8],
    inputs: &Inputs,
) -> Result<Output> {
    if eddsa::selected(m) {
        return eddsa::client_operation(client, name, m, credential, bytes, inputs);
    }
    if prehash::selected(m) {
        return prehash::client_operation(client, name, m, credential, bytes, inputs);
    }
    if slh_dsa::selected(m) {
        return slh_dsa::client_operation(client, name, m, credential, bytes, inputs);
    }
    if ml_dsa::selected(m) {
        return ml_dsa::client_operation(client, name, m, credential, bytes, inputs);
    }
    classical::client_operation(client, name, m, credential, bytes, inputs)
}
