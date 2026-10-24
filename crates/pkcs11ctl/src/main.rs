// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! PKCS#11 command-line workflows over the client library.
mod args;
mod inspect;
mod operations;
mod support;
use secrecy::ExposeSecret;
use std::process::ExitCode;
use support::*;

fn execute(matches: &clap::ArgMatches) -> Result<()> {
    let (name, m) = matches
        .subcommand()
        .ok_or_else(|| usage("missing command"))?;
    if get(m, "certificate-file").is_none() {
        need(matches, "module")?;
    }
    let inputs = operations::Inputs::load(name, m)?;
    if let Some(certificate) = &inputs.verification_certificate {
        let value = operations::verify(certificate, m, &inputs)?;
        return emit(name, value, get(matches, "format") == Some("json"));
    }
    let module_path = need(matches, "module")?;
    let target = if let Some(path) = get(m, "output") {
        Some(BinaryOutput::open(path)?)
    } else {
        None
    };
    let mut module = pkcs11_client::Provider::load(module_path)?;
    let outcome = operations::run(&mut module, name, m, &inputs);
    let finalized = module.finalize();
    let output = finish(outcome, finalized, "module finalization")?;
    match output {
        operations::Output::Structured(value) => {
            emit(name, value, get(matches, "format") == Some("json"))
        }
        operations::Output::Binary(bytes) => target
            .ok_or_else(|| usage("missing output destination"))?
            .write(&bytes),
        operations::Output::SecretBinary(bytes) => target
            .ok_or_else(|| usage("missing output destination"))?
            .write(bytes.expose_secret()),
    }
}
fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let requested_json = arguments
        .windows(2)
        .any(|w| w[0] == "--format" && w[1] == "json")
        || arguments.iter().any(|a| a == "--format=json");
    let matches = match args::command().try_get_matches_from(arguments) {
        Ok(m) => m,
        Err(e)
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return match e.print() {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(6),
            };
        }
        Err(_) => {
            // clap diagnostics can quote raw URI/PIN arguments. Never echo unparsed values.
            let message = "invalid command line; use pkcs11ctl --help or <command> --help";
            if requested_json {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema_version":1,"error":{"kind":"input","message":message}})
                );
            } else {
                eprintln!("{message}");
            }
            return ExitCode::from(2);
        }
    };
    match execute(&matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if get(&matches, "format") == Some("json") {
                eprintln!(
                    "{}",
                    serde_json::json!({"schema_version":1,"error":{"kind":error.kind,"message":error.message}})
                );
            } else {
                eprintln!("{}: {}", error.kind, error.message);
            }
            ExitCode::from(error.code)
        }
    }
}
