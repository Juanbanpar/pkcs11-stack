// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::{Arg, ArgAction, Command};

pub(super) fn value(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).long(name).help(help).num_args(1)
}
pub(super) fn required(name: &'static str, help: &'static str) -> Arg {
    value(name, help).required(true)
}
pub(super) fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}
pub(super) fn token(command: Command) -> Command {
    command.arg(required(
        "token",
        "Full token PKCS#11 URI, without object criteria",
    ))
}
pub(super) fn object(command: Command) -> Command {
    command.arg(required(
        "object",
        "Stable PKCS#11 object URI; exactly one match required",
    ))
}
pub(super) fn key(command: Command) -> Command {
    command.arg(required("key", "Stable private-key URI with type=private"))
}
pub(super) fn key_family(command: Command) -> Command {
    command.arg(
        value("key-family", "Key/certificate algorithm family")
            .value_parser(["classical", "ml-dsa", "eddsa"])
            .default_value("classical"),
    )
}
pub(super) fn auth(command: Command) -> Command {
    command
        .arg(
            value(
                "pin-file",
                "UTF-8 PIN file; removes one final LF/CRLF; never a PIN argument",
            )
            .conflicts_with("protected-path"),
        )
        .arg(flag(
            "protected-path",
            "Use the token's protected authentication path",
        ))
        .arg(
            value("role", "Explicit token login role")
                .value_parser(["user", "so"])
                .default_value("user"),
        )
}
pub(super) fn mutation(command: Command) -> Command {
    command.arg(
        flag(
            "confirm",
            "Explicitly authorize this mutation; no automatic retries",
        )
        .required(true),
    )
}
pub(super) fn named(command: Command) -> Command {
    command
        .arg(required("label", "Object label"))
        .arg(required("id", "Nonempty hexadecimal object ID"))
}
