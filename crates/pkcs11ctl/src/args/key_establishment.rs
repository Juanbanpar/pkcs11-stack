// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{required, value};
use clap::Command;

pub(super) fn kem_parameter(command: Command) -> Command {
    command.arg(
        required("parameter-set", "Expected ML-KEM parameter set").value_parser([
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        ]),
    )
}
pub(super) fn hkdf_digest(command: Command) -> Command {
    command.arg(
        required("digest", "HKDF hash; base key must match its output length")
            .value_parser(["sha256", "sha384", "sha512"]),
    )
}
pub(super) fn hkdf_options(command: Command) -> Command {
    hkdf_digest(command)
        .arg(
            required("kind", "Output key type and permissions").value_parser([
                "aes128",
                "aes192",
                "aes256",
                "derivation-secret",
            ]),
        )
        .arg(
            value("length", "Generic derivation-secret length in bytes")
                .required_if_eq("kind", "derivation-secret"),
        )
        .arg(value(
            "salt-file",
            "Public salt file, at most 4096 bytes; omitted means zero salt",
        ))
        .arg(value(
            "info-file",
            "Public protocol context file, at most 4096 bytes; omitted means empty",
        ))
}
pub(super) fn hybrid_options(command: Command) -> Command {
    hkdf_options(command)
        .mut_arg("digest", |arg| {
            arg.value_parser(["sha512"])
                .help("Hybrid combiner hash: sha512")
        })
        .mut_arg("salt-file", |arg| {
            arg.help("Public salt file, at most 128 bytes; omitted means zero salt")
        })
        .mut_arg("info-file", |arg| {
            arg.required(true)
                .help("Nonempty public protocol context file, at most 4096 bytes")
        })
}
