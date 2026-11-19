// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{flag, required, value};
use clap::Command;

pub(super) fn context(command: Command) -> Command {
    command
        .arg(
            value(
                "context-pin-file",
                "Separate per-operation PIN for always-authenticate keys",
            )
            .conflicts_with("context-protected-path"),
        )
        .arg(flag(
            "context-protected-path",
            "Use protected path for context authentication",
        ))
}
pub(super) fn signature(command: Command) -> Command {
    command
        .arg(required("algorithm", "Signature family").value_parser([
            "rsa-pkcs1",
            "rsa-pss",
            "ecdsa",
            "ed25519",
            "ed448",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "ed25519",
            "ed448",
            "hash-ml-dsa",
            "hash-slh-dsa",
            "slh-dsa-sha2-128s",
            "slh-dsa-sha2-128f",
            "slh-dsa-sha2-192s",
            "slh-dsa-sha2-192f",
            "slh-dsa-sha2-256s",
            "slh-dsa-sha2-256f",
            "slh-dsa-shake-128s",
            "slh-dsa-shake-128f",
            "slh-dsa-shake-192s",
            "slh-dsa-shake-192f",
            "slh-dsa-shake-256s",
            "slh-dsa-shake-256f",
            "hash-slh-dsa-sha2-128s",
            "hash-slh-dsa-sha2-128f",
            "hash-slh-dsa-sha2-192s",
            "hash-slh-dsa-sha2-192f",
            "hash-slh-dsa-sha2-256s",
            "hash-slh-dsa-sha2-256f",
        ]))
        .arg(
            value("digest", "Required for RSA/ECDSA; forbidden for ML-DSA")
                .required_if_eq_any([
                    ("algorithm", "rsa-pkcs1"),
                    ("algorithm", "rsa-pss"),
                    ("algorithm", "ecdsa"),
                    ("algorithm", "hash-ml-dsa"),
                    ("algorithm", "hash-slh-dsa"),
                ])
                .value_parser([
                    "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256",
                    "sha3-384", "sha3-512", "shake128", "shake256",
                ]),
        )
        .arg(
            value("mgf-digest", "Required for PSS only")
                .value_parser(["sha1", "sha224", "sha256", "sha384", "sha512"]),
        )
        .arg(flag(
            "allow-sha1",
            "Explicitly allow the legacy SHA-1 signature profile",
        ))
        .arg(flag(
            "allow-sha224",
            "Explicitly allow the legacy SHA-224 signature profile",
        ))
        .arg(value("salt-length", "Exact PSS salt length in bytes"))
        .arg(
            value("parameter-set", "Required for hash-ml-dsa/hash-slh-dsa").value_parser([
                "ml-dsa-44",
                "ml-dsa-65",
                "ml-dsa-87",
                "slh-dsa-sha2-128s",
                "slh-dsa-sha2-128f",
                "slh-dsa-sha2-192s",
                "slh-dsa-sha2-192f",
                "slh-dsa-sha2-256s",
                "slh-dsa-sha2-256f",
                "slh-dsa-shake-128s",
                "slh-dsa-shake-128f",
                "slh-dsa-shake-192s",
                "slh-dsa-shake-192f",
                "slh-dsa-shake-256s",
                "slh-dsa-shake-256f",
            ]),
        )
        .arg(required("input", "Input file; - reads stdin"))
        .arg(value(
            "context-file",
            "ML-DSA domain context file, at most 255 bytes; no stdin",
        ))
        .arg(
            value(
                "input-kind",
                "Interpret input as message or already computed digest",
            )
            .value_parser(["message", "digest"])
            .default_value("message"),
        )
}
pub(super) fn signing(command: Command) -> Command {
    signature(command)
        .arg(
            value(
                "hashing",
                "Classical message hashing policy; defaults to token",
            )
            .value_parser(["token", "allow-software", "software"]),
        )
        .arg(
            value(
                "hedging",
                "ML-DSA randomness requirement; defaults to required",
            )
            .value_parser(["required", "preferred", "deterministic"]),
        )
}
pub(super) fn bind() -> Command {
    Command::new("bind")
        .about("Prove a key/certificate association with one signature")
        .arg(required("certificate", "Explicit certificate URI"))
        .arg(
            value(
                "hashing",
                "Classical binding probe hashing policy; defaults to token",
            )
            .value_parser(["token", "allow-software", "software"]),
        )
}

pub(super) fn sign() -> Command {
    Command::new("sign")
        .about("Sign once; with a certificate, bind first and verify the output")
        .arg(value(
            "certificate",
            "Explicit certificate URI; binding adds one signature",
        ))
        .arg(required(
            "output",
            "New output file, or - for raw binary signature stdout",
        ))
}

pub(super) fn verify() -> Command {
    Command::new("verify")
        .about(
            "Verify a raw signature using a certificate or token public key; no trust validation",
        )
        .arg(
            value("certificate", "Token certificate URI with type=cert")
                .required_unless_present_any(["certificate-file", "key"]),
        )
        .arg(
            value(
                "certificate-file",
                "X.509 DER certificate file; no module required",
            )
            .conflicts_with_all([
                "certificate",
                "key",
                "pin-file",
                "protected-path",
                "role",
            ]),
        )
        .arg(
            value("key", "Token public key URI with type=public")
                .conflicts_with_all(["certificate", "certificate-file"]),
        )
        .arg(required("signature", "Raw signature file; - reads stdin"))
}
