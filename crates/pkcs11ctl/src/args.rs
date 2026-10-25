// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::{Arg, ArgAction, Command};

fn value(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).long(name).help(help).num_args(1)
}
fn required(name: &'static str, help: &'static str) -> Arg {
    value(name, help).required(true)
}
fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}
fn token(command: Command) -> Command {
    command.arg(required(
        "token",
        "Full token PKCS#11 URI, without object criteria",
    ))
}
fn object(command: Command) -> Command {
    command.arg(required(
        "object",
        "Stable PKCS#11 object URI; exactly one match required",
    ))
}
fn key(command: Command) -> Command {
    command.arg(required("key", "Stable private-key URI with type=private"))
}
fn key_family(command: Command) -> Command {
    command.arg(
        value("key-family", "Key/certificate algorithm family")
            .value_parser(["classical", "ml-dsa"])
            .default_value("classical"),
    )
}
fn auth(command: Command) -> Command {
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
fn context(command: Command) -> Command {
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
fn signature(command: Command) -> Command {
    command
        .arg(required("algorithm", "Signature family").value_parser([
            "rsa-pkcs1",
            "rsa-pss",
            "ecdsa",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
        ]))
        .arg(
            value("digest", "Required for RSA/ECDSA; forbidden for ML-DSA")
                .required_if_eq_any([
                    ("algorithm", "rsa-pkcs1"),
                    ("algorithm", "rsa-pss"),
                    ("algorithm", "ecdsa"),
                ])
                .value_parser(["sha256", "sha384", "sha512"]),
        )
        .arg(
            value("mgf-digest", "Required for PSS only")
                .value_parser(["sha256", "sha384", "sha512"]),
        )
        .arg(value("salt-length", "Exact PSS salt length in bytes"))
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
fn signing(command: Command) -> Command {
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
fn mutation(command: Command) -> Command {
    command.arg(
        flag(
            "confirm",
            "Explicitly authorize this mutation; no automatic retries",
        )
        .required(true),
    )
}
fn kem_parameter(command: Command) -> Command {
    command.arg(
        required("parameter-set", "Expected ML-KEM parameter set").value_parser([
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        ]),
    )
}
fn hkdf_digest(command: Command) -> Command {
    command.arg(
        required("digest", "HKDF hash; base key must match its output length")
            .value_parser(["sha256", "sha384", "sha512"]),
    )
}
fn hkdf_options(command: Command) -> Command {
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
fn hybrid_options(command: Command) -> Command {
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
fn named(command: Command) -> Command {
    command
        .arg(required("label", "Object label"))
        .arg(required("id", "Nonempty hexadecimal object ID"))
}

pub(crate) fn command() -> Command {
    let inspect = Command::new("inspect")
        .about("Read explicit attributes of one object")
        .arg(value("attributes", "Comma-separated class,label,id,object-id,private,sign,sensitive,extractable,always-authenticate,key-type,modulus,exponent,ec-params,ec-point,subject,issuer,serial,value")
            .default_value("class,label,id"));
    let export = Command::new("export")
        .about("Export certificate/data bytes or public-key SPKI DER; no trust validation")
        .arg(
            value("key-family", "Public-key algorithm family")
                .value_parser(["classical", "ml-dsa", "ml-kem"])
                .default_value("classical"),
        )
        .arg(required(
            "output",
            "New output file, or - for binary stdout",
        ));
    let bind = Command::new("bind")
        .about("Prove a key/certificate association with one signature")
        .arg(required("certificate", "Explicit certificate URI"))
        .arg(
            value(
                "hashing",
                "Classical binding probe hashing policy; defaults to token",
            )
            .value_parser(["token", "allow-software", "software"]),
        );
    let sign = Command::new("sign")
        .about("Sign once; with a certificate, bind first and verify the output")
        .arg(value(
            "certificate",
            "Explicit certificate URI; binding adds one signature",
        ))
        .arg(required(
            "output",
            "New output file, or - for raw binary signature stdout",
        ));
    let diagnose = Command::new("diagnose")
        .about("Check bounded pool capacity, role and lease reuse")
        .arg(value("pool-size", "Number of concurrent leases, 1..=64").default_value("2"));
    let verify = Command::new("verify")
        .about("Verify a raw signature using a certificate; no certificate trust validation")
        .arg(
            value("certificate", "Token certificate URI with type=cert")
                .required_unless_present("certificate-file"),
        )
        .arg(
            value(
                "certificate-file",
                "X.509 DER certificate file; no module required",
            )
            .conflicts_with_all(["certificate", "pin-file", "protected-path", "role"]),
        )
        .arg(required("signature", "Raw signature file; - reads stdin"));
    let random = Command::new("random")
        .about("Generate bytes once using the selected token's random generator")
        .arg(required("length", "Number of bytes, 1..=1048576"))
        .arg(required(
            "output",
            "New output file, or - for raw binary stdout",
        ));
    let init_token = Command::new("init-token")
        .about("Initialize/erase a token; destroys existing token contents")
        .arg(required("slot", "Current diagnostic slot ID"))
        .arg(required(
            "expected-token",
            "Exact token URI from tokens, with token/manufacturer/model/serial",
        ))
        .arg(required("label", "Token label, at most 32 UTF-8 bytes"))
        .arg(required("so-pin-file", "SO PIN file"));
    let init_pin = Command::new("init-pin")
        .about("Initialize/reset USER PIN; requires --role so and --pin-file")
        .arg(required("new-pin-file", "New USER PIN file"));
    let set_pin = Command::new("set-pin")
        .about("Change authenticated role's host PIN once")
        .arg(required("new-pin-file", "New PIN file"));
    let generate = Command::new("generate")
        .about("Generate a persistent nonextractable signing or ML-KEM key pair")
        .arg(required("kind", "Key kind").value_parser([
            "rsa",
            "p256",
            "p384",
            "p521",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        ]))
        .arg(value("bits", "RSA modulus size; RSA only"))
        .arg(flag(
            "always-authenticate",
            "Require per-signature context authentication",
        ));
    let import = Command::new("import")
        .about("Import public certificate DER, ML-KEM SPKI DER or data bytes")
        .arg(required("kind", "Object kind").value_parser(["cert", "data", "ml-kem"]))
        .arg(required("input", "Input file; - reads stdin"));
    let set_label = Command::new("set-label")
        .about("Relabel exactly one object")
        .arg(required("label", "New label"));
    let commands = [
        Command::new("info").about("Inspect the loaded library"),
        Command::new("slots").about("List diagnostic slot IDs"),
        Command::new("tokens").about("List tokens and stable token URIs"),
        token(Command::new("mechanisms").about("List advertised mechanisms")),
        auth(token(
            Command::new("objects").about("List persistent objects, without secret values"),
        )),
        auth(object(inspect)),
        auth(object(export)),
        auth(object(key_family(
            Command::new("certificate").about("Parse a supported certificate through client"),
        ))),
        auth(key(key_family(
            Command::new("capabilities").about("Inspect selected signing-key capabilities"),
        ))),
        auth(signing(key(
            Command::new("plan").about("Plan one signing request without signing")
        ))),
        context(auth(key(key_family(bind)))),
        context(auth(signing(key(sign)))),
        auth(signature(verify)),
        auth(token(random)),
        auth(object(
            Command::new("kem-capabilities")
                .about("Inspect current ML-KEM parameters and direction permissions")
                .arg(
                    required("operation", "Requested ML-KEM direction")
                        .value_parser(["encapsulate", "decapsulate"]),
                ),
        )),
        mutation(auth(named(kem_parameter(object(
            Command::new("encapsulate")
                .about("Create a token-held ML-KEM secret and write public ciphertext")
                .arg(required(
                    "output",
                    "New ciphertext file, or - for binary stdout",
                )),
        ))))),
        mutation(auth(named(kem_parameter(object(
            Command::new("decapsulate")
                .about("Decapsulate public ciphertext into a persistent token secret")
                .arg(required("input", "Ciphertext file; - reads stdin")),
        ))))),
        auth(hkdf_digest(object(
            Command::new("hkdf-capabilities")
                .about("Inspect a sensitive, nonextractable HKDF base secret"),
        ))),
        mutation(auth(named(hkdf_options(object(
            Command::new("derive-hkdf")
                .about("Derive a persistent nonextractable token key using HKDF"),
        ))))),
        mutation(auth(named(hybrid_options(object(
            Command::new("derive-hybrid")
                .about("Combine P-256 and ML-KEM-768 secrets on-token, then apply HKDF-SHA512")
                .arg(required(
                    "post-quantum",
                    "ML-KEM-768 raw secret URI with type=secret-key",
                )),
        ))))),
        auth(token(diagnose)),
        mutation(init_token),
        mutation(auth(token(init_pin))),
        mutation(auth(token(set_pin))),
        mutation(auth(named(token(generate)))),
        mutation(auth(named(token(import)))),
        mutation(auth(object(set_label))),
        mutation(auth(object(
            Command::new("delete").about("Delete exactly one object"),
        ))),
    ];
    Command::new("pkcs11ctl")
        .version(env!("CARGO_PKG_VERSION"))
        .about("PKCS#11 inspection, signing, verification and administration")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            value(
                "module",
                "Required explicit path to a trusted PKCS#11 library",
            )
            .global(true),
        )
        .arg(
            value(
                "format",
                "Structured output format (binary commands use --output)",
            )
            .value_parser(["text", "json"])
            .default_value("text")
            .global(true),
        )
        .subcommands(commands)
}
