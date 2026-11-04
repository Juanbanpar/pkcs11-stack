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
            .value_parser(["classical", "ml-dsa", "eddsa"])
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
            "ed25519",
            "ed448",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
        ]))
        .arg(
            value(
                "digest",
                "Required for RSA/ECDSA; forbidden for ML-DSA/EdDSA",
            )
            .required_if_eq_any([
                ("algorithm", "rsa-pkcs1"),
                ("algorithm", "rsa-pss"),
                ("algorithm", "ecdsa"),
            ])
            .value_parser([
                "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384",
                "sha3-512",
            ]),
        )
        .arg(value("mgf-digest", "Required for PSS only").value_parser([
            "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        ]))
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
        .about("Export certificate/data bytes, public SPKI DER or raw curveName keys; no trust validation")
        .arg(
            value("key-family", "Public-key algorithm family")
                .value_parser(["classical", "ml-dsa", "ml-kem", "eddsa", "x25519", "x448", "curve25519", "curve448", "edwards25519", "edwards448"])
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
        .arg(flag(
            "multipart",
            "Stream an original RSA/ECDSA/ML-DSA message; at most 64 MiB",
        ))
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
        .arg(flag("multipart", "Verify an original RSA/ECDSA/ML-DSA message in software using bounded storage; at most 64 MiB"))
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
        .about("Generate persistent nonextractable signing, authentication, encryption, derivation or KEM keys")
        .arg(required("kind", "Key kind").value_parser([
            "rsa",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            "aes128",
            "aes192",
            "aes256",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "hmac-sha224",
            "hmac-sha512-224",
            "hmac-sha512-256",
            "hmac-sha3-224",
            "hmac-sha3-256",
            "hmac-sha3-384",
            "hmac-sha3-512",
            "x25519",
            "x448",
            "curve25519",
            "curve448",
            "edwards25519",
            "edwards448",
            "p256",
            "p384",
            "p521",
            "ed25519",
            "ed448",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        ]))
        .arg(value("bits", "RSA modulus size; RSA only"))
        .arg(flag("general-tag", "HMAC only: restrict the new key to its native general mechanism"))
        .arg(
            value(
                "purpose",
                "AES encryption/wrapping/authentication or RSA signing/encryption",
            )
            .value_parser(["signing", "encryption", "wrapping", "authentication", "authentication-general"])
            .required_if_eq_any([
                ("kind", "aes128"),
                ("kind", "aes192"),
                ("kind", "aes256"),
            ]),
        )
        .arg(flag(
            "always-authenticate",
            "Require context authentication for each private-key operation",
        ));
    let import = Command::new("import")
        .about("Import public certificate/key DER, raw curveName public keys or data bytes")
        .arg(required("kind", "Object kind").value_parser([
            "cert",
            "data",
            "ml-kem",
            "public-key",
            "eddsa",
            "x25519",
            "x448",
            "curve25519",
            "curve448",
            "edwards25519",
            "edwards448",
        ]))
        .arg(required("input", "Input file; - reads stdin"))
        .arg(
            value("purpose", "Required for public-key import")
                .value_parser(["verification", "encryption"]),
        );
    let set_label = Command::new("set-label")
        .about("Relabel exactly one object")
        .arg(required("label", "New label"));
    let gcm = |name, help| {
        auth(object(Command::new(name).about(help)
        .arg(required("nonce", "Exactly 24 hex digits; encryption requires a unique nonce per key, also after errors"))
        .arg(value("aad-file", "Additional authenticated data file, at most 1 MiB; omitted means empty; no stdin"))
        .arg(flag("multipart", "Use native multipart AES-GCM with a zeroizing input buffer; the 16 MiB plaintext limit remains"))
        .arg(required("input", "Input file; - reads stdin; ciphertext includes the full 16-byte tag"))
        .arg(required("output", "New output file, or - for binary stdout; nonce/AAD are not included"))))
    };
    let hash_mode = |command: Command| {
        command
            .arg(flag(
                "multipart",
                "Use native token-hashed SHA-512 streams; original messages only, at most 64 MiB",
            ))
            .arg(
                value(
                    "input-kind",
                    "Original message hashed on token, or exactly 64 raw SHA-512 digest bytes",
                )
                .value_parser(["message", "digest"])
                .default_value("message"),
            )
    };
    let hash_input = |command: Command| {
        hash_mode(command)
            .arg(
                required("parameter-set", "Expected ML-DSA key parameter set").value_parser([
                    "ml-dsa-44",
                    "ml-dsa-65",
                    "ml-dsa-87",
                ]),
            )
            .arg(required(
                "input",
                "Input file; - reads stdin; at most 64 MiB for messages",
            ))
            .arg(value(
                "context-file",
                "FIPS 204 context file, at most 255 bytes; no stdin",
            ))
    };
    let commands = [
        auth(object(hash_mode(Command::new("hash-ml-dsa-capabilities").about("Inspect SHA-512 HashML-DSA signing support for one input mode")))),
        context(auth(object(hash_input(Command::new("sign-hash-ml-dsa").about("Sign using native SHA-512 HashML-DSA; no implicit hashing fallback")
            .arg(value("hedging", "Randomness requirement; defaults to required").value_parser(["required", "preferred", "deterministic"]))
            .arg(required("output", "New signature file, or - for binary stdout")))))),
        auth(object(hash_input(Command::new("verify-hash-ml-dsa").about("Verify SHA-512 HashML-DSA on the token with a public key")
            .arg(required("signature", "Raw signature file; - reads stdin"))))),
        Command::new("info").about("Inspect the loaded library"),
        Command::new("slots").about("List diagnostic slot IDs"),
        Command::new("tokens").about("List tokens and stable token URIs"),
        token(Command::new("mechanisms").about("List advertised mechanisms")),
        token(
            Command::new("generation-options")
                .about("List advisory key generation choices; no login or generation"),
        ),
        auth(token(
            Command::new("objects").about("List persistent objects, without secret values"),
        )),
        auth(token(Command::new("public-metadata").about("Read bounded public metadata, including profile and validation objects; no trust validation"))),
        token(Command::new("session-validation").about("Query provider-reported validation flags in a fresh session; not a report on previous commands")),
        auth(object(inspect)),
        auth(object(Command::new("template-metadata")
            .about("Inspect bounded wrap/unwrap/derive template structure without leaf values")
            .arg(required("template", "Template attribute").value_parser(["wrap", "unwrap", "derive"])))),
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
        auth(object(
            Command::new("encrypt-rsa-oaep")
                .about("Encrypt one RSA-OAEP block with explicit SHA-2 parameters")
                .arg(
                    required("digest", "OAEP hash; also the default MGF1 digest")
                        .value_parser(["sha256", "sha384", "sha512"]),
                )
                .arg(
                    value("mgf-digest", "MGF1 digest; defaults to --digest")
                        .value_parser(["sha256", "sha384", "sha512"]),
                )
                .arg(value(
                    "label-hex",
                    "Binary OAEP label as hexadecimal, at most 4096 bytes; default empty",
                ))
                .arg(required("input", "Plaintext file; - reads stdin"))
                .arg(required(
                    "output",
                    "New ciphertext file, or - for binary stdout",
                )),
        )),
        context(auth(object(
            Command::new("decrypt-rsa-oaep")
                .about("Decrypt one RSA-OAEP block with optional context authentication")
                .arg(
                    required("digest", "OAEP hash; also the default MGF1 digest")
                        .value_parser(["sha256", "sha384", "sha512"]),
                )
                .arg(
                    value("mgf-digest", "MGF1 digest; defaults to --digest")
                        .value_parser(["sha256", "sha384", "sha512"]),
                )
                .arg(value(
                    "label-hex",
                    "Binary OAEP label as hexadecimal, at most 4096 bytes; default empty",
                ))
                .arg(required("input", "Ciphertext file; - reads stdin"))
                .arg(required(
                    "output",
                    "New plaintext file, or - for binary stdout",
                )),
        ))),
        auth(signature(verify)),
        auth(
            signing(
                Command::new("verify-token")
                    .about("Verify a raw RSA/ECDSA/EdDSA/ML-DSA signature on the token using a public key")
                    .arg(flag("multipart", "Stream an original RSA/ECDSA/ML-DSA message; ML-DSA token verification requires a 3.2 interface; at most 64 MiB"))
                    .arg(required("key", "Stable public-key URI with type=public"))
                    .arg(required("signature", "Raw signature file; - reads stdin")),
            )
            .mut_arg("algorithm", |arg| {
                arg.value_parser(["rsa-pkcs1", "rsa-pss", "ecdsa", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"])
            }),
        ),
        auth(token(
            Command::new("digest")
                .about("Hash a file on the token using bounded multipart input")
                .arg(
                    required("algorithm", "Fixed-output hash algorithm").value_parser([
                        "sha224",
                        "sha256",
                        "sha384",
                        "sha512",
                        "sha512-224",
                        "sha512-256",
                        "sha3-224",
                        "sha3-256",
                        "sha3-384",
                        "sha3-512",
                    ]),
                )
                .arg(required("input", "File to hash; - reads stdin")),
        )),
        auth(token(
            Command::new("digest-algorithms")
                .about("List advertised multipart token hash algorithms"),
        )),
        auth(token(random)),
        auth(object(
            Command::new("key-wrap-capabilities")
                .about("List advisory AES-KW/KWP choices for a wrapping key")
                .arg(required("operation", "Direction").value_parser(["wrap", "unwrap"])),
        )),
        auth(object(
            Command::new("wrap-aes-key")
                .about("Wrap one extractable AES key with an explicit KW/KWP algorithm")
                .arg(required("target", "Stable target AES secret-key URI"))
                .arg(
                    required("algorithm", "Key-wrap algorithm; default IV only")
                        .value_parser(["kw", "kwp"]),
                )
                .arg(required(
                    "output",
                    "New wrapped-key file, or - for binary stdout",
                )),
        )),
        mutation(auth(object(
            Command::new("unwrap-aes-key")
                .about("Unwrap one KW/KWP blob into a sensitive nonextractable AES key")
                .arg(
                    required("algorithm", "Algorithm used for wrapping")
                        .value_parser(["kw", "kwp"]),
                )
                .arg(required(
                    "input",
                    "24/32/40-byte wrapped AES key; - reads stdin",
                ))
                .arg(required("id", "New secret-key ID in hexadecimal"))
                .arg(required("label", "New secret-key label")),
        ))),
        gcm(
            "encrypt-aes-gcm",
            "Encrypt at most 16 MiB; output is ciphertext followed by a full tag",
        ),
        gcm(
            "decrypt-aes-gcm",
            "Authenticate/decrypt AES-GCM; no output before authentication and checked closure",
        ),
        auth(object(
            Command::new("aes-gcm-capabilities")
                .about("Inspect current AES-GCM key permissions and provider support")
                .arg(flag("multipart", "Check native multipart entry points instead of single-part support"))
                .arg(
                    required("operation", "Requested direction")
                        .value_parser(["encrypt", "decrypt"]),
                ),
        )),
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
        mutation(auth(named(object(
            Command::new("derive-ecdh")
                .about("Derive a persistent ECDH key with explicit KDF and output purpose")
                .arg(required(
                    "input",
                    "Peer public key file (SPKI DER); - reads stdin",
                ))
                .arg(required("kdf", "Explicit KDF; no fallback").value_parser([
                    "null",
                    "x963-sha256",
                    "x963-sha384",
                    "x963-sha512",
                    "sp800-sha256",
                    "sp800-sha384",
                    "sp800-sha512",
                ]))
                .arg(required("kind", "Derived key purpose").value_parser([
                    "raw-secret",
                    "derivation-secret",
                    "aes128",
                    "aes192",
                    "aes256",
                ]))
                .arg(value(
                    "length",
                    "Byte length, required only for derivation-secret",
                ))
                .arg(value(
                    "shared-info-file",
                    "Public KDF context file, at most 4096 bytes",
                )),
        )))),
        context(auth(object(Command::new("sign-eddsa-named")
            .about("Sign original input using an explicit RFC 8032 curveName scheme")
            .arg(required("scheme", "EdDSA scheme; ph hashing runs on token").value_parser(["ed25519", "ed25519ctx", "ed25519ph", "ed448", "ed448ph"]))
            .arg(value("context-file", "Public binary context file, at most 255 bytes; no stdin"))
            .arg(required("input", "Original message file; - reads stdin"))
            .arg(required("output", "New signature file, or - for binary stdout"))))),
        auth(object(Command::new("verify-eddsa-named")
            .about("Verify original input on token using an explicit RFC 8032 curveName scheme")
            .arg(required("scheme", "EdDSA scheme; ph hashing runs on token").value_parser(["ed25519", "ed25519ctx", "ed25519ph", "ed448", "ed448ph"]))
            .arg(value("context-file", "Public binary context file, at most 255 bytes; no stdin"))
            .arg(required("input", "Original message file; - reads stdin"))
            .arg(required("signature", "Raw signature file; - reads stdin")))),
        mutation(auth(named(object(Command::new("derive-montgomery")
            .about("Derive a protected key from an explicit curveName private key")
            .arg(required("curve", "Explicit RFC 7748 curveName profile").value_parser(["curve25519", "curve448"]))
            .arg(required("input", "Raw 32/56-byte little-endian peer public key; - reads stdin"))
            .args(montgomery_kdf_args(false)))))),
        mutation(auth(named(object(Command::new("derive-x25519")
            .about("Derive a protected token-held key from an existing X25519 key")
            .arg(required("input", "Peer X25519 public key (SPKI DER); - reads stdin"))
            .args(montgomery_kdf_args(false)))))),
        mutation(auth(named(object(Command::new("derive-x448")
            .about("Derive a protected token-held key from an existing X448 private key")
            .arg(required("input", "Peer X448 public key (SPKI DER); - reads stdin"))
            .args(montgomery_kdf_args(true)))))),
        auth(hkdf_digest(object(
            Command::new("hkdf-capabilities")
                .about("Inspect a sensitive, nonextractable HKDF base secret"),
        ))),
        auth(object(
            Command::new("hmac-capabilities")
                .about("Inspect native HMAC support")
                .arg(flag("general-tag", "Inspect general mechanisms; omitted inspects full tags"))
                .arg(required("operation", "MAC direction").value_parser(["generate", "verify"])),
        )),
        auth(object(
            Command::new("mac-hmac")
                .about("Generate a native HMAC")
                .arg(flag("multipart", "Use native multipart MAC with a zeroizing input buffer; the 16 MiB limit remains"))
                .arg(value("tag-length", "Native general tag bytes: half the hash output through full length; omitted selects full tag"))
                .arg(
                    required("algorithm", "HMAC hash algorithm").value_parser([
                        "hmac-sha256",
                        "hmac-sha384",
                        "hmac-sha512",
                        "hmac-sha224",
                        "hmac-sha512-224",
                        "hmac-sha512-256",
                        "hmac-sha3-224",
                        "hmac-sha3-256",
                        "hmac-sha3-384",
                        "hmac-sha3-512",
                    ]),
                )
                .arg(required(
                    "input",
                    "Message file, at most 16 MiB; - reads stdin",
                ))
                .arg(required("output", "New raw tag file; - writes stdout")),
        )),
        auth(object(
            Command::new("verify-hmac")
                .about("Verify a native HMAC")
                .arg(flag("multipart", "Use native multipart MAC with a zeroizing input buffer; the 16 MiB limit remains"))
                .arg(value("tag-length", "Native general tag bytes: half the hash output through full length; omitted selects full tag"))
                .arg(
                    required("algorithm", "HMAC hash algorithm").value_parser([
                        "hmac-sha256",
                        "hmac-sha384",
                        "hmac-sha512",
                        "hmac-sha224",
                        "hmac-sha512-224",
                        "hmac-sha512-256",
                        "hmac-sha3-224",
                        "hmac-sha3-256",
                        "hmac-sha3-384",
                        "hmac-sha3-512",
                    ]),
                )
                .arg(required(
                    "input",
                    "Message file, at most 16 MiB; - reads stdin",
                ))
                .arg(required("tag-file", "Exact selected-length raw tag file; no stdin")),
        )),
        auth(object(
            Command::new("aes-cmac-capabilities")
                .about("Inspect native AES-CMAC support for the selected tag profile")
                .arg(value(
                    "tag-length",
                    "Native general CMAC tag bytes (8–16); omitted uses full tag",
                ))
                .arg(required("operation", "MAC direction").value_parser(["generate", "verify"])),
        )),
        auth(object(
            Command::new("mac-aes-cmac")
                .about("Generate an AES-CMAC tag on the token")
                .arg(flag("multipart", "Use native multipart MAC with a zeroizing input buffer; the 16 MiB limit remains"))
                .arg(value(
                    "tag-length",
                    "Native general CMAC tag bytes (8–16); omitted uses full tag",
                ))
                .arg(required(
                    "input",
                    "Message file, at most 16 MiB; - reads stdin",
                ))
                .arg(required("output", "New raw tag file; - writes stdout")),
        )),
        auth(object(
            Command::new("verify-aes-cmac")
                .about("Verify an AES-CMAC tag on the token")
                .arg(flag("multipart", "Use native multipart MAC with a zeroizing input buffer; the 16 MiB limit remains"))
                .arg(value(
                    "tag-length",
                    "Native general CMAC tag bytes (8–16); omitted uses full tag",
                ))
                .arg(required(
                    "input",
                    "Message file, at most 16 MiB; - reads stdin",
                ))
                .arg(required(
                    "tag-file",
                    "Raw tag file of the selected length; no stdin",
                )),
        )),
        auth(object(
            Command::new("kbkdf-capabilities")
                .about("Inspect native SP800-108 PRF choices for an explicit mode")
                .arg(value("prf", "PRF family; defaults to the existing HMAC profile").value_parser(["hmac","aes-cmac"]).default_value("hmac"))
                .arg(value("digest", "Inspect one HMAC hash; omitted retains the SHA-256/384/512 capability list").value_parser(["sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"]))
                .arg(
                    value("mode", "SP800-108 mode")
                        .value_parser(["counter", "feedback", "double-pipeline"])
                        .default_value("counter"),
                ),
        )),
        mutation(auth(named(hkdf_digest(object(
            Command::new("derive-kbkdf")
                .about("Derive one token key using explicit SP800-108 mode and PRF")
                .arg(value("prf", "PRF family; HMAC requires --digest, AES-CMAC forbids it").value_parser(["hmac","aes-cmac"]).default_value("hmac"))
                .arg(
                    value("mode", "SP800-108 mode")
                        .value_parser(["counter", "feedback", "double-pipeline"])
                        .default_value("counter"),
                )
                .arg(value(
                    "kdf-iv-file",
                    "Public feedback IV file, empty or PRF-block-length (16 bytes for AES-CMAC); no stdin",
                ))
                .arg(
                    required("kind", "Output type and permissions").value_parser([
                        "aes128",
                        "aes192",
                        "aes256",
                        "derivation-secret",
                    ]),
                )
                .arg(
                    value("length", "Derivation-secret length in bytes (1–4096)")
                        .required_if_eq("kind", "derivation-secret"),
                )
                .arg(value(
                    "kdf-label-file",
                    "Public KDF label file, at most 4096 bytes; omitted means empty",
                ))
                .arg(value(
                    "kdf-context-file",
                    "Public context file, at most 4096 bytes; omitted means empty",
                )),
        )))))
        .mut_arg("digest", |arg| arg.required(false).required_if_eq("prf","hmac").value_parser(["sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"]).help("HMAC hash; forbidden with --prf aes-cmac")),
        mutation(auth(named(hkdf_options(object(
            Command::new("derive-hkdf")
                .about("Derive a persistent nonextractable token key using HKDF")
                .arg(
                    value(
                        "salt-key",
                        "Token-held salt URI with type=secret-key; same token",
                    )
                    .conflicts_with("salt-file"),
                )
                .arg(
                    value(
                        "mode",
                        "HKDF stage; extract requires a hash-length derivation-secret output",
                    )
                    .value_parser(["extract-and-expand", "extract", "expand"])
                    .default_value("extract-and-expand"),
                ),
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
        .arg(
            value(
                "interface-version",
                "Require an exact standard interface, or negotiate automatically",
            )
            .value_parser(["auto", "2.40", "3.0", "3.1", "3.2"])
            .default_value("auto")
            .global(true),
        )
        .subcommands(commands)
}

fn montgomery_kdf_args(x448: bool) -> [clap::Arg; 4] {
    let kdf = value("kdf", "Native key derivation function").value_parser([
        "null",
        "x963-sha224",
        "x963-sha256",
        "x963-sha384",
        "x963-sha512",
        "nist-sha224",
        "nist-sha256",
        "nist-sha384",
        "nist-sha512",
    ]);
    let kind = value(
        "kind",
        if x448 {
            "Output purpose; secret is the legacy 64-byte output"
        } else {
            "Output purpose"
        },
    )
    .value_parser(if x448 {
        vec![
            "raw-secret",
            "secret",
            "derivation-secret",
            "aes128",
            "aes192",
            "aes256",
        ]
    } else {
        vec![
            "raw-secret",
            "derivation-secret",
            "aes128",
            "aes192",
            "aes256",
        ]
    });
    [
        if x448 {
            kdf.required(true)
        } else {
            kdf.default_value("null")
        },
        if x448 {
            kind.required(true)
        } else {
            kind.default_value("raw-secret")
        },
        value(
            "length",
            "Byte length (1..=4096), required only for derivation-secret",
        ),
        value(
            "shared-info-file",
            "Public context file, at most 4096 bytes; no stdin",
        ),
    ]
}
