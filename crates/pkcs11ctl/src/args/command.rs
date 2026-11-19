// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::Command;

use super::{
    key_establishment::{hkdf_digest, hkdf_options, hybrid_options, kem_parameter},
    options::{auth, flag, key, key_family, mutation, named, object, required, token, value},
    signing::{self, context, signature, signing as signing_args},
};

pub(crate) fn command() -> Command {
    let inspect = Command::new("inspect")
        .about("Read explicit attributes of one object")
        .arg(value("attributes", "Comma-separated class,label,id,object-id,private,sign,sensitive,extractable,always-authenticate,key-type,modulus,exponent,ec-params,ec-point,subject,issuer,serial,value")
            .default_value("class,label,id"));
    let export = Command::new("export")
        .about("Export certificate/data bytes or public-key SPKI DER; no trust validation")
        .arg(
            value("key-family", "Public-key algorithm family")
                .value_parser([
                    "classical",
                    "ml-dsa",
                    "ml-kem",
                    "slh-dsa",
                    "eddsa",
                    "montgomery",
                ])
                .default_value("classical"),
        )
        .arg(required(
            "output",
            "New output file, or - for binary stdout",
        ));
    let diagnose = Command::new("diagnose")
        .about("Check bounded pool capacity, role and lease reuse")
        .arg(value("pool-size", "Number of concurrent leases, 1..=64").default_value("2"));
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
        .about("Generate persistent nonextractable signing, ECDH, ML-KEM or AES keys")
        .arg(required("kind", "Key kind").value_parser([
            "rsa",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            "aes128",
            "aes192",
            "aes256",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "ed25519",
            "ed448",
            "x25519",
            "x448",
            "p256",
            "p384",
            "p521",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "ed25519",
            "ed448",
            "hash-ml-dsa",
            "hash-slh-dsa",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
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
        .arg(value("bits", "RSA modulus size; RSA only"))
        .arg(
            value("purpose", "Required AES permissions")
                .value_parser(["encryption", "wrapping", "authentication"])
                .required_if_eq_any([("kind", "aes128"), ("kind", "aes192"), ("kind", "aes256")]),
        )
        .arg(flag(
            "always-authenticate",
            "Require per-signature context authentication",
        ));
    let import = Command::new("import")
        .about("Import public certificate DER, ML-KEM SPKI DER or data bytes")
        .arg(required("kind", "Object kind").value_parser(["cert", "data", "ml-kem", "public-key"]))
        .arg(
            value("purpose", "Public-key purpose")
                .value_parser(["verification", "encryption"])
                .default_value("verification"),
        )
        .arg(required("input", "Input file; - reads stdin"));
    let set_label = Command::new("set-label")
        .about("Relabel exactly one object")
        .arg(required("label", "New label"));
    let gcm = |name, help| {
        auth(object(Command::new(name).about(help)
        .arg(required("nonce", "Exactly 24 hex digits; encryption requires a unique nonce per key, also after errors"))
        .arg(value("aad-file", "Additional authenticated data file, at most 1 MiB; omitted means empty; no stdin"))
        .arg(required("input", "Input file or - for stdin"))
        .arg(required("output", "New output file or - for binary stdout"))))
    };
    let digest = Command::new("digest")
        .about("Digest a file or stdin on the token")
        .arg(
            required("algorithm", "Digest algorithm")
                .value_parser(["sha1", "sha224", "sha256", "sha384", "sha512"]),
        )
        .arg(flag(
            "multipart",
            "Process the input through multipart digest calls",
        ))
        .arg(required("input", "Input file; - reads stdin"))
        .arg(required(
            "output",
            "New output file, or - for binary stdout",
        ));
    let mac = Command::new("mac")
        .about("Compute a full-tag MAC with a token secret key")
        .arg(required("algorithm", "MAC algorithm").value_parser([
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "aes-cmac",
        ]))
        .arg(flag(
            "multipart",
            "Process the input through multipart MAC calls",
        ))
        .arg(required("input", "Input file; - reads stdin"))
        .arg(required(
            "output",
            "New output file, or - for binary stdout",
        ));
    let verify_mac = Command::new("verify-mac")
        .about("Verify a full-tag MAC with a token secret key")
        .arg(required("algorithm", "MAC algorithm").value_parser([
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "aes-cmac",
        ]))
        .arg(flag(
            "multipart",
            "Process the input through multipart MAC calls",
        ))
        .arg(required("input", "Input file; - reads stdin"))
        .arg(required(
            "tag",
            "Expected full-tag file; - reads stdin only if input is a file",
        ));
    let aes_cipher = |name: &'static str, help: &'static str| {
        object(
            Command::new(name)
                .about(help)
                .arg(required("mode", "AES mode").value_parser(["ecb", "cbc", "cbc-pad"]))
                .arg(value(
                    "iv",
                    "Exactly 32 hex digits for CBC/CBC-PAD; forbidden for ECB",
                ))
                .arg(flag(
                    "multipart",
                    "Process the input through multipart AES calls",
                ))
                .arg(required("input", "Input file; - reads stdin"))
                .arg(required(
                    "output",
                    "New output file, or - for binary stdout",
                )),
        )
    };
    let derive_kbkdf = Command::new("derive-kbkdf")
        .about("Derive a persistent token key with NIST SP 800-108")
        .arg(required("prf", "PRF").value_parser([
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
            "aes-cmac",
        ]))
        .arg(required("mode", "SP 800-108 mode").value_parser([
            "counter",
            "feedback",
            "double-pipeline",
        ]))
        .arg(required("kind", "Output key type").value_parser([
            "aes128",
            "aes192",
            "aes256",
            "derivation-secret",
        ]))
        .arg(value("length", "Generic derivation-secret length in bytes"))
        .arg(value(
            "kdf-label-file",
            "Public KDF label file, at most 4096 bytes",
        ))
        .arg(value(
            "kdf-context-file",
            "Public KDF context file, at most 4096 bytes",
        ))
        .arg(value("iv", "Feedback IV in hex; omitted means none"));
    let aes_cipher_capabilities = Command::new("aes-cipher-capabilities")
        .about("Inspect AES mode permissions and provider support")
        .arg(required("mode", "AES mode").value_parser(["ecb", "cbc", "cbc-pad"]))
        .arg(required("operation", "Requested direction").value_parser(["encrypt", "decrypt"]));
    let derive_montgomery = Command::new("derive-montgomery")
        .about("Derive a persistent token key from X25519/X448 agreement")
        .arg(required("curve", "Base/peer curve").value_parser(["x25519", "x448"]))
        .arg(required(
            "peer",
            "Raw RFC 7748 peer public-key file; - reads stdin",
        ))
        .arg(required("kdf", "ECDH KDF").value_parser([
            "null",
            "x963-sha256",
            "x963-sha384",
            "x963-sha512",
            "sp800-56a-sha256",
            "sp800-56a-sha384",
            "sp800-56a-sha512",
        ]))
        .arg(value(
            "shared-info-file",
            "Public KDF context file, at most 4096 bytes",
        ))
        .arg(required("kind", "Output key type").value_parser([
            "aes128",
            "aes192",
            "aes256",
            "derivation-secret",
        ]))
        .arg(value("length", "Generic derivation-secret length in bytes"));
    let function_support = Command::new("function-support")
        .about("Report which standard functions the selected interface provides");
    let commands = [
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
        auth(object(inspect)),
        auth(object(export)),
        auth(object(key_family(
            Command::new("certificate").about("Parse a supported certificate through client"),
        ))),
        auth(key(key_family(
            Command::new("capabilities").about("Inspect selected signing-key capabilities"),
        ))),
        auth(signing_args(key(
            Command::new("plan").about("Plan one signing request without signing")
        ))),
        context(auth(key(key_family(signing::bind())))),
        context(auth(signing_args(key(signing::sign())))),
        auth(signature(signing::verify())),
        auth(token(random)),
        gcm(
            "encrypt-aes-gcm",
            "Encrypt up to 16 MiB. Output is ciphertext followed by a 16-byte tag",
        ),
        gcm(
            "decrypt-aes-gcm",
            "Authenticate/decrypt AES-GCM once; no output before authentication and checked closure",
        ),
        auth(object(
            Command::new("aes-gcm-capabilities")
                .about("Inspect current AES-GCM key permissions and provider support")
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
        auth(token(digest)),
        auth(object(mac)),
        auth(object(verify_mac)),
        auth(aes_cipher("encrypt-aes", "Encrypt with a token AES key")),
        auth(aes_cipher("decrypt-aes", "Decrypt with a token AES key")),
        mutation(auth(named(object(derive_kbkdf)))),
        mutation(auth(named(object(derive_montgomery)))),
        auth(object(aes_cipher_capabilities)),
        token(function_support),
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
