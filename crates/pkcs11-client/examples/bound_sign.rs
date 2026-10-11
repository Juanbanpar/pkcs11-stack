// SPDX-License-Identifier: MIT OR Apache-2.0
//! Explicit certificate binding followed by verified RSA/SHA-256 signing.
mod support;

use pkcs11_client::{
    Authentication, DigestAlgorithm, Pin, Provider, SignInput, SignRequest, SignatureAlgorithm,
    SigningPolicy, token_uri,
};
use std::{io::Write, num::NonZeroUsize};

fn main() -> support::Result<()> {
    let args = support::arguments(
        5,
        "bound_sign MODULE KEY_URI CERT_URI PIN_FILE INPUT > signature.bin",
    )?;
    let token = token_uri(args[1].parse()?)?;
    let certificate_uri = args[2].parse()?;
    let pin = support::pin_file(&args[3])?;
    let message = std::fs::read(&args[4])?;
    let provider = Provider::load(&args[0])?;
    let client = provider.client(
        &token,
        NonZeroUsize::new(1).unwrap(),
        SigningPolicy::default(),
    )?;
    let authentication = || Authentication::User(Pin::Value(&pin));
    let key = client.private_key(args[1].parse()?, authentication())?;
    let certificate = client.certificate(certificate_uri, authentication())?;
    let identity = client.bind_identity(key, certificate, authentication(), None)?;
    let request = SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input: SignInput::Message(&message),
        pss: None,
    };
    let signature = client.sign_identity(&identity, &request, authentication(), None)?;
    drop(client);
    provider.finalize()?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&signature)?;
    stdout.flush()?;
    Ok(())
}
