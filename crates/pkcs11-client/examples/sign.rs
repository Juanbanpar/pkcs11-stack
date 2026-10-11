// SPDX-License-Identifier: MIT OR Apache-2.0
//! RSA PKCS#1 v1.5 / SHA-256 signing through the client facade.
mod support;

use pkcs11_client::{
    Authentication, DigestAlgorithm, Pin, Provider, SignInput, SignRequest, SignatureAlgorithm,
    SigningPolicy, token_uri,
};
use std::{io::Write, num::NonZeroUsize};

fn main() -> support::Result<()> {
    let args = support::arguments(4, "sign MODULE KEY_URI PIN_FILE INPUT > signature.bin")?;
    let token = token_uri(args[1].parse()?)?;
    let pin = support::pin_file(&args[2])?;
    let message = std::fs::read(&args[3])?;
    let provider = Provider::load(&args[0])?;
    let client = provider.client(
        &token,
        NonZeroUsize::new(1).unwrap(),
        SigningPolicy::default(),
    )?;
    let authentication = || Authentication::User(Pin::Value(&pin));
    let key = client.private_key(args[1].parse()?, authentication())?;
    let request = SignRequest {
        algorithm: SignatureAlgorithm::RsaPkcs1,
        digest: DigestAlgorithm::Sha256,
        input: SignInput::Message(&message),
        pss: None,
    };
    let signature = client.sign(&key, &request, authentication(), None)?;
    drop(client);
    provider.finalize()?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&signature)?;
    stdout.flush()?;
    Ok(())
}
