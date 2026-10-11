// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_runtime::{Module, PrivateKeyRef, SessionMode, SessionPool, SigningPolicy};
use pkcs11_rustls_adapter::{Credential, Credentials, PinInput};
use rustls::{RootCertStore, crypto::CryptoProvider};
use rustls_pki_types::CertificateDer;
use secrecy::SecretString;
use std::{io::Read, num::NonZeroUsize, sync::Arc};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn arguments(counts: &[usize], usage: &'static str) -> Result<Vec<String>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{usage}");
        std::process::exit(0);
    }
    if !counts.contains(&args.len()) {
        return Err(usage.into());
    }
    Ok(args)
}

fn certificate(path: &str) -> Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

pub fn roots(path: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(path)?)?;
    Ok(roots)
}

fn pin_file(path: &str) -> Result<SecretString> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("PIN file exceeds 65536 bytes".into());
    }
    let text = std::str::from_utf8(&bytes)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = if bytes.ends_with(b"\r\n") {
        text.strip_suffix('\r').unwrap_or(text)
    } else {
        text
    };
    Ok(SecretString::from(text))
}

pub fn credential(
    module: Arc<Module>,
    token: &str,
    key: &str,
    leaf: &str,
    issuer: &str,
    pin_path: &str,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<Credential>> {
    let pool = Arc::new(SessionPool::new_owned(
        module,
        &token.parse()?,
        SessionMode::ReadOnly,
        NonZeroUsize::new(2).unwrap(),
    )?);
    let pin_path = pin_path.to_owned();
    let source = Arc::new(move || {
        let pin = pin_file(&pin_path)
            .map_err(|_| pkcs11_rustls_adapter::Error::CredentialsUnavailable)?;
        Ok(Credentials {
            user: Some(PinInput::Value(pin)),
            context: None,
        })
    });
    Ok(Arc::new(Credential::load(
        pool,
        PrivateKeyRef::new(key.parse()?)?,
        vec![certificate(leaf)?, certificate(issuer)?],
        SigningPolicy::default(),
        source,
        provider,
    )?))
}

pub fn finalize(module: Arc<Module>) -> Result<()> {
    Arc::try_unwrap(module)
        .map_err(|_| "module still has live consumers")?
        .finalize()?;
    Ok(())
}
