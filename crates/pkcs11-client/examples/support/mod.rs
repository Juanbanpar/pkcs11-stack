// SPDX-License-Identifier: MIT OR Apache-2.0
use secrecy::SecretString;
use std::io::Read;
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn arguments(count: usize, usage: &'static str) -> Result<Vec<String>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{usage}");
        std::process::exit(0);
    }
    if args.len() != count {
        return Err(usage.into());
    }
    Ok(args)
}

// This is an application secret source, not library prompting or PIN caching.
pub fn pin_file(path: &str) -> Result<SecretString> {
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
