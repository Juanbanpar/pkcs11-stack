// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::ArgMatches;
use pkcs11_client::{Authentication, Pin};
use pkcs11_locator::Pkcs11Uri;
use secrecy::SecretString;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

pub(crate) struct Failure {
    pub code: u8,
    pub kind: &'static str,
    pub message: String,
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;
pub(crate) fn finish<T>(
    outcome: Result<T>,
    cleanup: std::result::Result<(), pkcs11_client::Error>,
    phase: &'static str,
) -> Result<T> {
    if let Err(error) = cleanup {
        let mut message = format!("{phase} failed: {error}");
        if let Err(primary) = outcome {
            message.push_str(&format!("; operation failed: {}", primary.message));
        }
        message.push_str("; effects may have occurred; no retry was made");
        return Err(Failure {
            code: 5,
            kind: "runtime",
            message,
        });
    }
    outcome
}

pub(crate) fn usage(message: &str) -> Failure {
    Failure {
        code: 2,
        kind: "input",
        message: message.into(),
    }
}
impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self {
            code: 6,
            kind: "io",
            message: e.to_string(),
        }
    }
}
impl From<pkcs11_locator::Error> for Failure {
    fn from(_: pkcs11_locator::Error) -> Self {
        usage("invalid PKCS#11 URI")
    }
}
impl From<pkcs11_client::Error> for Failure {
    fn from(e: pkcs11_client::Error) -> Self {
        use pkcs11_client::ErrorKind;
        let (code, kind) = match e.kind() {
            ErrorKind::Input => (2, "input"),
            ErrorKind::Selection => (3, "selection"),
            ErrorKind::Policy => (4, "policy"),
            ErrorKind::Runtime => (5, "runtime"),
            _ => (4, "client"),
        };
        Self {
            code,
            kind,
            message: e.to_string(),
        }
    }
}
pub(crate) fn get<'a>(m: &'a ArgMatches, name: &str) -> Option<&'a str> {
    m.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub(crate) fn need<'a>(m: &'a ArgMatches, name: &str) -> Result<&'a str> {
    get(m, name).ok_or_else(|| usage("missing required argument"))
}
pub(crate) fn flag(m: &ArgMatches, name: &str) -> bool {
    m.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
pub(crate) fn number(m: &ArgMatches, name: &str) -> Result<usize> {
    need(m, name)?
        .parse()
        .map_err(|_| usage("invalid unsigned number"))
}
pub(crate) fn uri(m: &ArgMatches, name: &str) -> Result<Pkcs11Uri> {
    Ok(need(m, name)?.parse()?)
}
pub(crate) fn token_uri(uri: Pkcs11Uri) -> Result<Pkcs11Uri> {
    Ok(pkcs11_client::token_uri(uri)?)
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 || !value.is_ascii() {
        return Err(usage("ID must be nonempty even-length hexadecimal"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|c| {
            std::str::from_utf8(c)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| usage("invalid hexadecimal ID"))
        })
        .collect()
}
pub(crate) fn input(path: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin().read_to_end(&mut bytes)?;
    } else {
        bytes = std::fs::read(path)?;
    }
    Ok(bytes)
}
pub(crate) fn bounded_input(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let reader: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(path)?)
    };
    let mut bytes = Vec::new();
    reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(usage("input exceeds this operation's size limit"));
    }
    Ok(bytes)
}
fn pin_file(path: &str) -> Result<SecretString> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(usage("PIN file too large"));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| usage("PIN file is not UTF-8"))?;
    Ok(SecretString::from(value))
}
pub(crate) enum Credential {
    None,
    Value(SecretString),
    Protected,
}
impl Credential {
    pub fn load(m: &ArgMatches, file: &str, protected: &str) -> Result<Self> {
        if let Some(path) = get(m, file) {
            Ok(Self::Value(pin_file(path)?))
        } else if flag(m, protected) {
            Ok(Self::Protected)
        } else {
            Ok(Self::None)
        }
    }
    pub fn host_file(m: &ArgMatches, name: &str) -> Result<SecretString> {
        pin_file(need(m, name)?)
    }
    pub fn pin(&self) -> Option<Pin<'_>> {
        match self {
            Self::None => None,
            Self::Value(v) => Some(Pin::Value(v)),
            Self::Protected => Some(Pin::ProtectedPath),
        }
    }
    pub fn auth(&self, so: bool) -> Authentication<'_> {
        match self.pin() {
            None => Authentication::None,
            Some(p) if so => Authentication::SecurityOfficer(p),
            Some(p) => Authentication::User(p),
        }
    }
    pub fn host(&self) -> Result<&SecretString> {
        match self {
            Self::Value(v) => Ok(v),
            _ => Err(usage("this operation requires a host PIN file")),
        }
    }
}
// Reserve a new output before executing a token operation. Remove incomplete files.
pub(crate) struct BinaryOutput {
    file: Option<File>,
    path: Option<PathBuf>,
    committed: bool,
}
impl BinaryOutput {
    pub fn open(path: &str) -> Result<Self> {
        if path == "-" {
            return Ok(Self {
                file: None,
                path: None,
                committed: false,
            });
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(Self {
            file: Some(options.open(path)?),
            path: Some(path.into()),
            committed: false,
        })
    }
    pub fn write(mut self, bytes: &[u8]) -> Result<()> {
        if let Some(file) = &mut self.file {
            file.write_all(bytes)?;
            file.flush()?;
        } else {
            let mut out = std::io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()?;
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for BinaryOutput {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            if let Some(path) = &self.path {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
pub(crate) fn emit(command: &str, result: Value, json_output: bool) -> Result<()> {
    let value = if json_output {
        json!({"schema_version":1,"command":command,"result":result})
    } else {
        result
    };
    let mut out = std::io::stdout().lock();
    if json_output {
        writeln!(out, "{value}")?;
    } else {
        render(&mut out, "", &value)?;
    }
    Ok(())
}
fn render(out: &mut impl Write, prefix: &str, value: &Value) -> std::io::Result<()> {
    match value {
        Value::Object(map) => {
            for (name, value) in map {
                render(out, &format!("{prefix}{name}: "), value)?;
            }
        }
        Value::Array(values) => {
            for (i, value) in values.iter().enumerate() {
                render(out, &format!("{prefix}[{i}] "), value)?;
            }
        }
        _ => writeln!(out, "{prefix}{value}")?,
    }
    Ok(())
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn cleanup_failure_takes_runtime_precedence_and_retains_both_errors() {
        let result = finish::<()>(
            Err(usage("invalid operation")),
            Err(pkcs11_client::Error::ProviderInUse),
            "session closure",
        );
        let error = result.expect_err("cleanup error");
        assert_eq!(error.code, 5);
        assert_eq!(error.kind, "runtime");
        assert!(error.message.contains("session closure failed"));
        assert!(
            error
                .message
                .contains("provider still has live owned consumers")
        );
        assert!(error.message.contains("invalid operation"));
        assert!(error.message.contains("no retry"));
    }

    #[test]
    fn cleanup_failure_never_releases_successful_output() {
        assert!(
            finish(
                Ok(vec![1, 2, 3]),
                Err(pkcs11_client::Error::ProviderInUse),
                "module finalization"
            )
            .is_err()
        );
        assert_eq!(finish(Ok(42), Ok(()), "session closure").ok(), Some(42));
        let error =
            finish::<()>(Err(usage("invalid operation")), Ok(()), "session closure").unwrap_err();
        assert_eq!(error.code, 2);
    }
}
