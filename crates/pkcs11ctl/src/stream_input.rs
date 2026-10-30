// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::support::*;
use clap::ArgMatches;
use std::{fs::File, io::Read};

pub(crate) struct MultipartInput {
    file: Option<File>,
    maximum: usize,
}
impl MultipartInput {
    pub fn load(name: &str, m: &ArgMatches) -> Result<Option<Self>> {
        let maximum = match name {
            "mac-hmac" | "verify-hmac" => pkcs11_client::HMAC_MAXIMUM_MESSAGE,
            "mac-aes-cmac" | "verify-aes-cmac" => pkcs11_client::AES_CMAC_MAXIMUM_MESSAGE,
            "sign" | "verify" | "verify-token" | "sign-hash-ml-dsa" | "verify-hash-ml-dsa" => {
                64 * 1024 * 1024
            }
            _ => return Ok(None),
        };
        if !flag(m, "multipart") {
            return Ok(None);
        }
        let file = match need(m, "input")? {
            "-" => None,
            path => Some(File::open(path)?),
        };
        if let Some(file) = &file {
            let metadata = file.metadata()?;
            if metadata.is_file() && metadata.len() > maximum as u64 {
                return Err(usage("multipart input exceeds the size limit"));
            }
        }
        Ok(Some(Self { file, maximum }))
    }

    pub fn read<T>(
        &self,
        operation: impl FnOnce(&mut dyn Read) -> std::result::Result<T, pkcs11_client::Error>,
    ) -> Result<T> {
        let input: Box<dyn Read + '_> = match &self.file {
            Some(file) => Box::new(file),
            None => Box::new(std::io::stdin().lock()),
        };
        let mut reader = BoundedReader {
            input,
            remaining: self.maximum,
            exceeded: false,
        };
        let result = operation(&mut reader);
        if reader.exceeded {
            return Err(usage("multipart input exceeds the size limit"));
        }
        result.map_err(Failure::from)
    }
}

struct BoundedReader<R> {
    input: R,
    remaining: usize,
    exceeded: bool,
}
impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        // Read one byte beyond the budget to distinguish exact-length input from
        // an overrun, including stdin and files that grow after preflight.
        let length = buffer.len().min(self.remaining.saturating_add(1));
        let read = self.input.read(&mut buffer[..length])?;
        if read > self.remaining {
            self.exceeded = true;
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.remaining -= read;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_budget_requires_eof_and_overrun_is_not_delivered() {
        for (bytes, exceeded) in [(&b"abc"[..], false), (&b"abcd"[..], true)] {
            let mut reader = BoundedReader {
                input: bytes,
                remaining: 3,
                exceeded: false,
            };
            let mut buffer = [0; 3];
            assert_eq!(reader.read(&mut buffer).unwrap(), 3);
            assert_eq!(&buffer, b"abc");
            assert_eq!(reader.read(&mut []).unwrap(), 0);
            if exceeded {
                assert_eq!(
                    reader.read(&mut buffer).unwrap_err().kind(),
                    std::io::ErrorKind::InvalidData
                );
            } else {
                assert_eq!(reader.read(&mut buffer).unwrap(), 0);
            }
            assert_eq!(reader.exceeded, exceeded);
        }
    }
}
