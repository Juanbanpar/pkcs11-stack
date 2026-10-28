// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::io::Read;

// Keep input and I/O diagnostics out of errors. Incomplete guards are discarded
// by the caller on any read/update failure; Interrupted does not end the operation.
pub(crate) fn read_chunks(
    reader: &mut impl Read,
    mut update: impl FnMut(&[u8]) -> Result<(), Error>,
    input_error: Error,
) -> Result<(), Error> {
    let mut buffer = SecretBox::new(Box::new(vec![0; 64 * 1024]));
    loop {
        let length = match reader.read(buffer.expose_secret_mut()) {
            Ok(0) => return Ok(()),
            Ok(length) => length,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(input_error),
        };
        update(&buffer.expose_secret()[..length])?;
    }
}
