// SPDX-License-Identifier: MIT OR Apache-2.0
use rustls::{ClientConnection, ServerConnection};

pub fn transfer(c: &mut ClientConnection, s: &mut ServerConnection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    if c.wants_write() {
        c.write_tls(&mut wire).unwrap();
        let mut remaining = wire.as_slice();
        while !remaining.is_empty() {
            assert!(s.read_tls(&mut remaining).unwrap() > 0);
            s.process_new_packets()?;
        }
    }
    wire.clear();
    if s.wants_write() {
        s.write_tls(&mut wire).unwrap();
        let mut remaining = wire.as_slice();
        while !remaining.is_empty() {
            assert!(c.read_tls(&mut remaining).unwrap() > 0);
            c.process_new_packets()?;
        }
    }
    Ok(())
}
