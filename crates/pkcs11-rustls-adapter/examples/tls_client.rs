// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verify a TLS server and optionally authenticate with a token-backed client key.
mod support;

use pkcs11_runtime::Module;
use pkcs11_rustls_adapter::ClientResolver;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

fn main() -> support::Result<()> {
    let args = support::arguments(
        &[3, 9],
        "tls_client ADDRESS DNS_NAME SERVER_CA_DER [MODULE TOKEN_URI KEY_URI LEAF_DER ISSUER_DER PIN_FILE]",
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let module = args.get(3).map(Module::load).transpose()?.map(Arc::new);
    {
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(support::roots(&args[2])?);
        let config = if let Some(module) = &module {
            let credential = support::credential(
                module.clone(),
                &args[4],
                &args[5],
                &args[6],
                &args[7],
                &args[8],
                provider,
            )?;
            builder.with_client_cert_resolver(Arc::new(ClientResolver::new(vec![credential])))
        } else {
            builder.with_no_client_auth()
        };
        let timeout = Duration::from_secs(10);
        let socket = TcpStream::connect_timeout(&args[0].parse()?, timeout)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        let connection =
            ClientConnection::new(Arc::new(config), ServerName::try_from(args[1].clone())?)?;
        let mut stream = StreamOwned::new(connection, socket);
        stream.write_all(b"ping\n")?;
        stream.flush()?;
        let mut response = [0; 5];
        stream.read_exact(&mut response)?;
        if &response != b"pong\n" {
            return Err("unexpected application response".into());
        }
        stream.conn.send_close_notify();
        stream.flush()?;
    }
    if let Some(module) = module {
        support::finalize(module)?;
    }
    println!("TLS exchange complete");
    Ok(())
}
