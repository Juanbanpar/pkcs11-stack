// SPDX-License-Identifier: MIT OR Apache-2.0
//! One TLS 1.3 connection on loopback, optionally requiring a client certificate.
mod support;

use pkcs11_runtime::Module;
use pkcs11_rustls_adapter::{ServerResolver, server_config_builder};
use rustls::{ServerConnection, StreamOwned, server::WebPkiClientVerifier};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    time::Duration,
};

fn main() -> support::Result<()> {
    let args = support::arguments(
        &[8, 9],
        "tls_server MODULE TOKEN_URI KEY_URI LEAF_DER ISSUER_DER PIN_FILE DNS_NAME ADDRESS_FILE [CLIENT_CA_DER]",
    )?;
    // This application chooses ring explicitly. The adapter does not select it.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let module = Arc::new(Module::load(&args[0])?);
    {
        let credential = support::credential(
            module.clone(),
            &args[1],
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            provider.clone(),
        )?;
        let resolver = Arc::new(ServerResolver::new(
            vec![(args[6].clone(), credential)],
            None,
        )?);
        let builder = server_config_builder(provider.clone(), &[&rustls::version::TLS13])?;
        let config = if let Some(ca) = args.get(8) {
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(support::roots(ca)?),
                provider,
            )
            .build()?;
            builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(resolver)
        } else {
            builder.with_no_client_auth().with_cert_resolver(resolver)
        };
        let listener = TcpListener::bind("127.0.0.1:0")?;
        // The address file is a readiness signal for the caller, never overwritten.
        let mut address = std::fs::File::create_new(&args[7])?;
        writeln!(address, "{}", listener.local_addr()?)?;
        drop(address);
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut stream = StreamOwned::new(ServerConnection::new(Arc::new(config))?, socket);
        let mut request = [0; 5];
        stream.read_exact(&mut request)?;
        if &request != b"ping\n" {
            return Err("unexpected application request".into());
        }
        stream.write_all(b"pong\n")?;
        stream.conn.send_close_notify();
        stream.flush()?;
    }
    support::finalize(module)?;
    println!("TLS exchange complete");
    Ok(())
}
