//! Utilities for testing TLS code.
use openssl::ssl::SslContextBuilder;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509;

pub mod custom_client;
pub mod custom_server;
pub mod x509_certificates;

/// Sets the peer verification cert store for the `SslContext` to a store
/// containing `certs`.
///
/// # Panics
/// * if the store cannot be set for the `SSLContext`.
pub fn set_peer_verification_cert_store(certs: Vec<X509>, builder: &mut SslContextBuilder) {
    // `SslConnector::builder` calls `set_default_verify_paths`, automatically
    // adding many CA certificates to the context's `cert_store`. Thus, we overwrite
    // the cert_store with an empty one:
    set_empty_cert_store(builder);
    let store = cert_store(certs);
    builder
        .set_verify_cert_store(store)
        .expect("Failed to set the verify_cert_store.");
}

fn set_empty_cert_store(builder: &mut SslContextBuilder) {
    let empty_cert_store = X509StoreBuilder::new()
        .expect("Failed to init X509 store builder.")
        .build();
    builder.set_cert_store(empty_cert_store);
}

fn cert_store(certs: Vec<X509>) -> X509Store {
    let mut cert_store_builder =
        X509StoreBuilder::new().expect("Failed to init X509 store builder.");
    for cert in certs {
        cert_store_builder
            .add_cert(cert.clone())
            .expect("Failed to add the certificate to the cert_store.");
    }
    cert_store_builder.build()
}
