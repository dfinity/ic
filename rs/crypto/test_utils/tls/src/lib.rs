use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_interfaces::crypto::KeyManager;
use ic_registry_client_fake::FakeRegistryClient;
use ic_types::NodeId;
use std::sync::Arc;

pub mod custom_client;
pub mod custom_server;
pub mod registry;
pub mod test_client;
pub mod test_server;
pub mod x509_certificates;

#[derive(Clone)]
pub enum TlsVersion {
    TLS1_2,
    TLS1_3,
}

impl From<&TlsVersion> for &rustls::SupportedProtocolVersion {
    fn from(tls_version: &TlsVersion) -> Self {
        match tls_version {
            TlsVersion::TLS1_2 => &rustls::version::TLS12,
            TlsVersion::TLS1_3 => &rustls::version::TLS13,
        }
    }
}

#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

impl From<&CipherSuite> for rustls::SupportedCipherSuite {
    fn from(cipher_suite: &CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::TLS13_AES_256_GCM_SHA384 => {
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
            }
            CipherSuite::TLS13_AES_128_GCM_SHA256 => {
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            }
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
            CipherSuite::TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            CipherSuite::TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
        }
    }
}

pub fn temp_crypto_component_with_tls_keys(
    registry: Arc<FakeRegistryClient>,
    node_id: NodeId,
) -> (TempCryptoComponent, TlsPublicKeyCert) {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(registry)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .with_remote_vault()
        .build();

    let tls_certificate = temp_crypto
        .current_node_public_keys()
        .expect("Failed to retrieve node public keys")
        .tls_certificate
        .expect("missing tls_certificate");
    let tls_pubkey = TlsPublicKeyCert::new_from_der(tls_certificate.certificate_der)
        .expect("failed to create X509 cert from DER");
    (temp_crypto, tls_pubkey)
}
