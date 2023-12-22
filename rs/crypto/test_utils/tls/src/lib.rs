use tokio_rustls::rustls;

pub mod custom_client;
pub mod custom_server;
pub mod registry;
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
            CipherSuite::TLS13_AES_256_GCM_SHA384 => rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_AES_128_GCM_SHA256 => rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
                rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
            CipherSuite::TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            CipherSuite::TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
        }
    }
}
