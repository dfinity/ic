use ic_agent::export::reqwest;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        VerifierBuilderError, WebPkiServerVerifier,
    },
    pki_types::{CertificateDer as RustlsCertificate, UnixTime},
};
use std::sync::Arc;
use url::Url;

/// Represents a URL, with a TLS certificate in case the latter is self-signed and must explicitly
/// be trusted.
pub(crate) enum UrlAndMaybeCert<'a> {
    WithoutCert(Url),
    WithCert(Url, RustlsCertificate<'a>),
}

/// A custom server certificate verifier that checks if the remote certificate matches a specific
/// expected certificate. If it does not match, it falls back to the default WebPkiServerVerifier,
/// which verifies the certificate using the standard local root store.
#[derive(Debug)]
struct ExactCertWithFallbackVerifier<'a> {
    expected_cert: RustlsCertificate<'a>,
    fallback: Arc<WebPkiServerVerifier>,
}

impl<'a> ExactCertWithFallbackVerifier<'a> {
    /// Default root CA store, following the logic inside
    /// reqwest::async_impl::client::ClientBuilder::build()
    /// https://github.com/seanmonstar/reqwest/blob/master/src/async_impl/client.rs
    fn default_root_cert_store() -> rustls::RootCertStore {
        let mut root_cert_store = rustls::RootCertStore::empty();

        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let native_certs = rustls_native_certs::load_native_certs().certs;
        root_cert_store.add_parsable_certificates(native_certs);

        root_cert_store
    }

    fn new(expected_cert: RustlsCertificate<'a>) -> Result<Self, VerifierBuilderError> {
        let fallback =
            WebPkiServerVerifier::builder(Arc::new(Self::default_root_cert_store())).build()?;

        Ok(Self {
            expected_cert,
            fallback,
        })
    }
}

impl ServerCertVerifier for ExactCertWithFallbackVerifier<'_> {
    fn verify_server_cert(
        &self,
        end_entity: &RustlsCertificate,
        intermediates: &[RustlsCertificate],
        server_name: &rustls::pki_types::ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Check if the received certificate matches the expected one
        if end_entity == &self.expected_cert {
            return Ok(ServerCertVerified::assertion());
        }

        // If it does not, fall back to default behaviour
        self.fallback
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &RustlsCertificate<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.fallback.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &RustlsCertificate<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.fallback.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.fallback.supported_verify_schemes()
    }
}

pub(crate) fn get_client_for_self_signed_cert(
    cert: RustlsCertificate,
) -> Result<reqwest::Client, String> {
    let verifier =
        ExactCertWithFallbackVerifier::new(cert.into_owned()).map_err(|e| e.to_string())?;

    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    reqwest::ClientBuilder::new()
        .use_preconfigured_tls(rustls_config)
        .build()
        .map_err(|e| e.to_string())
}
