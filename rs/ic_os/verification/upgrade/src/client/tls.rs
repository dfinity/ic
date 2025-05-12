use futures_util::FutureExt;
use hyper::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::client::legacy::connect::HttpConnector;
use ic_os_upgrade::tls::shared_key_for_attestation;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use tonic::codegen::Service;

/// Custom TLS connector that fills tls_shared_key_for_attestation upon connection.
#[derive(Clone)]
pub(crate) struct TlsConnector {
    pub tls_shared_key_for_attestation: Arc<Mutex<[u8; 32]>>,
}

impl Service<Uri> for TlsConnector {
    type Response = <HttpsConnector<HttpConnector> as Service<Uri>>::Response;
    type Error = <HttpsConnector<HttpConnector> as Service<Uri>>::Error;
    type Future = <HttpsConnector<HttpConnector> as Service<Uri>>::Future;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let mut connector = HttpsConnectorBuilder::new()
            .with_tls_config(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DangerAcceptInvalidCerts))
                    .with_no_client_auth(),
            )
            .https_or_http()
            .enable_http2()
            .build();

        let tls_shared_key_for_attestation = self.tls_shared_key_for_attestation.clone();
        let mut parts = req.into_parts();
        parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
        Box::pin(
            connector
                .call(Uri::try_from(parts).expect("Could not create Uri"))
                .map(move |stream| match stream {
                    Ok(MaybeHttpsStream::Https(ref inner)) => {
                        *tls_shared_key_for_attestation.lock().unwrap().deref_mut() =
                            shared_key_for_attestation(&inner.inner().get_ref().1);
                        stream
                    }
                    Ok(_) => unreachable!("Expected Https stream"),
                    err => err,
                }),
        )
    }
}

#[derive(Debug)]
pub(crate) struct DangerAcceptInvalidCerts;

impl ServerCertVerifier for DangerAcceptInvalidCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
