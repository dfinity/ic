use anyhow::Context;
use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapAny};
use base64ct::LineEnding;
use der::EncodePem;
use rcgen::{
    generate_simple_self_signed, Certificate, CertificateParams, CustomExtension, Error, KeyPair,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer::Pkcs8;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use x509_parser::certificate;
use x509_parser::der_parser::oid;

#[derive(Debug)]
pub(super) struct ResolverWithAttestation {
    delegate: Arc<dyn ResolvesServerCert>,
    refresher: Arc<AttestationTokenRefresher>,
}

#[derive(Debug)]
struct AttestationTokenRefresher {
    tls_cert_with_attestation: ArcSwap<CertifiedKey>,
    cancellation_token: CancellationToken,
}

impl Drop for ResolverWithAttestation {
    fn drop(&mut self) {
        self.refresher.cancellation_token.cancel();
    }
}

impl ResolverWithAttestation {
    pub(crate) async fn new(delegate: Arc<dyn ResolvesServerCert>) -> Result<Self> {
        let refresher = Arc::new(AttestationTokenRefresher::new().await?);
        let refresher_clone = refresher.clone();
        tokio::task::spawn(async move {
            refresher_clone
                .refresh_attestation_token_periodically()
                .await
        });

        Ok(Self {
            delegate,
            refresher,
        })
    }
}

impl AttestationTokenRefresher {
    pub(crate) async fn new() -> Result<Self> {
        Ok(Self {
            tls_cert_with_attestation: Self::new_tls_key_with_attestation_token().await?.into(),
            cancellation_token: Default::default(),
        })
    }

    async fn refresh_attestation_token_periodically(&self) {
        // TODO: Use backoff
        const SLEEP_ON_ERROR: Duration = Duration::from_secs(30);
        const SLEEP_ON_SUCCESS: Duration = Duration::from_secs(3600 * 24);
        while !self.cancellation_token.is_cancelled() {
            match Self::new_tls_key_with_attestation_token().await {
                Ok(new_tls_key_with_attestation) => {
                    self.tls_cert_with_attestation
                        .store(new_tls_key_with_attestation);
                    // TODO: sleep until expiration
                    tokio::time::sleep(SLEEP_ON_SUCCESS).await;
                }
                Err(err) => {
                    warn!(
                        "Could not renew attestation token: {}. Will retry after {}s.",
                        err,
                        SLEEP_ON_ERROR.as_secs()
                    );
                    tokio::time::sleep(SLEEP_ON_ERROR).await;
                }
            }
        }
    }

    async fn new_tls_key_with_attestation_token() -> Result<Arc<CertifiedKey>> {
        let key_pair = KeyPair::generate()?;
        let attestation_token_pem =
            attestee::fetch_tls_certificate(key_pair.public_key_pem(), &mut vec![].as_slice())
                .await
                .context("Could not fetch tls certificate")?;
        println!("PEM:");
        println!("{}", attestation_token_pem);

        let certificate_chain = CertificateDer::pem_slice_iter(attestation_token_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Certificate chain error")?;
        println!("Certificates in chain: {}", certificate_chain.len());
        let key =
            rustls::crypto::ring::sign::any_ecdsa_type(&Pkcs8(key_pair.serialized_der().into()))?;
        Ok(Arc::new(CertifiedKey::new(certificate_chain, key)))
    }

    // async fn generate_tls_cert() -> Result<rcgen::CertifiedKey> {
    //     let key_pair = KeyPair::generate()?;
    //     println!("{}", key_pair.public_key_pem());
    //     let attestation_token_pem =
    //         attestee::fetch_tls_certificate(key_pair.public_key_pem(), &mut vec![].as_slice())
    //             .await
    //             .context("Could not fetch attestation token")?;
    //             // .to_der()?;
    //     println!("Fetches attestation token: {:x?}", attestation_token_pem);
    //     // let mut params = CertificateParams::new(vec![])?;
    //     // params
    //     //     .custom_extensions
    //     //     .push(CustomExtension::from_oid_content(
    //     //         &[1, 3, 6, 1, 4, 1, 56387, 42, 1],
    //     //         attestation_token_der.0,
    //     //     ));
    //     // let cert = params.self_signed(&key_pair)?;
    //
    //     Ok(rcgen::CertifiedKey { cert: Certificate, key_pair })
    // }
}

impl ResolvesServerCert for ResolverWithAttestation {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if true
            || client_hello
                .alpn()
                .is_some_and(|mut alpn| alpn.any(|alpn| alpn == b"ic-attest"))
        {
            let tls_cert = self.refresher.tls_cert_with_attestation.load_full();

            Some(tls_cert)
        } else {
            self.delegate.resolve(client_hello)
        }
    }
}
