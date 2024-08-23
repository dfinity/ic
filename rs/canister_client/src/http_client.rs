//! The hyper based HTTP client
use futures_util::{
    future::{Either as EitherFut, Map, Ready},
    FutureExt,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header::CONTENT_TYPE, Method, StatusCode, Uri as HyperUri};
use hyper_rustls::{HttpsConnector as HyperTlsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        connect::{
            dns::{self, GaiResolver},
            HttpConnector as HyperConnector,
        },
        Client as HyperClient, ResponseFuture as HyperFuture,
    },
    rt::TokioExecutor,
};
use itertools::Either;
use serde_cbor::Value;
use std::sync::Arc;
use std::{
    borrow::Cow,
    collections::HashMap,
    io,
    iter::{once, Once},
    net::SocketAddr,
    task::{Context, Poll},
    time::Duration,
};
use tower::Service;
use url::Url;

#[derive(Clone)]
pub struct HttpClientConfig {
    pub pool_idle_timeout: Option<Duration>,
    pub pool_max_idle_per_host: usize,
    pub http2_only: bool,
    pub overrides: HashMap<String, Either<SocketAddr, dns::Name>>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_idle_timeout: Some(Duration::from_secs(600)),
            pool_max_idle_per_host: 1,
            http2_only: true,
            overrides: HashMap::new(),
        }
    }
}

/// An HTTP Client to communicate with a replica.
#[derive(Clone)]
pub struct HttpClient {
    hyper: HyperClient<HyperTlsConnector<HyperConnector<DnsResolverWithOverrides>>, Full<Bytes>>,
}

#[derive(Clone)]
pub(crate) struct DnsResolverWithOverrides {
    dns_resolver: GaiResolver,
    overrides: HashMap<String, Either<SocketAddr, dns::Name>>,
}

impl DnsResolverWithOverrides {
    fn new(overrides: HashMap<String, Either<SocketAddr, dns::Name>>) -> Self {
        DnsResolverWithOverrides {
            dns_resolver: GaiResolver::new(),
            overrides,
        }
    }
}

impl Service<dns::Name> for DnsResolverWithOverrides {
    type Response = Either<dns::GaiAddrs, Once<SocketAddr>>;
    type Error = io::Error;
    type Future = EitherFut<
        Map<
            dns::GaiFuture,
            fn(Result<dns::GaiAddrs, io::Error>) -> Result<Self::Response, io::Error>,
        >,
        Ready<Result<Self::Response, io::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.dns_resolver.poll_ready(cx)
    }

    fn call(&mut self, name: dns::Name) -> Self::Future {
        const MAX_DEPTH: usize = 128;
        let mut name: Cow<dns::Name> = Cow::Owned(name);
        for _ in 0..MAX_DEPTH {
            match self.overrides.get(name.as_str()) {
                Some(Either::Left(dest)) => {
                    let fut = futures_util::future::ready(Ok(Either::Right(once(dest.to_owned()))));
                    return EitherFut::Right(fut);
                }
                Some(Either::Right(new_name)) => name = Cow::Borrowed(new_name),
                None => {
                    let resolver_fut = self.dns_resolver.call(name.into_owned());
                    fn map(
                        v: Result<dns::GaiAddrs, io::Error>,
                    ) -> Result<Either<dns::GaiAddrs, Once<SocketAddr>>, io::Error>
                    {
                        v.map(Either::Left)
                    }
                    return EitherFut::Left(resolver_fut.map(map));
                }
            }
        }
        EitherFut::Right(futures_util::future::ready(Err(io::Error::new(
            io::ErrorKind::Other,
            "unable to resolve dns query",
        ))))
    }
}

#[derive(Debug)]
struct DangerAcceptInvalidCerts {}
impl rustls::client::danger::ServerCertVerifier for DangerAcceptInvalidCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

impl HttpClient {
    pub fn new_with_config(config: HttpClientConfig) -> Self {
        let mut http_connector =
            HyperConnector::new_with_resolver(DnsResolverWithOverrides::new(config.overrides));
        http_connector.enforce_http(false);

        let mut rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerAcceptInvalidCerts {}))
            .with_no_client_auth();
        rustls_config.enable_sni = false;
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(rustls_config)
            .https_or_http();
        let https_connector = if config.http2_only {
            https_connector.enable_http2()
        } else {
            https_connector.enable_http1().enable_http2()
        };
        let https_connector = https_connector.wrap_connector(http_connector);

        let hyper = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .http2_only(config.http2_only)
            .build::<_, Full<Bytes>>(https_connector);

        Self { hyper }
    }

    pub fn new() -> Self {
        Self::new_with_config(HttpClientConfig::default())
    }

    fn build_uri(&self, url: &Url, end_point: &str) -> Result<HyperUri, String> {
        let url = url.join(end_point).map_err(|e| {
            format!(
                "HttpClient: Failed to create URI for {}: {:?}",
                end_point, e
            )
        })?;

        url.as_str()
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse {:?}: {:?}", url, e))
    }

    fn build_post_request(&self, uri: HyperUri, http_body: Vec<u8>) -> Result<HyperFuture, String> {
        let req = hyper::Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .header(CONTENT_TYPE, "application/cbor")
            .body(Full::new(Bytes::from(http_body)))
            .map_err(|e| {
                format!(
                    "HttpClient: Failed to create POST request for {:?}: {:?}",
                    uri, e
                )
            })?;
        Ok(self.hyper.request(req))
    }

    async fn wait_for_one_http_request(
        uri: HyperUri,
        response_future: HyperFuture,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let result = tokio::time::timeout_at(deadline, response_future)
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?;
        let response = result.map_err(|e| format!("Request failed for {:?}: {:?}", uri, e))?;
        let status = response.status();
        let parsed_body = tokio::time::timeout_at(deadline, response.collect())
            .await
            .map_err(|e| {
                format!(
                    "HttpClient: Request to {:?} timed out while waiting for body: {:?}. Returned status {:?}.",
                    uri, e, status.canonical_reason().unwrap_or("empty status"),
                )
            })?
            .map(|collected| collected.to_bytes().to_vec())
            .map_err(|e| {
                format!(
                    "HttpClient: Request to {:?} failed to get bytes: {:?}. Returned status: {:?}.",
                    uri, e, status.canonical_reason().unwrap_or("empty status"),
                )
            })?;

        let is_update_call = uri.path().ends_with("/call");

        // update calls with a response code of 200 indicates an error occurred.
        if !status.is_success() || (is_update_call && status == StatusCode::OK) {
            let readable_response = if is_update_call {
                format!("{:?}", serde_cbor::from_slice::<Value>(&parsed_body))
            } else {
                format!("{:?}", &std::str::from_utf8(&parsed_body))
            };

            return Err(format!(
                "HTTP Client: Request to {:?} failed with {:?}, {:?}",
                uri,
                status.canonical_reason().unwrap_or("empty status"),
                readable_response,
            ));
        }
        Ok(parsed_body)
    }

    pub(crate) async fn get_with_response(
        &self,
        url: &Url,
        end_point: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.hyper.get(uri.clone());
        Self::wait_for_one_http_request(uri, response_future, deadline).await
    }

    pub(crate) async fn post_with_response(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.build_post_request(uri.clone(), http_body)?;
        Self::wait_for_one_http_request(uri, response_future, deadline).await
    }

    pub async fn send_post_request(
        &self,
        url: &str,
        http_body: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> Result<(Vec<u8>, hyper::StatusCode), String> {
        let uri = url
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse URL {:?}: {:?}", url, e))?;
        let req = hyper::Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .header(CONTENT_TYPE, "application/cbor")
            .body(Full::new(Bytes::from(http_body)))
            .map_err(|e| format!("HttpClient: Failed to fill body {:?}: {:?}", url, e))?;
        let response_future = self.hyper.request(req);

        let response = tokio::time::timeout_at(deadline, response_future)
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?;
        let response_body = response
            .map_err(|e| format!("HttpClient: Request failed out for {:?}: {:?}", uri, e))?;
        let status_code = response_body.status();
        let response_bytes = tokio::time::timeout_at(deadline, response_body.collect())
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?
            .map(|collected| collected.to_bytes().to_vec())
            .map_err(|e| format!("HttpClient: Failed to get bytes for {:?}: {:?}", uri, e))?;

        Ok((response_bytes, status_code))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}
