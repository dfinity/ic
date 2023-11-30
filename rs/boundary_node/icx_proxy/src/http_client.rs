use std::{
    borrow::Cow,
    cell::RefCell,
    collections::HashMap,
    fs::File,
    future::Future,
    hash::{Hash, Hasher},
    io::{Cursor, Read},
    iter,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context, Error};
use http::{HeaderMap, HeaderName, HeaderValue};
use hyper::{
    self,
    body::Bytes,
    client::{
        connect::dns::{GaiResolver, Name},
        HttpConnector,
    },
    service::Service,
    Client,
};
use hyper_rustls::HttpsConnectorBuilder;
use ic_agent::agent::http_transport::hyper_transport;
use itertools::Either;

use crate::domain_addr::DomainAddr;

/// The options for the HTTP client
pub struct HttpClientOpts<'a> {
    /// The list of custom root HTTPS certificates to use to talk to the replica. This can be used
    /// to connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    pub ssl_root_certificate: Vec<PathBuf>,

    /// Allows HTTPS connection to replicas with invalid HTTPS certificates. This can be used to
    /// connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is *VERY* unsecure.
    pub danger_accept_invalid_ssl: bool,

    /// Override DNS resolution for specific replica domains to particular IP addresses.
    pub replicas: &'a Vec<DomainAddr>,
}

pub type Body = hyper::Body;

pub trait HyperBody:
    hyper_transport::HyperBody
    + From<&'static [u8]>
    + From<&'static str>
    + From<Bytes>
    + From<Cow<'static, [u8]>>
    + From<Cow<'static, str>>
    + From<String>
    + From<Body>
    + Into<Body>
{
}

impl<B> HyperBody for B where
    B: hyper_transport::HyperBody
        + From<&'static [u8]>
        + From<&'static str>
        + From<Bytes>
        + From<Cow<'static, [u8]>>
        + From<Cow<'static, str>>
        + From<String>
        + From<Body>
        + Into<Body>
{
}

/// Trait representing the constraints on [`Service`] that [`HyperReplicaV2Transport`] requires.
pub trait HyperService<B1: HyperBody>:
    hyper_transport::HyperService<B1, ResponseBody = Self::ResponseBody2>
{
    /// Values yielded in the `Body` of the `Response`.
    type ResponseBody2: HyperBody;
}

impl<B1, B2, S> HyperService<B1> for S
where
    B1: HyperBody,
    B2: HyperBody,
    S: hyper_transport::HyperService<B1, ResponseBody = B2>,
{
    type ResponseBody2 = B2;
}

#[allow(clippy::declare_interior_mutable_const)]
pub const HEADER_X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
#[allow(clippy::declare_interior_mutable_const)]
pub const HEADER_IC_SUBNET_ID: HeaderName = HeaderName::from_static("x-ic-subnet-id");
#[allow(clippy::declare_interior_mutable_const)]
pub const HEADER_IC_SUBNET_TYPE: HeaderName = HeaderName::from_static("x-ic-subnet-type");
#[allow(clippy::declare_interior_mutable_const)]
pub const HEADER_IC_NODE_ID: HeaderName = HeaderName::from_static("x-ic-node-id");
#[allow(clippy::declare_interior_mutable_const)]
const HEADER_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
#[allow(clippy::declare_interior_mutable_const)]
const HEADER_IC_METHOD_NAME: HeaderName = HeaderName::from_static("x-ic-method-name");
#[allow(clippy::declare_interior_mutable_const)]
const HEADER_IC_SENDER: HeaderName = HeaderName::from_static("x-ic-sender");
#[allow(clippy::declare_interior_mutable_const)]
const HEADER_IC_REQUEST_TYPE: HeaderName = HeaderName::from_static("x-ic-request-type");

// Headers to pass from replica to the caller
#[allow(clippy::declare_interior_mutable_const)]
pub const HEADERS_PASS_IN: [HeaderName; 7] = [
    HEADER_IC_SUBNET_ID,
    HEADER_IC_NODE_ID,
    HEADER_IC_SUBNET_TYPE,
    HEADER_IC_CANISTER_ID,
    HEADER_IC_METHOD_NAME,
    HEADER_IC_SENDER,
    HEADER_IC_REQUEST_TYPE,
];

// Headers to pass from caller to replica
#[allow(clippy::declare_interior_mutable_const)]
pub const HEADERS_PASS_OUT: [HeaderName; 1] = [HEADER_X_REQUEST_ID];

thread_local!(pub static HEADERS_IN: RefCell<HeaderMap<HeaderValue>> = RefCell::new(HeaderMap::new()));
thread_local!(pub static HEADERS_OUT: RefCell<HeaderMap<HeaderValue>> = RefCell::new(HeaderMap::new()));

// Wrapper for the Hyper client (Hyper service) that uses thread local storage to pass specific HTTP headers back and forth
#[derive(Clone)]
pub struct HyperClientWrapper<S> {
    inner: S,
}

impl<S> Service<http::Request<Body>> for HyperClientWrapper<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            // Add selected headers to the request
            HEADERS_OUT.with(|f| {
                for (k, v) in (*f.borrow()).iter() {
                    #[allow(clippy::borrow_interior_mutable_const)]
                    if HEADERS_PASS_OUT.contains(k) {
                        req.headers_mut().append(k, v.clone());
                    }
                }
            });

            let res = inner.call(req).await;

            // If the request was a success - extract headers from it
            if let Ok(v) = &res {
                HEADERS_IN.with(|f| {
                    let mut m = f.borrow_mut();
                    m.clear();

                    for (k, v) in v.headers() {
                        #[allow(clippy::borrow_interior_mutable_const)]
                        if HEADERS_PASS_IN.contains(k) {
                            m.append(k, v.clone());
                        }
                    }
                });
            }

            res
        })
    }
}

pub fn setup(opts: HttpClientOpts) -> Result<impl HyperService<Body>, Error> {
    let HttpClientOpts {
        danger_accept_invalid_ssl,
        ssl_root_certificate,
        replicas,
    } = opts;

    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    let tls_config = if !danger_accept_invalid_ssl {
        use rustls::{Certificate, RootCertStore};

        let mut root_cert_store = RootCertStore::empty();

        if !ssl_root_certificate.is_empty() {
            match rustls_native_certs::load_native_certs() {
                Err(e) => tracing::warn!("Could not load native certs: {}", e),
                Ok(certs) => {
                    for cert in certs {
                        if let Err(e) = root_cert_store.add(&rustls::Certificate(cert.0)) {
                            tracing::warn!("Could not add native cert: {}", e);
                        }
                    }
                }
            }
        }

        for cert_path in ssl_root_certificate {
            let mut buf = Vec::new();

            if let Err(e) = File::open(&cert_path).and_then(|mut v| v.read_to_end(&mut buf)) {
                tracing::warn!("Could not load cert `{}`: {}", cert_path.display(), e);
                continue;
            }

            match cert_path.extension() {
                Some(v) if v == "pem" => {
                    tracing::info!(
                        "adding PEM cert `{}` to root certificates",
                        cert_path.display()
                    );
                    let mut pem = Cursor::new(buf);
                    let certs = match rustls_pemfile::certs(&mut pem) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                "No valid certificate was found `{}`: {}",
                                cert_path.display(),
                                e
                            );
                            continue;
                        }
                    };
                    for c in certs {
                        if let Err(e) = root_cert_store.add(&rustls::Certificate(c)) {
                            tracing::warn!(
                                "Could not add part of cert `{}`: {}",
                                cert_path.display(),
                                e
                            );
                        }
                    }
                }
                Some(v) if v == "der" => {
                    tracing::info!(
                        "adding DER cert `{}` to root certificates",
                        cert_path.display()
                    );
                    if let Err(e) = root_cert_store.add(&Certificate(buf)) {
                        tracing::warn!("Could not add cert `{}`: {}", cert_path.display(), e);
                    }
                }
                _ => tracing::warn!(
                    "Could not load cert `{}`: unknown extension",
                    cert_path.display()
                ),
            }
        }

        builder
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    } else {
        use rustls::{
            client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName},
            DigitallySignedStruct,
        };

        tracing::warn!("Allowing invalid certs. THIS VERY IS INSECURE.");
        struct NoVerifier;

        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::Certificate,
                _intermediates: &[rustls::Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::Certificate,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::Certificate,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
        }
        builder
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };

    // Advertise support for HTTP/2
    //tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let domain_addrs: HashMap<Uncased, SocketAddr> = replicas
        .iter()
        .filter_map(|v| Some((v.domain.host()?, v.addr?)))
        .map(|(domain, addr)| Ok((Uncased(Name::from_str(domain)?), addr)))
        .collect::<Result<_, Error>>()
        .context("Invalid domain in `replicas` flag")?;

    let resolver = tower::service_fn(move |name: Name| {
        let domain_addrs = domain_addrs.clone();

        async move {
            let name = Uncased(name);
            match domain_addrs.get(&name) {
                Some(&v) => Ok(Either::Left(iter::once(v))),
                None => GaiResolver::new().call(name.0).await.map(Either::Right),
            }
        }
    });

    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);

    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);

    let client: Client<_, Body> = Client::builder().build(connector);
    Ok(HyperClientWrapper { inner: client })
}

#[derive(Clone, Debug, Eq)]
struct Uncased(Name);

impl PartialEq<Uncased> for Uncased {
    fn eq(&self, v: &Uncased) -> bool {
        self.0.as_str().eq_ignore_ascii_case(v.0.as_str())
    }
}

impl Hash for Uncased {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().len().hash(state);
        for b in self.0.as_str().as_bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}
