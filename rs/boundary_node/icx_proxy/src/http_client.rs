use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    hash::{Hash, Hasher},
    io::{Cursor, Read},
    iter,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use clap::Args;
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
use ic_agent::agent::http_transport;
use itertools::Either;
use tracing::error;

/// DNS resolve overrides
/// `ic0.app=[::1]:9090`

#[derive(Clone)]
struct OptResolve {
    domain: String,
    addr: SocketAddr,
}

impl FromStr for OptResolve {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        let (domain, addr) = s
            .split_once('=')
            .ok_or_else(|| anyhow::Error::msg("missing '='"))?;
        Ok(OptResolve {
            domain: domain.into(),
            addr: addr.parse()?,
        })
    }
}

/// The options for the HTTP client
#[derive(Args)]
pub struct Opts {
    /// The list of custom root HTTPS certificates to use to talk to the replica. This can be used
    /// to connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    ssl_root_certificate: Vec<PathBuf>,

    /// Allows HTTPS connection to replicas with invalid HTTPS certificates. This can be used to
    /// connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is *VERY* unsecure.
    #[clap(long)]
    danger_accept_invalid_ssl: bool,

    /// Override DNS resolution for specific replica domains to particular IP addresses.
    /// Examples: ic0.app=[::1]:9090
    #[clap(long, value_name("DOMAIN=IP_PORT"))]
    replica_resolve: Vec<OptResolve>,
}

pub type Body = hyper::Body;

pub trait HyperBody:
    http_transport::HyperBody
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
    B: http_transport::HyperBody
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

/// Trait representing the contraints on [`Service`] that [`HyperReplicaV2Transport`] requires.
pub trait HyperService<B1: HyperBody>:
    http_transport::HyperService<B1, ResponseBody = Self::ResponseBody2>
{
    /// Values yielded in the `Body` of the `Response`.
    type ResponseBody2: HyperBody;
}

impl<B1, B2, S> HyperService<B1> for S
where
    B1: HyperBody,
    B2: HyperBody,
    S: http_transport::HyperService<B1, ResponseBody = B2>,
{
    type ResponseBody2 = B2;
}

pub fn setup(opts: Opts) -> Result<impl HyperService<Body>, anyhow::Error> {
    let Opts {
        danger_accept_invalid_ssl,
        ssl_root_certificate,
        replica_resolve,
    } = opts;
    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    let tls_config = if !danger_accept_invalid_ssl {
        use rustls::{Certificate, RootCertStore};

        let mut root_cert_store = RootCertStore::empty();
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

        use rustls::OwnedTrustAnchor;
        let trust_anchors = webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|trust_anchor| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                trust_anchor.subject,
                trust_anchor.spki,
                trust_anchor.name_constraints,
            )
        });
        root_cert_store.add_server_trust_anchors(trust_anchors);

        builder
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    } else {
        use rustls::{
            client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName},
            internal::msgs::handshake::DigitallySignedStruct,
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

    #[derive(Debug, Eq)]
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

    let mapped = replica_resolve
        .into_iter()
        .map(|v| Ok((Uncased(Name::from_str(&v.domain)?), v.addr)))
        .collect::<Result<HashMap<_, _>, anyhow::Error>>()
        .context("Invalid domain in `replica-resolve` flag");
    // TODO: inspect_err
    let _ = mapped.as_ref().map_err(|e| error!("{}", e));
    let mapped = Arc::new(mapped?);
    let resolver = tower::service_fn(move |name: Name| {
        let mapped = mapped.clone();
        async move {
            let name = Uncased(name);
            if let Some(v) = mapped.get(&name) {
                Ok(Either::Left(iter::once(*v)))
            } else {
                GaiResolver::new().call(name.0).await.map(Either::Right)
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
    Ok(client)
}
