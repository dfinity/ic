//! This module contains various utilities for https://hyper.rs
//! specific to Message Routing.
use hyper::Uri;
use hyper_rustls::MaybeHttpsStream;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioIo};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_xnet_uri::XNetAuthority;
use std::{
    convert::TryFrom,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tower::{BoxError, Service};

/// The type of the connection that should be used. This enum is mostly useful
/// for testing to avoid setting up the registry and keystore for TLS.
#[derive(Copy, Clone, Debug, Default)]
enum ConnectionType {
    /// Only accept TLS connections.
    #[default]
    Tls,
    /// Only accept raw unencrypted connections. Should only be used for
    /// testing.
    Raw,
}

// TLS connector for the client side.
#[derive(Clone)]
pub struct TlsConnector {
    connection_type: ConnectionType,
    http: HttpConnector,
    tls: Arc<dyn TlsConfig>,
}

impl TlsConnector {
    pub fn new(tls: Arc<dyn TlsConfig>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Self {
            connection_type: ConnectionType::Tls,
            http,
            tls,
        }
    }

    /// Like [TlsConnector::new], but connects over unencrypted channel.
    /// This function should be used only in tests.
    pub fn new_for_tests(tls: Arc<dyn TlsConfig>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Self {
            connection_type: ConnectionType::Raw,
            http,
            tls,
        }
    }
}

impl Service<Uri> for TlsConnector {
    type Future = Pin<
        Box<dyn Future<Output = Result<MaybeHttpsStream<TokioIo<TcpStream>>, BoxError>> + Send>,
    >;
    type Response = MaybeHttpsStream<TokioIo<TcpStream>>;
    type Error = BoxError;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(|e| Box::new(e) as Box<_>)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let xnet_auth = match XNetAuthority::try_from(&dst) {
            Ok(auth) => auth,
            Err(err) => return Box::pin(async move { Err(Box::new(err) as Box<_>) }),
        };

        let http_uri = format!("http://{}", xnet_auth.address)
            .parse::<Uri>()
            .expect("failed to parse URI coming from trusted source");

        let connecting = self.http.call(http_uri);
        let tls = self.tls.clone();
        let connection_type = self.connection_type;
        let future = async move {
            let tcp_stream = connecting.await?;
            match connection_type {
                ConnectionType::Raw => Ok(MaybeHttpsStream::Http(tcp_stream)),
                ConnectionType::Tls => {
                    let tls_config = tls
                        .client_config(xnet_auth.node_id, xnet_auth.registry_version)
                        .map_err(Box::new)?;
                    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
                    let irrelevant_domain =
                        "domain.is-irrelevant-as-hostname-verification-is.disabled";
                    let tls_stream = tls_connector
                        .connect(
                            irrelevant_domain
                                .try_into()
                                // TODO: ideally the expect should run at compile time
                                .expect("failed to create domain"),
                            TokioIo::new(tcp_stream),
                        )
                        .await?;
                    Ok(MaybeHttpsStream::Https(TokioIo::new(tls_stream)))
                }
            }
        };
        Box::pin(future)
    }
}
