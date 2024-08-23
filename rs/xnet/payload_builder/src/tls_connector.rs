#![allow(clippy::type_complexity)]

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
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Handle,
};
use tower::Service;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Box an error to erase its type.
fn box_err(e: impl std::error::Error + Send + Sync + 'static) -> BoxError {
    Box::new(e) as Box<_>
}

/// Binds a TCP listener to the specified address with `SO_REUSEADDR`
/// and `SO_REUSEPORT` set.
pub fn bind_listener(
    addr: &SocketAddr,
    runtime_handle: Handle,
) -> Result<(TcpListener, SocketAddr), BoxError> {
    let socket = bind_tcp_socket_with_reuse(addr)?;
    let listener = {
        let _guard = runtime_handle.enter();
        TcpListener::from_std(socket.into())?
    };
    let address = listener.local_addr()?;

    Ok((listener, address))
}

/// Binds a TCP socket on the given address after having set the `SO_REUSEADDR`
/// and `SO_REUSEPORT` flags.
///
/// Setting the flags after binding to the port has no effect.
fn bind_tcp_socket_with_reuse(addr: &SocketAddr) -> Result<socket2::Socket, BoxError> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(*addr))?;
    socket.listen(128)?;

    Ok(socket)
}

/// The type of the connection that should be used. This enum is mostly useful
/// for testing to avoid setting up the registry and keystore for TLS.
#[derive(Debug, Clone, Copy, Default)]
enum ConnectionType {
    /// Only accept TLS connections.
    #[allow(dead_code)]
    #[default]
    Tls,
    /// Only accept raw unencrypted connections. Should only be used for
    /// testing.
    #[allow(dead_code)]
    Raw,
}

// TLS connector for the client side.
#[derive(Clone)]
pub struct TlsConnector {
    connection_type: ConnectionType,
    http: HttpConnector,
    tls: Arc<dyn TlsConfig + Send + Sync>,
}

impl TlsConnector {
    pub fn new(tls: Arc<dyn TlsConfig + Send + Sync>) -> Self {
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
    pub fn new_for_tests(tls: Arc<dyn TlsConfig + Send + Sync>) -> Self {
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
        self.http.poll_ready(cx).map_err(box_err)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let xnet_auth = match XNetAuthority::try_from(&dst) {
            Ok(auth) => auth,
            Err(err) => return Box::pin(async move { Err(box_err(err)) }),
        };

        let http_uri = format!("http://{}", xnet_auth.address)
            .parse::<Uri>()
            .expect("failed to parse URI coming from trusted source");

        let connecting = self.http.call(http_uri);
        let tls = self.tls.clone();
        let connection_type = self.connection_type;
        let future = async move {
            let tcp_stream = connecting.await.map_err(box_err)?;
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
                        .await
                        .map_err(box_err)?;
                    Ok(MaybeHttpsStream::Https(TokioIo::new(tls_stream)))
                }
            }
        };
        Box::pin(future)
    }
}
