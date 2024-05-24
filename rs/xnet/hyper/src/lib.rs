#![allow(clippy::type_complexity)]

//! This module contains various utilities for https://hyper.rs
//! specific to Message Routing.
use hyper::{
    client::connect::{Connected, Connection, HttpConnector},
    server::{accept::Accept, conn::AddrIncoming},
    service::Service,
    Uri,
};
use ic_crypto_tls_interfaces::{AuthenticatedPeer, SomeOrAllNodes, TlsConfig};
use ic_crypto_utils_tls::node_id_from_certificate_der;
use ic_interfaces_registry::RegistryClient;
use ic_xnet_uri::XNetAuthority;
use std::convert::TryFrom;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// An implementation of hyper Executor that spawns futures on a tokio runtime
/// handle.
#[derive(Clone, Debug)]
pub struct ExecuteOnRuntime(pub tokio::runtime::Handle);

impl<F> hyper::rt::Executor<F> for ExecuteOnRuntime
where
    F: Future + 'static + Send,
    <F as Future>::Output: Send,
{
    fn execute(&self, fut: F) {
        self.0.spawn(fut);
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The current state of TLS connection.
enum ConnectionState<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// The handshake is still in progress.
    Handshake(
        Pin<Box<dyn Future<Output = Result<(IO, AuthenticatedPeer), std::io::Error>> + Send>>,
    ),
    /// Handshake was not successful.
    Failed(std::io::Error),
    /// The handshake completed successfully.
    Ready { stream: IO, peer: AuthenticatedPeer },
    /// An unencrypted TCP stream, MUST ONLY BE USED IN TESTS.
    Unencrypted(TcpStream),
}

/// Box an error to erase its type.
fn box_err(e: impl std::error::Error + Send + Sync + 'static) -> BoxError {
    Box::new(e) as Box<_>
}

/// A TLS connection.
pub struct TlsConnection(ConnectionState<tokio_rustls::TlsStream<TcpStream>>);

impl TlsConnection {
    /// Returns the identity of the connected peer if the TLS
    /// handshake completed successfully. Returns None if the handshake is not
    /// completed yet or failed.
    pub fn peer(&self) -> Option<&AuthenticatedPeer> {
        match &self.0 {
            ConnectionState::Ready { peer, .. } => Some(peer),
            _ => None,
        }
    }

    /// If the handshake is completed, applies `f` to the TlsStream.
    /// Otherwise, tries to make the progress with the handshake first.
    fn after_handshake<F, R>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<std::io::Result<R>>
    where
        F: FnOnce(
            Pin<&mut tokio_rustls::TlsStream<TcpStream>>,
            &mut Context<'_>,
        ) -> Poll<std::io::Result<R>>,
    {
        match &mut self.0 {
            ConnectionState::Handshake(fut) => match Future::poll(Pin::new(fut), cx) {
                Poll::Ready(Ok((stream, peer))) => {
                    // We have to switch the state before we call the
                    // callback, because the callback might call back
                    // into TlsConnection and cause another poll on
                    // the `fut` future, which is not allowed for
                    // futures that returned `Ready`.
                    self.0 = ConnectionState::Ready { stream, peer };
                    if let ConnectionState::Ready { ref mut stream, .. } = self.0 {
                        f(Pin::new(stream), cx)
                    } else {
                        unreachable!()
                    }
                }
                Poll::Ready(Err(tls_err)) => {
                    self.0 = ConnectionState::Failed(std::io::Error::new(
                        tls_err.kind(),
                        tls_err.to_string(),
                    ));
                    Poll::Ready(Err(tls_err))
                }
                Poll::Pending => Poll::Pending,
            },
            ConnectionState::Failed(err) => {
                Poll::Ready(Err(std::io::Error::new(err.kind(), err.to_string())))
            }
            ConnectionState::Ready { ref mut stream, .. } => f(Pin::new(stream), cx),
            ConnectionState::Unencrypted(_) => {
                unreachable!("must only be called for encrypted connections")
            }
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.0 {
            ConnectionState::Unencrypted(ref mut tcp_stream) => {
                Pin::new(tcp_stream).poll_read(cx, buf)
            }
            _ => self.after_handshake(cx, |stream, cx| stream.poll_read(cx, buf)),
        }
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.0 {
            ConnectionState::Unencrypted(ref mut tcp_stream) => {
                Pin::new(tcp_stream).poll_write(cx, buf)
            }
            _ => self.after_handshake(cx, |stream, cx| stream.poll_write(cx, buf)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.0 {
            ConnectionState::Unencrypted(ref mut tcp_stream) => Pin::new(tcp_stream).poll_flush(cx),
            _ => self.after_handshake(cx, |stream, cx| stream.poll_flush(cx)),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.0 {
            ConnectionState::Unencrypted(ref mut tcp_stream) => {
                Pin::new(tcp_stream).poll_shutdown(cx)
            }
            _ => self.after_handshake(cx, |stream, cx| stream.poll_shutdown(cx)),
        }
    }
}

impl Connection for TlsConnection {
    fn connected(&self) -> Connected {
        match &self.0 {
            ConnectionState::Ready { .. } => Connected::new(),
            ConnectionState::Unencrypted(tcp_stream) => tcp_stream.connected(),
            ConnectionState::Failed(_) | ConnectionState::Handshake(_) => {
                unreachable!("connected() cannot be called on unestablished/failed connections")
            }
        }
    }
}

/// An acceptor that produces TLS connections.
pub struct TlsAccept {
    inner: AddrIncoming,
    connection_type: ConnectionType,
    tls: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
}

impl Accept for TlsAccept {
    type Conn = TlsConnection;
    type Error = BoxError;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.inner).poll_accept(cx).map(|opt_res| {
            opt_res.map(|res| match res {
                Ok(conn) => match self.connection_type {
                    ConnectionType::Raw => Ok(TlsConnection(ConnectionState::Unencrypted(
                        conn.into_inner(),
                    ))),
                    ConnectionType::Tls => {
                        let tls = Arc::clone(&self.tls);
                        let registry_version = self.registry_client.get_latest_version();
                        let future = async move {
                            let server_config = tls
                                .server_config(SomeOrAllNodes::All, registry_version)
                                .map_err(|err| std::io::Error::other(err.to_string()))?;
                            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
                            let tls_stream = tls_acceptor.accept(conn.into_inner()).await?;
                            let peer_cert = tls_stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .ok_or(std::io::Error::other("no peer certificates"))?
                                .first()
                                .ok_or(std::io::Error::other("no peer certificates"))?;
                            let peer_id = AuthenticatedPeer::Node(
                                node_id_from_certificate_der(peer_cert.as_ref())
                                    .map_err(|err| std::io::Error::other(format!("{:?}", err)))?,
                            );
                            Ok((tokio_rustls::TlsStream::Server(tls_stream), peer_id))
                        };
                        Ok(TlsConnection(ConnectionState::Handshake(Box::pin(future))))
                    }
                },
                Err(err) => Err(Box::new(err) as Box<_>),
            })
        })
    }
}

/// A convenience function that constructs a Hyper server builder that uses TLS
/// acceptor using Crypto API.
///
/// This function sets the SO_REUSEADDR and SO_REUSEPORT options on the socket.
///
/// Returns an `Err` if binding to the specified socket address or setting
/// the above socket options failed.
pub fn tls_bind(
    addr: &SocketAddr,
    tls: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
) -> Result<(SocketAddr, hyper::server::Builder<TlsAccept>), BoxError> {
    tls_bind_with_connection_type(addr, tls, registry_client, ConnectionType::Tls)
}

/// Like [tls_bind], but accepts unencrypted connections.
/// This function should be used only in tests.
pub fn tls_bind_for_test(
    addr: &SocketAddr,
    tls: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
) -> Result<(SocketAddr, hyper::server::Builder<TlsAccept>), BoxError> {
    tls_bind_with_connection_type(addr, tls, registry_client, ConnectionType::Raw)
}

/// A common implementation
fn tls_bind_with_connection_type(
    addr: &SocketAddr,
    tls: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
    connection_type: ConnectionType,
) -> Result<(SocketAddr, hyper::server::Builder<TlsAccept>), BoxError> {
    let socket = bind_tcp_socket_with_reuse(addr)?;
    socket.listen(128)?;
    let listener = TcpListener::from_std(socket.into())?;

    AddrIncoming::from_listener(listener)
        .map(move |inner| {
            (
                inner.local_addr(),
                hyper::server::Server::<TlsAccept, ()>::builder(TlsAccept {
                    connection_type,
                    inner,
                    tls,
                    registry_client,
                }),
            )
        })
        .map_err(box_err)
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
    type Response = TlsConnection;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<TlsConnection, BoxError>> + Send>>;

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
                ConnectionType::Raw => Ok(TlsConnection(ConnectionState::Unencrypted(tcp_stream))),
                ConnectionType::Tls => {
                    let tls_config = tls
                        .client_config(xnet_auth.node_id, xnet_auth.registry_version)
                        .map_err(Box::new)?;
                    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
                    let irrelevant_domain =
                        "domain.is-irrelevant-as-hostname-verification-is.disabled";
                    tls_connector
                        .connect(
                            irrelevant_domain
                                .try_into()
                                // TODO: ideally the expect should run at compile time
                                .expect("failed to create domain"),
                            tcp_stream,
                        )
                        .await
                        .map(|tls_stream| {
                            TlsConnection(ConnectionState::Ready {
                                stream: tokio_rustls::TlsStream::Client(tls_stream),
                                peer: AuthenticatedPeer::Node(xnet_auth.node_id),
                            })
                        })
                        .map_err(box_err)
                }
            }
        };
        Box::pin(future)
    }
}
