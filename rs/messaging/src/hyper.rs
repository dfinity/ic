#![allow(clippy::type_complexity)]

//! This module contains various utilities for https://hyper.rs
//! specific to Message Routing.
use crate::xnet_uri::XNetAuthority;
use hyper::{
    client::connect::{Connected, Connection, HttpConnector},
    server::{accept::Accept, conn::AddrIncoming},
    service::Service,
    Uri,
};
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, SomeOrAllNodes, TlsHandshake, TlsServerHandshakeError,
    TlsStream,
};
use ic_interfaces::registry::RegistryClient;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

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
enum ConnectionState {
    /// The handshake is still in progress.
    Handshake(
        Pin<
            Box<
                dyn Future<Output = Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError>>
                    + Send,
            >,
        >,
    ),
    /// Handshake was not successful.
    Failed(TlsServerHandshakeError),
    /// The handshake completed successfully.
    Ready {
        stream: TlsStream,
        peer: AuthenticatedPeer,
    },
    /// An unecrypted TCP stream, MUST ONLY BE USED IN TESTS.
    Unencrypted(TcpStream),
}

/// Box an error to erase its type.
fn box_err(e: impl std::error::Error + Send + Sync + 'static) -> BoxError {
    Box::new(e) as Box<_>
}

/// Construct an IO error of kind Other holding the specified error.
fn io_err(e: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// A TLS connection.
pub struct TlsConnection(ConnectionState);

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
        F: FnOnce(Pin<&mut TlsStream>, &mut Context<'_>) -> Poll<std::io::Result<R>>,
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
                    self.0 = ConnectionState::Failed(tls_err.clone());
                    Poll::Ready(Err(io_err(tls_err)))
                }
                Poll::Pending => Poll::Pending,
            },
            ConnectionState::Failed(err) => Poll::Ready(Err(io_err(err.clone()))),
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
    tls: Arc<dyn TlsHandshake + Send + Sync>,
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
                            tls.perform_tls_server_handshake(
                                conn.into_inner(),
                                AllowedClients::new(SomeOrAllNodes::All, HashSet::new()).unwrap(),
                                registry_version,
                            )
                            .await
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
    tls: Arc<dyn TlsHandshake + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
) -> Result<(SocketAddr, hyper::server::Builder<TlsAccept>), BoxError> {
    let socket = bind_tcp_socket_with_reuse(addr)?;
    socket.listen(128)?;
    let listener = TcpListener::from_std(socket.into())?;

    AddrIncoming::from_listener(listener)
        .map(move |inner| {
            (
                inner.local_addr(),
                hyper::server::Server::<TlsAccept, ()>::builder(TlsAccept {
                    connection_type: ConnectionType::default(),
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
        SocketAddr::V4(_) => Domain::ipv4(),
        SocketAddr::V6(_) => Domain::ipv6(),
    };
    let socket = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;

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
#[derive(Debug, Clone, Copy)]
enum ConnectionType {
    /// Only accept TLS connections.
    #[allow(dead_code)]
    Tls,
    /// Only accept raw unencrypted connections. Should only be used for
    /// testing.
    #[allow(dead_code)]
    Raw,
}

// Unit tests are not ready to handle TLS yet, so we fallback
// to raw connections there.
impl Default for ConnectionType {
    #[cfg(test)]
    fn default() -> Self {
        ConnectionType::Raw
    }
    #[cfg(not(test))]
    fn default() -> Self {
        ConnectionType::Tls
    }
}

// TLS connector for the client side.
#[derive(Clone)]
pub struct TlsConnector {
    connection_type: ConnectionType,
    http: HttpConnector,
    tls: Arc<dyn TlsHandshake + Send + Sync>,
}

impl TlsConnector {
    pub fn new(tls: Arc<dyn TlsHandshake + Send + Sync>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Self {
            connection_type: ConnectionType::default(),
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
                    let tls_stream = tls
                        .perform_tls_client_handshake(
                            tcp_stream,
                            xnet_auth.node_id,
                            xnet_auth.registry_version,
                        )
                        .await
                        .map_err(box_err)?;
                    Ok(TlsConnection(ConnectionState::Ready {
                        stream: tls_stream,
                        peer: AuthenticatedPeer::Node(xnet_auth.node_id),
                    }))
                }
            }
        };
        Box::pin(future)
    }
}
