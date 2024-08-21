use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[cfg(not(feature = "tls"))]
use std::path::Path;

#[cfg(feature = "tls")]
use anyhow::Error;

use axum::extract::connect_info::Connected;
use futures_util::ready;
use hyper::server::{accept::Accept, Builder, Server};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(not(feature = "tls"))]
use tokio::net::UnixSocket;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UnixListener, UnixStream};

// These are used in case the peer_addr() below fails for whatever reason
const DEFAULT_IP_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
const DEFAULT_SOCK_ADDR: SocketAddr = SocketAddr::new(DEFAULT_IP_ADDR, 0);

// Custom extractor of ConnectInfo for our Tcp listener, default does not work with it
#[derive(Clone)]
pub struct TcpConnectInfo(pub SocketAddr);

impl Connected<&TcpStream> for TcpConnectInfo {
    fn connect_info(target: &TcpStream) -> Self {
        Self(target.peer_addr().unwrap_or(DEFAULT_SOCK_ADDR))
    }
}

// Unix socket handler
pub struct SocketUnix {
    listener: UnixListener,
}

#[cfg(not(feature = "tls"))]
impl SocketUnix {
    pub fn bind(path: impl AsRef<Path>, backlog: u32) -> Result<Self, std::io::Error> {
        let socket = UnixSocket::new_stream()?;
        socket.bind(path)?;
        let listener = socket.listen(backlog)?;
        Ok(Self { listener })
    }
}

impl Accept for SocketUnix {
    type Conn = UnixStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let conn = ready!(self.listener.poll_accept(cx))?.0;
        Poll::Ready(Some(Ok(conn)))
    }
}

// TCP socket handler
pub struct SocketTcp {
    listener: TcpListener,
}

impl SocketTcp {
    pub fn bind(addr: SocketAddr, backlog: u32) -> Result<Self, std::io::Error> {
        let socket = TcpSocket::new_v6()?;
        socket.set_keepalive(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(backlog)?;
        Ok(Self { listener })
    }
}

impl Accept for SocketTcp {
    type Conn = TcpStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let conn = ready!(self.listener.poll_accept(cx))?.0;
        conn.set_nodelay(true)?;
        Poll::Ready(Some(Ok(conn)))
    }
}

// Convenience methods for constructing a Hyper Server listening on TCP/Unix sockets with a backlog set
#[cfg(not(feature = "tls"))]
pub trait UnixServerExt {
    fn bind_unix(path: impl AsRef<Path>, backlog: u32) -> Result<Builder<SocketUnix>, io::Error>;
}
#[cfg(not(feature = "tls"))]
impl UnixServerExt for Server<SocketUnix, ()> {
    fn bind_unix(path: impl AsRef<Path>, backlog: u32) -> Result<Builder<SocketUnix>, io::Error> {
        let incoming = SocketUnix::bind(path, backlog)?;
        Ok(Server::builder(incoming))
    }
}

pub trait TcpServerExt {
    fn bind_tcp(addr: SocketAddr, backlog: u32) -> Result<Builder<SocketTcp>, io::Error>;
}

impl TcpServerExt for Server<SocketTcp, ()> {
    fn bind_tcp(addr: SocketAddr, backlog: u32) -> Result<Builder<SocketTcp>, io::Error> {
        let incoming = SocketTcp::bind(addr, backlog)?;
        Ok(Server::builder(incoming))
    }
}

#[cfg(feature = "tls")]
pub fn listen_tcp_backlog(addr: SocketAddr, backlog: u32) -> Result<std::net::TcpListener, Error> {
    // Create tokio TcpListener that can set the backlog
    let socket = TcpSocket::new_v6()?;
    socket.bind(addr)?;
    let listener = socket.listen(backlog)?;

    // Turn it into a std TcpListener that axum_server can consume
    let listener = listener.into_std()?;
    // It's returned with non-blocking mode on, disable it
    listener.set_nonblocking(false)?;

    Ok(listener)
}
