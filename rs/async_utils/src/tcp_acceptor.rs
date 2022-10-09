use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::net::{TcpListener, TcpStream};

pub struct Counter {
    count: Arc<AtomicUsize>,
}

impl Counter {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self { count }
    }
}

impl Drop for Counter {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The class is a small wrapper around a TCP listener. The TcpAcceptor is used to limit
/// the number of live TCP connections.
pub struct TcpAcceptor {
    tcp_listener: TcpListener,
    max_connections: usize,
    connections: Arc<AtomicUsize>,
}

/// Struct that keeps a reference count to the number of open TCP connections.
pub struct WrappedTcpStream {
    tcp_stream: TcpStream,
    connections: Counter,
}

impl WrappedTcpStream {
    fn new(tcp_stream: TcpStream, connections: Arc<AtomicUsize>) -> Self {
        Self {
            tcp_stream,
            connections: Counter::new(connections),
        }
    }

    pub fn take(self) -> (TcpStream, Counter) {
        let WrappedTcpStream {
            tcp_stream,
            connections,
        } = self;
        (tcp_stream, connections)
    }

    pub async fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tcp_stream.peek(buf).await
    }
}

impl TcpAcceptor {
    pub fn new(tcp_listener: TcpListener, max_connections: usize) -> Self {
        Self {
            tcp_listener,
            max_connections,
            connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Accepts a new TCP connection iff the existing live connections don't exceed 'max_connections'.
    /// Otherwise, refuse the connection.
    pub async fn accept(&self) -> std::io::Result<(WrappedTcpStream, SocketAddr)> {
        let (tcp_stream, addr) = self.tcp_listener.accept().await?;

        // there is a race condition between the load() and the subsequent fetch_add(),
        // but we can live with that because 'max_connections' is a soft limit
        if self.connections.load(Ordering::Relaxed) >= self.max_connections {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                "Too many existing TCP connections.",
            ));
        }
        Ok((
            WrappedTcpStream::new(tcp_stream, self.connections.clone()),
            addr,
        ))
    }
}
