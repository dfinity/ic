/// The module contains utilities used for establishing RPC connections over a unix domain
/// socket (UDS) between two processes managed by systemd.
///
/// Existing socket systemd configurations can be found
/// ic-os/guestos/rootfs/etc/systemd/system/*.socket.
use async_stream::AsyncStream;
use futures::TryFutureExt;
use std::{
    os::unix::io::FromRawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

/// The function uses the passed 'path' for creating a unix domain socket
/// for serving inter-process communication requests.
pub fn incoming_from_path<P: AsRef<std::path::Path>>(
    path: P,
) -> AsyncStream<Result<UnixStream, std::io::Error>, impl futures::Future<Output = ()>> {
    let uds = tokio::net::UnixListener::bind(path).expect("Failed to bind path.");
    async_stream::stream! {
        loop {
            let item = uds.accept().map_ok(|(stream, _)| UnixStream(stream)).await;
            yield item;
        }
    }
}

/// # Safety
/// To ensure safety caller needs to ensure that the FD exists and only consumed once.
unsafe fn listener_from_systemd_socket(socket_fds: i32) -> tokio::net::UnixListener {
    // unsafe
    // https://doc.rust-lang.org/std/os/unix/io/trait.FromRawFd.html#tymethod.from_raw_fd
    let std_unix_listener = std::os::unix::net::UnixListener::from_raw_fd(socket_fds);

    // Set non-blocking mode as required by `tokio::net::UnixListener::from_std`.
    std_unix_listener
        .set_nonblocking(true)
        .expect("Failed to make listener non-blocking");

    tokio::net::UnixListener::from_std(std_unix_listener)
        .expect("Failed to convert UnixListener into Tokio equivalent")
}

/// incoming_from_first_systemd_socket() takes the first FD(3) passed by systemd. It does not check if
/// more FDs are passed to the process.
///
/// # Safety
/// To ensure safety caller needs to ensure that the FD(3) exists and only consumed once.
pub unsafe fn incoming_from_first_systemd_socket(
) -> AsyncStream<Result<UnixStream, std::io::Error>, impl futures::Future<Output = ()>> {
    const SOCKET_FD: i32 = 3; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
    let uds = listener_from_systemd_socket(SOCKET_FD);
    async_stream::stream! {
        loop {
            let item = uds.accept().map_ok(|(st, _)| UnixStream(st)).await;

            yield item;
        }
    }
}

/// incoming_from_second_systemd_socket() takes the second FD(4) passed by systemd. It does not check if
/// more FDs are passed to the process.
///
/// # Safety
///  To ensure safety caller needs to ensure that the FD(4) exists and only consumed once.
pub unsafe fn incoming_from_second_systemd_socket(
) -> AsyncStream<Result<UnixStream, std::io::Error>, impl futures::Future<Output = ()>> {
    const SOCKET_FD: i32 = 4; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
    let uds = listener_from_systemd_socket(SOCKET_FD);
    async_stream::stream! {
        loop {
            let item = uds.accept().map_ok(|(st, _)| UnixStream(st)).await;

            yield item;
        }
    }
}

#[derive(Debug)]
pub struct UnixStream(pub tokio::net::UnixStream);

impl Connected for UnixStream {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        UdsConnectInfo {
            peer_addr: self.0.peer_addr().ok().map(Arc::new),
            peer_cred: self.0.peer_cred().ok(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub peer_addr: Option<Arc<tokio::net::unix::SocketAddr>>,
    pub peer_cred: Option<tokio::net::unix::UCred>,
}

impl AsyncRead for UnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
