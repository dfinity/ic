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

/// listener_from_first_systemd_socket() takes the first FD(3) passed by systemd. It does not check if
/// more FDs are passed to the process. Make sure to call ensure_single_named_systemd_socket() before!
/// To ensure that only one listener on the socket exists this function should only be called once!
fn listener_from_first_systemd_socket() -> tokio::net::UnixListener {
    const SD_LISTEN_FDS_START: i32 = 3; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html

    let std_unix_listener = unsafe {
        // SAFETY: Primitives returned by `FromRawFd::from_raw_fd` have the contract
        // that they are the sole owner of the file descriptor they are wrapping.
        // Because no other function is calling `tokio::net::UnixListener::from_raw_fd` on
        // the first file descriptor provided by systemd, we consider this call safe.
        std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START)
    };

    // Set non-blocking mode as required by `tokio::net::UnixListener::from_std`.
    std_unix_listener
        .set_nonblocking(true)
        .expect("Failed to make listener non-blocking");

    tokio::net::UnixListener::from_std(std_unix_listener)
        .expect("Failed to convert UnixListener into Tokio equivalent")
}

/// ensure_single_named_systemd_socket() ensures that the correct file descriptor is passed by
/// checking the name. Additionally it makes sure that only one FD is received.
pub fn ensure_single_named_systemd_socket(socket_name: &str) {
    // This env. variable is set by the systemd service manager and can be used to check what file
    // descriptors are passed.
    // Setting the env. variable is done by ic-os/guestos/rootfs/etc/systemd/system/*.socket.
    // For more info see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
    const SYSTEMD_SOCKET_NAMES: &str = "LISTEN_FDNAMES";
    let systemd_socket_names =
        std::env::var(SYSTEMD_SOCKET_NAMES).expect("failed to read systemd socket names");
    if systemd_socket_names != socket_name {
        panic!(
            "Expected to receive a single systemd socket named '{}' but instead got '{}'",
            socket_name, systemd_socket_names
        );
    }
}

/// Creates an incoming async stream using the first systemd socket.
pub fn incoming_from_first_systemd_socket(
) -> AsyncStream<Result<UnixStream, std::io::Error>, impl futures::Future<Output = ()>> {
    let uds = listener_from_first_systemd_socket();

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
