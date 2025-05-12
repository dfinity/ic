use crate::tls::shared_key_for_attestation;
use pin_project::pin_project;
use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tonic::transport::server::Connected;

#[derive(Clone, Debug)]
pub struct TlsConnectionInfoForUpgrade {
    pub(crate) tls_shared_key_for_attestation: [u8; 32],
}

#[pin_project]
pub struct TlsStreamWrapper(#[pin] pub tokio_rustls::server::TlsStream<TcpStream>);

impl AsyncRead for TlsStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl Connected for TlsStreamWrapper {
    type ConnectInfo = TlsConnectionInfoForUpgrade;

    fn connect_info(&self) -> Self::ConnectInfo {
        TlsConnectionInfoForUpgrade {
            tls_shared_key_for_attestation: shared_key_for_attestation(&self.0.get_ref().1),
        }
    }
}

impl AsyncWrite for TlsStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().0.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        self.project().0.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}
