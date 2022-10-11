use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use ic_crypto_tls_interfaces::{
    TlsPublicKeyCert, TlsStream, TlsStreamReadHalf, TlsStreamWriteHalf,
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::Certificate;

mod cert_resolver;
pub mod client_handshake;
mod csp_server_signing_key;
mod node_cert_verifier;
pub mod server_handshake;

fn certified_key(
    self_tls_cert: TlsPublicKeyCert,
    csp_server_signing_key: CspServerEd25519SigningKey,
) -> CertifiedKey {
    CertifiedKey {
        cert: vec![Certificate(self_tls_cert.as_der().clone())],
        key: Arc::new(Box::new(csp_server_signing_key)),
        ocsp: None,
        sct_list: None,
    }
}

/// A TLS stream based on Rustls.
pub struct RustlsTlsStream {
    tls_stream: tokio_rustls::TlsStream<TcpStream>,
}

impl RustlsTlsStream {
    pub fn new(tls_stream: tokio_rustls::TlsStream<TcpStream>) -> Self {
        Self { tls_stream }
    }
}

impl TlsStream for RustlsTlsStream {
    fn split(self: Box<Self>) -> (Box<dyn TlsStreamReadHalf>, Box<dyn TlsStreamWriteHalf>) {
        let (tokio_rh, tokio_wh) = tokio::io::split(self.tls_stream);
        let rh = Box::new(RustlsTlsStreamReadHalf::new(tokio_rh));
        let wh = Box::new(RustlsTlsStreamWriteHalf::new(tokio_wh));
        (rh, wh)
    }
}

impl AsyncRead for RustlsTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.tls_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustlsTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.tls_stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.tls_stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.tls_stream).poll_shutdown(cx)
    }
}

/// The read half of a Rustls-based TLS stream.
pub struct RustlsTlsStreamReadHalf {
    read_half: ReadHalf<tokio_rustls::TlsStream<TcpStream>>,
}

impl RustlsTlsStreamReadHalf {
    pub fn new(read_half: ReadHalf<tokio_rustls::TlsStream<TcpStream>>) -> Self {
        Self { read_half }
    }
}

impl AsyncRead for RustlsTlsStreamReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.read_half).poll_read(cx, buf)
    }
}

impl TlsStreamReadHalf for RustlsTlsStreamReadHalf {}

/// The read half of a Rustls-based TLS stream.
///
/// See also the documentation of [`TlsStream`], especially the part on correct
/// flushing for the Rustls variant.
pub struct RustlsTlsStreamWriteHalf {
    write_half: WriteHalf<tokio_rustls::TlsStream<TcpStream>>,
}

impl RustlsTlsStreamWriteHalf {
    pub fn new(write_half: WriteHalf<tokio_rustls::TlsStream<TcpStream>>) -> Self {
        Self { write_half }
    }
}

impl AsyncWrite for RustlsTlsStreamWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.write_half).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_shutdown(cx)
    }
}

impl TlsStreamWriteHalf for RustlsTlsStreamWriteHalf {}
