use arc_swap::ArcSwapOption;
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures_util::future::BoxFuture;
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

#[derive(Clone)]
pub struct CustomAcceptor {
    inner: Arc<ArcSwapOption<RustlsAcceptor>>,
}

impl CustomAcceptor {
    pub fn new(inner: Arc<ArcSwapOption<RustlsAcceptor>>) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for CustomAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = S;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = &*self.inner;
        let acceptor = inner.load().clone();

        Box::pin(async move {
            match acceptor {
                Some(acceptor) => acceptor.accept(stream, service).await,
                None => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Acceptor is not available",
                )),
            }
        })
    }
}
