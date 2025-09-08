use ic_logger::{ReplicaLogger, debug, info, new_logger, warn};
use std::future::Future;
use std::io;
use std::io::Error;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use stubborn_io::ReconnectOptions;
use stubborn_io::strategies::ExpBackoffStrategy;
use stubborn_io::tokio::{StubbornIo, UnderlyingIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;

pub struct RobustUnixStream(UnixStream);

impl AsyncRead for RobustUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for RobustUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl UnderlyingIo<(PathBuf, ReplicaLogger)> for RobustUnixStream {
    fn establish(
        (path, logger): (PathBuf, ReplicaLogger),
    ) -> Pin<Box<dyn Future<Output = io::Result<Self>> + Send>> {
        Box::pin(async move {
            debug!(logger, "Trying to (re-)connect to socket {:?}", path);
            let stream = UnixStream::connect(&path).await?;
            Ok(RobustUnixStream(stream))
        })
    }
}

pub type RobustUnixSocket = StubbornIo<RobustUnixStream, (PathBuf, ReplicaLogger)>;

pub async fn connect(socket_path: PathBuf, logger: ReplicaLogger) -> io::Result<RobustUnixSocket> {
    const MINIMUM_DELAY: Duration = Duration::from_millis(100);
    const MAXIMUM_DELAY: Duration = Duration::from_secs(1);
    const EXPONENTIAL_BACKOFF_FACTOR: f64 = 2.0;
    const JITTER_AMOUNT: f64 = 0.05;
    let options = ReconnectOptions::new()
        .with_on_disconnect_callback({
            let logger = new_logger!(logger);
            let socket_path = socket_path.clone();
            move || {
                warn!(
                    logger,
                    "Detected disconnection from socket {:?}. Attempting to reconnect...",
                    socket_path
                );
            }
        })
        .with_on_connect_callback({
            let logger = new_logger!(logger);
            let socket_path = socket_path.clone();
            move || {
                debug!(
                    logger,
                    "Successfully (re-)connected to socket {:?}", socket_path
                )
            }
        })
        .with_on_connect_fail_callback({
            let logger = new_logger!(logger);
            let socket_path = socket_path.clone();
            move || info!(logger, "Failed to reconnect to socket {:?}", socket_path)
        })
        .with_retries_generator(|| {
            ExpBackoffStrategy::new(MINIMUM_DELAY, EXPONENTIAL_BACKOFF_FACTOR, JITTER_AMOUNT)
                .with_max(MAXIMUM_DELAY)
        });
    RobustUnixSocket::connect_with_options((socket_path, logger), options).await
}
