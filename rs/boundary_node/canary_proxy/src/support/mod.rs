//! Runtime utilities

mod auto_server;

mod rewind;
/// Implementation of [`hyper::rt::Executor`] that utilises [`tokio::spawn`].
mod tokio_executor;
mod tokio_io;

pub use auto_server::Builder as ServerBuilder;
pub(crate) use rewind::Rewind;
pub use tokio_executor::TokioExecutor;
pub use tokio_io::TokioIo;
