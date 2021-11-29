//! Reader/writer definitions

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub type WriteStub = Box<dyn AsyncWrite + Send + Unpin>;
pub type ReadStub = Box<dyn AsyncRead + Send + Unpin>;

#[derive(Debug)]
pub enum ErrorCode {
    // Payload is the argument to send()
    SendFull(Payload),

    // No data available
    ReadEmpty,

    Failed,
}

pub type Payload = Vec<u8>;

#[async_trait]
pub trait StreamWriter {
    async fn send(&mut self, payload: Payload) -> Result<(), ErrorCode>;
}

#[async_trait]
pub trait StreamReader {
    async fn receive(&mut self) -> Result<Payload, ErrorCode>;
}
