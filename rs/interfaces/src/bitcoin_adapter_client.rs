use ic_protobuf::bitcoin::v1::{BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper};
use std::time::Duration;
use tonic::Status;

/// Describe RPC error -- can be either related to transport (i.e.
/// failure to transport or parse a message) or to server (i.e. server
/// responded, but gave us a message indicating an error).
#[derive(Debug)]
pub enum RpcError {
    /// Failure at transport
    ConnectionBroken,
    /// Failure at server endpoint
    ServerError(Status),
    /// Invalid request passed to the client
    InvalidRequest(BitcoinAdapterRequestWrapper),
}

pub type RpcResult<T> = Result<T, RpcError>;

pub struct Options {
    pub timeout: Option<Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // Since we are allowed to block only for few milliseconds the consensus thread,
            // set reasonable defaults.
            timeout: Some(Duration::from_millis(10)),
        }
    }
}

/// Sync interface for communicating with the bitcoin adapter. Note the function calls block the
/// running thread. Also the calls may panic if called from async context.
pub trait BitcoinAdapterClient: Send + Sync {
    fn send_request(
        &self,
        request: BitcoinAdapterRequestWrapper,
        opts: Options,
    ) -> RpcResult<BitcoinAdapterResponseWrapper>;
}
