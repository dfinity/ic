use ic_btc_types_internal::{BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper};
use std::time::Duration;
use strum_macros::IntoStaticStr;

/// Describe RPC error -- can be either related to transport (i.e.
/// failure to transport) or to server (i.e. server responded, but
/// gave us a message indicating an error).
#[derive(Debug, IntoStaticStr)]
pub enum BitcoinAdapterClientError {
    /// Failure at transport.
    ConnectionBroken,
    /// Bitcoin adapter client is unavailable at the moment and is not able to serve requests.
    // Likely a transient error. For example still syncing the header chain up to the lastest checkpoint.
    // You can retry the operation.
    Unavailable(String),
    /// Bitcoin adapter request was cancelled by the adapter client. Likely a timeout.
    Cancelled(String),
    /// Catch-all for unexpected errors in the bitcoin client. Likely a fatal error.
    Unknown(String),
}

pub type RpcResult<T> = Result<T, BitcoinAdapterClientError>;

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
