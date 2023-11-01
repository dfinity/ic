use std::time::Duration;
use strum_macros::IntoStaticStr;
use thiserror::Error;

/// Describe RPC error -- can be either related to transport (i.e.
/// failure to transport) or to server (i.e. server responded, but
/// gave us a message indicating an error).
#[derive(Debug, IntoStaticStr, Error)]
pub enum RpcError {
    /// Failure at transport.
    #[error("ConnectionBroken")]
    ConnectionBroken,

    /// The adapter is unavailable at the moment and is not able to serve requests.
    // Likely a transient error. For example in the BTC feature, this error may mean
    // the adapter is still syncing the header chain up to the latest checkpoint.
    // You can retry the operation.
    #[error("Unavailable({0})")]
    Unavailable(String),

    /// The adapter request was cancelled by the adapter client. Likely a timeout.
    #[error("Cancelled({0})")]
    Cancelled(String),

    /// Catch-all for unexpected errors in the bitcoin client. Likely a fatal error.
    #[error("Unknown({0})")]
    Unknown(String),
}

pub type RpcResult<T> = Result<T, RpcError>;

pub struct Options {
    pub timeout: Duration,
}

/// Sync interface for communicating with an adapter.
pub trait RpcAdapterClient<T>: Send + Sync {
    type Response;

    /// The method blocks the running thread. May panic if called from async context.
    fn send_blocking(&self, request: T, opts: Options) -> RpcResult<Self::Response>;
}

/// The error type that can be returned on "send".
#[derive(Clone, Eq, Debug, PartialEq)]
pub enum SendError<Request> {
    /// Channel is full. Some responses must be consumes before new
    /// requests are send.
    Full(Request),
    /// No connection to adapter.
    BrokenConnection,
}

/// The error type that can be returned on "try_receive".
#[derive(Clone, Eq, Debug, PartialEq)]
pub enum TryReceiveError {
    /// No new response are available.
    Empty,
}

/// Abstract interface for non-blocking channel.
pub trait NonBlockingChannel<Request> {
    type Response;

    fn send(&self, request: Request) -> Result<(), SendError<Request>>;
    fn try_receive(&mut self) -> Result<Self::Response, TryReceiveError>;
}
