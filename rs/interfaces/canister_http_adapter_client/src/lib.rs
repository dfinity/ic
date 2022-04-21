use ic_types::canister_http::{CanisterHttpRequest, CanisterHttpResponse};

/// The error type that can be returned on "send".
#[derive(Debug, PartialEq)]
pub enum SendError<Request> {
    /// Channel is full. Some responses must be consumes before new
    /// requests are send.
    Full(Request),
}

/// The error type that can be returned on "try_receive".
#[derive(Debug, PartialEq)]
pub enum TryReceiveError {
    /// No new response are available.
    Empty,
}

/// Abstract interface for non-blocking channel.
pub trait NonBlockingChannel<Request, Response> {
    fn send(&mut self, request: Request) -> Result<(), SendError<Request>>;
    fn try_receive(&mut self) -> Result<Response, TryReceiveError>;
}

pub type CanisterHttpAdapterClient =
    Box<dyn NonBlockingChannel<CanisterHttpRequest, CanisterHttpResponse> + Send>;
