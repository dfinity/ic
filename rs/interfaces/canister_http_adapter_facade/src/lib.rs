/// The error type that can be returned on "send".
#[derive(Debug, PartialEq)]
pub enum SendError<Request> {
    /// The "bridge" is full. Some responses must be consumes before new
    /// requests are send.
    Full(Request),
    /// The "bridge" is closed. Sending and receiving fails.
    Closed(Request),
}

/// The error type that can be returned on "try_receive".
#[derive(Debug, PartialEq)]
pub enum ReceiveError {
    /// No new response are available.
    Empty,
    /// The "channel" is disconnected.
    Disconnected,
}

/// Abstract interface for non-blocking channel.
pub trait NonBlockingChannel<Request, Response> {
    fn send(&mut self, request: Request) -> Result<(), SendError<Request>>;
    fn try_receive(&mut self) -> Result<Response, ReceiveError>;
}
