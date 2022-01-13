/// Abstraction which provides simple way to send RPC requests from a sync
/// context and check for available replies.
use std::convert::From;
use std::future::Future;
use std::pin::Pin;
use tokio::{
    runtime::Handle,
    sync::mpsc::{
        channel,
        error::{TryRecvError, TrySendError},
        Receiver, Sender,
    },
};

/// The error type that can be returned on "send".
#[derive(Debug, PartialEq)]
pub enum RpcBridgeSendError<Request> {
    /// The "bridge" is full. Some responses must be consumes before new
    /// requests are send.
    Full(Request),
    /// The "bridge" is closed. Sending and receiving fails.
    Closed(Request),
}

/// The error type that can be returned on "try_receive".
#[derive(Debug, PartialEq)]
pub enum RpcBridgeReceiveError {
    /// No new response are available.
    Empty,
    /// The "bridge" is disconnected.
    Disconnected,
}

impl From<TryRecvError> for RpcBridgeReceiveError {
    fn from(error: TryRecvError) -> Self {
        match error {
            TryRecvError::Empty => RpcBridgeReceiveError::Empty,
            TryRecvError::Disconnected => RpcBridgeReceiveError::Disconnected,
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The interface provides two non-blocking function - "send" and "try_receive".
/// The intended is to use the interface with RPC clients.
pub struct RpcBridge<Request, Response> {
    rt_handle: Handle,
    // The "bridge" takes ownership of the closure and the closure takes ownership of the RPC
    // client.
    func: Box<dyn FnMut(Request) -> BoxFuture<Response>>,
    tx: Sender<Response>,
    rx: Receiver<Response>,
}

impl<Request, Response> RpcBridge<Request, Response>
where
    Request: Send,
    Response: Send + 'static,
{
    pub fn new(
        rt_handle: Handle,
        inflight_requests: usize,
        func: Box<dyn FnMut(Request) -> BoxFuture<Response>>,
    ) -> Self {
        let (tx, rx) = channel(inflight_requests);
        Self {
            rt_handle,
            func,
            tx,
            rx,
        }
    }

    /// Enqueues a request that will be send to the RPC server iff we don't have
    /// more than 'inflight_requests' requests waiting to be consumed by the
    /// client.
    pub fn send(&mut self, request: Request) -> Result<(), RpcBridgeSendError<Request>> {
        // Accept the request iff we can secure capacity for sending the response back.
        let permit = match self.tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(err) => {
                return match err {
                    TrySendError::Full(_) => Err(RpcBridgeSendError::Full(request)),
                    TrySendError::Closed(_) => Err(RpcBridgeSendError::Closed(request)),
                };
            }
        };
        // Construct the future for obtaining the response but don't not poll it yet.
        let response_fut = (self.func)(request);
        // Spawn an async task that polls the response and once available send the
        // response over to the channel making it available to the client.
        self.rt_handle.spawn(async move {
            let response = response_fut.await;
            permit.send(response);
        });
        Ok(())
    }

    /// Returns an available response.
    pub fn try_receive(&mut self) -> Result<Response, RpcBridgeReceiveError> {
        self.rx.try_recv().map_err(RpcBridgeReceiveError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_sequential_send_and_receive() {
        let inc_fun = |x: i32| -> BoxFuture<i32> { Box::pin(async move { x + 1 }) };
        let mut bridge = RpcBridge::new(tokio::runtime::Handle::current(), 10, Box::new(inc_fun));

        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
        assert_eq!(bridge.send(1), Ok(()));
        // We must yield here in other to allow for the task that runs the closure to be executed.
        tokio::task::yield_now().await;
        assert_eq!(bridge.try_receive(), Ok(2));
        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
        assert_eq!(bridge.send(100), Ok(()));
        // We must yield here in other to allow for the task that runs the closure to be executed.
        tokio::task::yield_now().await;
        assert_eq!(bridge.try_receive(), Ok(101));
        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
    }

    #[tokio::test]
    async fn test_batched_send_and_receive() {
        let inc_fun = |x: i32| -> BoxFuture<i32> { Box::pin(async move { x + 1 }) };
        let mut bridge = RpcBridge::new(tokio::runtime::Handle::current(), 10, Box::new(inc_fun));

        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
        assert_eq!(bridge.send(1), Ok(()));
        assert_eq!(bridge.send(100), Ok(()));

        // We must yield in other to allow for tasks that run closures to be executed.
        tokio::task::yield_now().await;
        assert_eq!(bridge.try_receive(), Ok(2));
        assert_eq!(bridge.try_receive(), Ok(101));
        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
    }

    #[tokio::test]
    async fn test_at_capacity() {
        let inc_fun = |x: i32| -> BoxFuture<i32> { Box::pin(async move { x + 1 }) };
        let mut bridge = RpcBridge::new(tokio::runtime::Handle::current(), 2, Box::new(inc_fun));

        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
        assert_eq!(bridge.send(1), Ok(()));
        assert_eq!(bridge.send(100), Ok(()));
        assert_eq!(bridge.send(1000), Err(RpcBridgeSendError::Full(1000)));

        // We must yield in other to allow for tasks that run closures to be executed.
        tokio::task::yield_now().await;
        assert_eq!(bridge.try_receive(), Ok(2));

        // After receiving a single response resend the request that failed.
        assert_eq!(bridge.send(1000), Ok(()));

        // We must yield in other to allow for the task that runs the new closure to be executed.
        tokio::task::yield_now().await;
        assert_eq!(bridge.try_receive(), Ok(101));
        assert_eq!(bridge.try_receive(), Ok(1001));

        assert_eq!(bridge.try_receive(), Err(RpcBridgeReceiveError::Empty));
    }
}
