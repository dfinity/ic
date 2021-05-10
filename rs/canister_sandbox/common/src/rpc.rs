use std::pin::Pin;
use std::result::Result;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};

/// Pieces for a very simple bidirectional RPC using an underlying
/// duplex stream channel.

/// Describe RPC error -- can be either related to transport (i.e.
/// failure to transport or parse a message) or to server (i.e. server
/// responded, but gave us a message indicating an error).
#[derive(Clone, Debug)]
pub enum Error {
    /// Failure at transport
    ConnectionBroken,
    /// Failure at server endpoint
    ServerError,
}
pub type RPCResult<T> = Result<T, Error>;

/// Sink for messages (exchanged at transport layer). Note that this
/// always includes capabilities for exchange across threads.
// Improvement: Handle to be improved by SCL-215.
pub trait MessageSink<Message>: Send + Sync {
    fn handle(&self, cookie: u64, msg: Message);
}

/// Accept RPC results.
pub trait PostResult<Value> {
    fn post_result(&self, value: RPCResult<Value>);
}

/// Get results, either synchronously or asynchronously.
pub trait GetResult<Value> {
    fn poll(&self, cx: &mut Context<'_>) -> Poll<RPCResult<Value>>;
    fn sync(&self) -> RPCResult<Value>;
}

/// Demultiplexes request into specific target RPC function, collect
/// reply and returns it.
pub trait DemuxServer<Request, Reply>: Send + Sync {
    fn dispatch(&self, req: Request) -> Call<Reply>;
}

/// An RPC channel. This consists of a sink to which messages can be
/// pushed, and a reply manager through which the corresponding replies
/// can be picked up.
pub struct Channel<Request, Reply> {
    output: Arc<dyn MessageSink<Request>>,
    reply_manager: Arc<ReplyManager<Reply>>,
}

impl<Request, Reply: 'static> Channel<Request, Reply> {
    pub fn new(
        output: Arc<dyn MessageSink<Request>>,
        reply_manager: Arc<ReplyManager<Reply>>,
    ) -> Self {
        Self {
            output,
            reply_manager,
        }
    }

    pub fn call<ExpectedReply: Sync + Send + 'static>(
        &self,
        req: Request,
        xform: fn(Reply) -> RPCResult<ExpectedReply>,
    ) -> Arc<dyn GetResult<ExpectedReply>> {
        let reply_cell = Arc::new(ReplyBuffer::<Reply, ExpectedReply>::new(xform));
        let post_result: Arc<dyn PostResult<Reply> + Sync + Send> = reply_cell.clone();
        let cookie = self.reply_manager.register_reply_cell(post_result);
        self.output.handle(cookie, req);
        reply_cell
    }
}

/// Represents an ongoing RPC call -- this is a "half-sync" object,
/// users can either synchronously wait on the result (suspending
/// current thread, *not* lending it to asyn execution), or they
/// can use it async (suspend and lend current thread to async
/// execution.
pub struct Call<Reply> {
    cell: Arc<dyn GetResult<Reply>>,
}

impl<Reply: 'static> Call<Reply> {
    /// Creates a new call object referred to a prepared reply cell
    /// (generally created through and previously register with a
    /// a ReplyManager).
    pub fn new(cell: Arc<dyn GetResult<Reply>>) -> Self {
        Self { cell }
    }

    /// Creates a new call object that is already resolved to a prepared
    /// result.
    pub fn new_resolved(result: RPCResult<Reply>) -> Self {
        let cell = Arc::new(ReadyResult::new(result));
        Self { cell }
    }

    /// Creates a new call object that adapts the type of an existing
    /// call object and transforms its return value.
    pub fn new_wrap<Source: 'static>(source: Call<Source>, f: fn(Source) -> Reply) -> Self {
        let cell = Arc::new(GetResultAdaptor::new(source.cell, f));
        Self { cell }
    }

    /// Turns this call into an async future. This consumes the call
    /// and allows using the RPC as an async call.
    pub fn future(self) -> Pin<Box<dyn std::future::Future<Output = RPCResult<Reply>> + 'static>> {
        Box::pin(Future {
            cell: self.cell.clone(),
        })
    }

    /// Suspends calling thread and wait on RPC to be completed.
    pub fn sync(self) -> RPCResult<Reply> {
        self.cell.sync()
    }
}

/// Buffer to receive a reply value and make it accessible to the
/// requestor. The input reply value might still be "packed" and in
/// need of transformation to the expected value.
pub struct ReplyBuffer<InputValue, Value> {
    repr: Mutex<ReplyBufferInt<Value>>,
    cond: Condvar,
    xform: fn(InputValue) -> RPCResult<Value>,
}
#[derive(Default)]
struct ReplyBufferInt<Reply> {
    result: Option<RPCResult<Reply>>,
    waker: Option<std::task::Waker>,
}

impl<InputValue, Value: Send + Sync> ReplyBuffer<InputValue, Value> {
    pub fn new(xform: fn(InputValue) -> RPCResult<Value>) -> Self {
        Self {
            repr: Mutex::new(ReplyBufferInt {
                result: None,
                waker: None,
            }),
            cond: Condvar::new(),
            xform,
        }
    }
}

impl<InputValue, Value> PostResult<InputValue> for ReplyBuffer<InputValue, Value> {
    fn post_result(&self, value: RPCResult<InputValue>) {
        let maybe_waker = {
            let mut mut_repr = self.repr.lock().unwrap();
            mut_repr.result = Some(match value {
                Ok(value) => (self.xform)(value),
                Err(err) => Err(err),
            });
            self.cond.notify_all();
            mut_repr.waker.take()
        };
        if let Some(waker) = maybe_waker {
            waker.wake()
        }
    }
}

impl<InputValue, Value> GetResult<Value> for ReplyBuffer<InputValue, Value> {
    fn poll(&self, cx: &mut Context<'_>) -> Poll<RPCResult<Value>> {
        let mut mut_repr = self.repr.lock().unwrap();
        let maybe_result = mut_repr.result.take();
        if let Some(result) = maybe_result {
            Poll::Ready(result)
        } else {
            mut_repr.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn sync(&self) -> RPCResult<Value> {
        let mut mut_cell = self.repr.lock().unwrap();
        loop {
            let maybe_result = mut_cell.result.take();
            if let Some(result) = maybe_result {
                return result;
            } else {
                mut_cell = self.cond.wait(mut_cell).unwrap();
            }
        }
    }
}

/// Mediator into which replies of kind 'Value' can be pushed into and
/// returned to requestors, matched up by cookie.
pub struct ReplyManager<Message> {
    repr: Mutex<ReplyManagerInt<Message>>,
}
struct ReplyManagerInt<Message> {
    /// Requests and replies are matched up using cookies exchanged on
    /// the transport. This value is incremented on each request to
    /// ensure uniqueness (barring wrap-around).
    next_cookie: u64,

    /// Reserved cells to hold the replies, indexed by the cookie
    /// associated with the request.
    cells: std::collections::HashMap<u64, Arc<dyn PostResult<Message> + Sync + Send>>,
}

impl<Message> ReplyManager<Message> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            repr: Mutex::new(ReplyManagerInt {
                next_cookie: 1,
                cells: std::collections::HashMap::new(),
            }),
        }
    }

    fn register_reply_cell(&self, cell: Arc<dyn PostResult<Message> + Sync + Send>) -> u64 {
        let mut mut_repr = self.repr.lock().unwrap();
        let cookie = mut_repr.next_cookie;
        mut_repr.next_cookie = cookie + 1;
        mut_repr.cells.insert(cookie, cell);
        cookie
    }
}

impl<Message> MessageSink<Message> for ReplyManager<Message> {
    fn handle(&self, cookie: u64, msg: Message) {
        let maybe_cell = {
            let mut mut_repr = self.repr.lock().unwrap();
            mut_repr.cells.remove(&cookie)
        };
        if let Some(cell) = maybe_cell {
            cell.post_result(Ok(msg))
        }
    }
}

// Various kinds of RPC results.

/// An RPC result that is immediately "ready" (i.e. pass a value to
/// a caller such that it does not need to wait).

pub struct ReadyResult<Value> {
    value: Mutex<RPCResult<Value>>,
}

impl<Value> ReadyResult<Value> {
    pub fn new(value: RPCResult<Value>) -> Self {
        Self {
            value: Mutex::new(value),
        }
    }
}

impl<Value> GetResult<Value> for ReadyResult<Value> {
    fn poll(&self, _cx: &mut Context<'_>) -> Poll<RPCResult<Value>> {
        Poll::Ready(self.sync())
    }
    fn sync(&self) -> RPCResult<Value> {
        let mut mut_value = self.value.lock().unwrap();
        std::mem::replace(&mut mut_value, Err(Error::ServerError))
    }
}

/// Adapt a result of one kind to another.
pub struct GetResultAdaptor<S, T> {
    inner: Arc<dyn GetResult<S>>,
    f: fn(S) -> T,
}

impl<S, T> GetResultAdaptor<S, T> {
    pub fn new(inner: Arc<dyn GetResult<S>>, f: fn(S) -> T) -> Self {
        Self { inner, f }
    }
}

impl<S, T> GetResult<T> for GetResultAdaptor<S, T> {
    fn poll(&self, cx: &mut Context<'_>) -> Poll<RPCResult<T>> {
        match self.inner.poll(cx) {
            Poll::Ready(result) => Poll::Ready(result.map(self.f)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn sync(&self) -> RPCResult<T> {
        self.inner.sync().map(self.f)
    }
}

/// Adapt a result getter into a std future.
pub struct Future<Value> {
    cell: Arc<dyn GetResult<Value>>,
}

impl<Value> std::future::Future for Future<Value> {
    type Output = RPCResult<Value>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.cell.poll(cx)
    }
}

/// Wrap a demux server plus an outgoing channel such that we can push
/// messages in, the messages are dispatched, and corresponding output
/// messages are sent on the output channel.
pub struct ServerStub<Request: Send + Sync, Reply: Send + Sync + 'static> {
    server: Arc<dyn DemuxServer<Request, Reply>>,
    outgoing: Arc<dyn MessageSink<Reply>>,
}

impl<Request: Send + Sync, Reply: Send + Sync + 'static> ServerStub<Request, Reply> {
    pub fn new(
        server: Arc<dyn DemuxServer<Request, Reply>>,
        outgoing: Arc<dyn MessageSink<Reply>>,
    ) -> Self {
        Self { server, outgoing }
    }
}

impl<Request: Send + Sync, Reply: Send + Sync + 'static> MessageSink<Request>
    for ServerStub<Request, Reply>
{
    fn handle(&self, cookie: u64, req: Request) {
        let reply = self.server.dispatch(req);

        #[allow(clippy::single_match)]
        match reply.sync() {
            Ok(reply) => self.outgoing.handle(cookie, reply),
            Err(_) => (),
        }
    }
}
