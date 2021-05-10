use crate::frame_decoder::FrameDecoder;
use crate::rpc::MessageSink;

use bytes::{
    buf::{Buf, BufMut},
    BytesMut,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::convert::TryInto;
use std::marker::PhantomData;
use std::os::unix::{io::AsRawFd, net::UnixStream};
use std::sync::{Arc, Condvar, Mutex};

/// Two alternatives for a message kind: An RPC request or a reply.
pub enum RequestOrReply<Request, Reply> {
    Request(Request),
    Reply(Reply),
}

/// Disassemble a tagged message (carries a cookie) and classify it
/// as either Request or Reply (also allowing for third "nothing at all"
/// state in case of something incomprehensible). Cookies are used by
/// the transport layer to associate Replies with Requests on the
/// corresponding reverse channel.
pub trait MessageDemux<Request, Reply> {
    fn split(self) -> Option<(u64, RequestOrReply<Request, Reply>)>;
}

/// Reverse, multiplex request or reply into a generic message.
pub trait MuxInto<Message> {
    fn wrap(self, cookie: u64) -> Message;
}

/// Demultiplex stream into "requests" and "replies". Both are forwarded
/// to different handlers -- generally, requests will go to RPC
/// handler implementation, replies will go into a reply buffer.
pub struct Demux<Request, Reply, Message: MessageDemux<Request, Reply>> {
    /// Targets to split messages to.
    request_handler: Arc<dyn MessageSink<Request>>,
    reply_handler: Arc<dyn MessageSink<Reply>>,

    /// We need this parameterized by kind of envelope message to
    /// facilitate splitting.
    phantom: std::marker::PhantomData<Message>,
}

impl<Request, Reply, Message: MessageDemux<Request, Reply>> Demux<Request, Reply, Message> {
    pub fn new(
        request_handler: Arc<dyn MessageSink<Request>>,
        reply_handler: Arc<dyn MessageSink<Reply>>,
    ) -> Self {
        Self {
            request_handler,
            reply_handler,
            phantom: std::marker::PhantomData {},
        }
    }

    pub fn handle(&self, msg: Message) {
        if let Some((cookie, item)) = msg.split() {
            match item {
                RequestOrReply::Request(req) => {
                    self.request_handler.handle(cookie, req);
                }
                RequestOrReply::Reply(rep) => self.reply_handler.handle(cookie, rep),
            }
        }
    }
}

struct UnixStreamMessageWriter<Message: 'static + Serialize + Send> {
    state: Mutex<UnixStreamMessageWriterInt<Message>>,
    // Keep reference to stream object so it will kept alive for as
    // long as this object is alive. Actual access is through the "raw"
    // fd (we otherwise have problem with concurrent access through
    // same fd).
    _socket: Arc<UnixStream>,
    fd: libc::c_int,
    trigger_send: Condvar,
}
struct UnixStreamMessageWriterInt<Message: 'static + Send> {
    buf: BytesMut,
    sending: bool,
    // Phantom data to ensure the writer is correctly parameterized
    // over the type it can write. This needs to be inside the "Int"
    // object to ensure compiler can see it "inside" the mutex
    // (so it doesn't need Sync).
    phantom: PhantomData<Message>,
}

impl<Message: 'static + Serialize + Send> UnixStreamMessageWriter<Message> {
    fn new(socket: Arc<UnixStream>) -> Arc<Self> {
        let fd = socket.as_raw_fd();
        let instance = Arc::new(UnixStreamMessageWriter {
            state: Mutex::new(UnixStreamMessageWriterInt::<Message> {
                buf: BytesMut::new(),
                sending: false,
                phantom: PhantomData,
            }),
            _socket: socket,
            fd,
            trigger_send: Condvar::new(),
        });
        let copy_instance = Arc::clone(&instance);
        std::thread::spawn(move || {
            copy_instance.thread_flush_fn();
        });
        instance
    }

    fn try_flush(&self, buf: &mut BytesMut, flags: libc::c_int) {
        #[cfg(target_os = "linux")]
        let flags = flags | libc::MSG_NOSIGNAL;
        // Unsafe section required due to raw handling of buffer contents,
        // calling directly into libc send/recv function. This is done because
        // at the time of writing there was no better way known to the author
        // to perform I/O without either silly thread-bouncing or superfluous
        // locking of read side against write side.
        // Any call to try_flush itself is safe: Internal buffer is managed
        // consistently wrt to result of send (success or failure).
        let count = unsafe {
            libc::send(
                self.fd,
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len(),
                flags,
            )
        };
        if count > 0 {
            buf.advance(count.try_into().unwrap());
        }
    }

    fn thread_flush_fn(&self) {
        loop {
            let mut buf = {
                let mut guard = self.state.lock().unwrap();
                loop {
                    if guard.buf.is_empty() {
                        guard.sending = false;
                        guard = self.trigger_send.wait(guard).unwrap();
                    } else {
                        break guard.buf.split();
                    }
                }
            };
            while !buf.is_empty() {
                self.try_flush(&mut buf, 0);
            }
        }
    }

    fn write_frame(&self, data: &[u8]) {
        let mut guard = self.state.lock().unwrap();
        guard.buf.put_u32(data.len() as u32);
        guard.buf.extend_from_slice(data);
        if !guard.sending {
            self.try_flush(&mut guard.buf, libc::MSG_DONTWAIT);
            if !guard.buf.is_empty() {
                guard.sending = true;
                self.trigger_send.notify_one();
            }
        }
    }
}

impl<Message: 'static + Serialize + Send, M: MuxInto<Message> + 'static + Send> MessageSink<M>
    for UnixStreamMessageWriter<Message>
{
    fn handle(&self, cookie: u64, msg: M) {
        let msg: Message = msg.wrap(cookie);
        let serialized_msg = serde_cbor::to_vec(&msg).expect("Failed to serialize message");
        self.write_frame(&serialized_msg);
    }
}

/// Multiplex writer for different kinds of messages over a unix domain
/// socket.
pub struct UnixStreamMuxWriter<Message: 'static + Serialize + Send> {
    repr: Arc<UnixStreamMessageWriter<Message>>,
}

impl<Message: 'static + Serialize + Send> UnixStreamMuxWriter<Message> {
    pub fn new(socket: Arc<UnixStream>) -> Self {
        let repr = UnixStreamMessageWriter::new(socket);
        Self { repr }
    }

    pub fn make_sink<M: MuxInto<Message> + 'static + Send>(
        &self,
    ) -> Arc<dyn MessageSink<M> + Sync + Send> {
        self.repr.clone()
    }
}

/// Reads from a unix stream socket and demultiplex messages to handlers.
pub fn socket_read_demux<
    Request,
    Reply,
    Message: MessageDemux<Request, Reply> + DeserializeOwned + Clone,
>(
    hdl: Demux<Request, Reply, Message>,
    socket: Arc<UnixStream>,
) {
    let fd = socket.as_raw_fd();
    let mut decoder = FrameDecoder::<Message>::new();
    let mut buf = BytesMut::new();
    loop {
        while let Some(frame) = decoder.decode(&mut buf) {
            hdl.handle(frame);
        }
        if buf.capacity() < 4096 {
            buf.reserve(4096);
        }
        let p = buf.as_mut_ptr();
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_NOSIGNAL;
        // The unsafe section is required due to raw handling of buffer contents,
        // calling directly into libc send/recv function. This is done because
        // at the time of writing there was no better way known to the author
        // to perform I/O without either silly thread-bouncing or superfluous
        // locking of read side against write side.
        let count = unsafe {
            libc::recv(
                fd,
                p.add(buf.len()) as *mut std::ffi::c_void,
                buf.capacity(),
                flags,
            )
        };
        if count > 0 {
            // The unsafe section is required because data was read into the buffer
            // (in above unsafe section). This is actually known to be correctly
            // initialized by system call already.
            unsafe {
                buf.set_len(buf.len() + (count as usize));
            }
        } else {
            break;
        }
    }
}
