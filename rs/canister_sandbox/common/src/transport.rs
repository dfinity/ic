use crate::fdenum::EnumerateInnerFileDescriptors;
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
use std::os::unix::{io::AsRawFd, io::RawFd, net::UnixStream};
use std::sync::{Arc, Condvar, Mutex};

// There are different types used for the msg_controllen member of
// struct cmsghdr -- we presently support Linux and Darwin compilation.
// Add a type alias to allow making correct casts.
#[cfg(target_os = "linux")]
type MsgControlLenType = usize;
#[cfg(not(target_os = "linux"))]
type MsgControlLenType = libc::socklen_t;

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

pub struct UnixStreamMessageWriter<Message: 'static + Serialize + Send> {
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
    fds: Vec<RawFd>,
    sending: bool,
    quit: bool,
    // Phantom data to ensure the writer is correctly parameterized
    // over the type it can write. This needs to be inside the "Int"
    // object to ensure compiler can see it "inside" the mutex
    // (so it doesn't need Sync).
    phantom: PhantomData<Message>,
}

impl<Message: 'static + Serialize + Send + EnumerateInnerFileDescriptors>
    UnixStreamMessageWriter<Message>
{
    fn new(socket: Arc<UnixStream>) -> Arc<Self> {
        let fd = socket.as_raw_fd();
        let instance = Arc::new(UnixStreamMessageWriter {
            state: Mutex::new(UnixStreamMessageWriterInt::<Message> {
                buf: BytesMut::new(),
                fds: vec![],
                sending: false,
                quit: false,
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

    // Precondition: When this function is called, buf MUST NOT be empty.
    fn try_flush(&self, buf: &mut BytesMut, fds: &mut Vec<RawFd>, flags: libc::c_int) {
        #[cfg(target_os = "linux")]
        let flags = flags | libc::MSG_NOSIGNAL;

        // Let's be pedantic here about sending file descriptors:
        // - there is a limited number of file descriptors we can send per message (252,
        //   but let's be conservative), so if we were hypothetically being asked to
        //   send more we need to split this up.
        // - we can only send file descriptors along with at least 1 byte of payload
        //   data
        //
        // AFAICT this situation can never arrive due to the low number
        // of file descriptors we handle with sandbox, but it is not
        // too hard to be pedantically correct, so let's do it.

        let fds_to_send = std::cmp::min(16, fds.len());
        let bytes_to_send = if fds_to_send < fds.len() {
            1
        } else {
            buf.len()
        };

        // Important invariant: we never try to send more than the buffer
        // holds.
        assert!(bytes_to_send <= buf.len());

        // Unsafe section required due to raw handling of buffer contents,
        // calling directly into libc send/recv function. This is done because
        // at the time of writing there was no better way known to the author
        // to perform I/O without either silly thread-bouncing or superfluous
        // locking of read side against write side.
        // Any call to try_flush itself is safe: Internal buffer is managed
        // consistently wrt to result of send (success or failure).
        let num_bytes_sent = unsafe {
            let mut iov = libc::iovec {
                iov_base: buf.as_ptr() as *mut std::ffi::c_void,
                iov_len: bytes_to_send,
            };
            let mut cmsgbuf: [u8; 4096] = [0; 4096];
            let mut hdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: flags,
            };
            if fds_to_send > 0 {
                hdr.msg_control = cmsgbuf.as_mut_ptr() as *mut std::ffi::c_void;
                hdr.msg_controllen =
                    libc::CMSG_SPACE((std::mem::size_of::<RawFd>() * fds_to_send) as u32)
                        as MsgControlLenType;
                let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len =
                    libc::CMSG_LEN((std::mem::size_of::<RawFd>() * fds_to_send) as u32)
                        as MsgControlLenType;
                let data = libc::CMSG_DATA(cmsg);
                for (index, fd) in fds.iter().enumerate().take(fds_to_send) {
                    let dst = std::slice::from_raw_parts_mut(
                        data.add(std::mem::size_of::<RawFd>() * index),
                        std::mem::size_of::<RawFd>(),
                    );
                    dst.copy_from_slice(&RawFd::to_ne_bytes(*fd));
                }
            }

            libc::sendmsg(self.fd, &hdr, flags)
        };
        if num_bytes_sent > 0 {
            // If at least one byte was sent, then it is guaranteed that
            // the ancillary message (file descriptors) were sent
            // along with it.
            buf.advance(num_bytes_sent.try_into().unwrap());
            fds.drain(0..fds_to_send);
        }
    }

    fn thread_flush_fn(&self) {
        loop {
            let (mut buf, mut fds) = {
                let mut guard = self.state.lock().unwrap();
                if guard.quit {
                    return;
                }
                loop {
                    if guard.buf.is_empty() {
                        guard.sending = false;
                        guard = self.trigger_send.wait(guard).unwrap();
                    } else {
                        break (guard.buf.split(), std::mem::take(&mut guard.fds));
                    }
                }
            };
            while !buf.is_empty() {
                // Precondition of try_flush satisfied by loop check.
                self.try_flush(&mut buf, &mut fds, 0);
            }
        }
    }

    fn write_frame(&self, data: &[u8], fds: &[RawFd]) {
        // If we are writing any file descriptors, then we must also
        // write some data down to the socket. Ensure that nobody tries
        // sending file descriptors without at least one byte of data
        // per descriptor.
        // This is "given" because we serialize some "fake" integer
        // with every descriptor we pass.
        assert!(data.len() >= fds.len());

        // If someone asks us to send a zero-size frame (not going to
        // happen, but still), just bail out early. This satisfies
        // the invariant below.
        if data.is_empty() {
            return;
        }

        let mut guard = self.state.lock().unwrap();
        let mut state = &mut *guard;
        state.buf.put_u32(data.len() as u32);
        state.buf.extend_from_slice(data);
        state.fds.extend_from_slice(fds);
        if !state.sending {
            // The buffer cannot be empty at this point because we
            // put at least one byte in. This satisfies the precondition
            // of try_flush.
            self.try_flush(&mut state.buf, &mut state.fds, libc::MSG_DONTWAIT);
            if !state.buf.is_empty() {
                state.sending = true;
                self.trigger_send.notify_one();
            }
        }
    }

    pub fn stop(&self) {
        let mut guard = self.state.lock().unwrap();
        guard.quit = true;
        self.trigger_send.notify_one();
    }
}

impl<
        Message: 'static + Serialize + Send + EnumerateInnerFileDescriptors,
        M: MuxInto<Message> + 'static + Send,
    > MessageSink<M> for UnixStreamMessageWriter<Message>
{
    fn handle(&self, cookie: u64, msg: M) {
        let mut msg: Message = msg.wrap(cookie);
        // Extract file descriptors from the struct we want to send.
        let mut fd_locs = vec![];
        msg.enumerate_fds(&mut fd_locs);
        let fds: Vec<RawFd> = fd_locs.iter().map(|fd| **fd).collect();

        // Serialize the message.
        let serialized_msg = serde_cbor::to_vec(&msg).expect("Failed to serialize message");

        // Send message data + file descriptors down.
        // There must be a field in the struct for every file descriptor
        // that we send, so the amount of data in the message is
        // always strictly larger than the number of file descriptors
        // we send. This satisfies the invariant of write_frame.
        self.write_frame(&serialized_msg, &fds);
    }
}

/// Multiplex writer for different kinds of messages over a unix domain
/// socket.
pub struct UnixStreamMuxWriter<Message: 'static + Serialize + Send> {
    repr: Arc<UnixStreamMessageWriter<Message>>,
}

impl<Message: 'static + Serialize + Send + EnumerateInnerFileDescriptors>
    UnixStreamMuxWriter<Message>
{
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

fn install_file_descriptors<Message: EnumerateInnerFileDescriptors>(
    msg: &mut Message,
    fds: &mut Vec<RawFd>,
) {
    let mut fd_locs = vec![];
    msg.enumerate_fds(&mut fd_locs);
    for n in 0..fd_locs.len() {
        if n < fds.len() {
            *fd_locs[n] = fds[n];
        } else {
            *fd_locs[n] = -1;
        }
    }
    if fd_locs.len() < fds.len() {
        fds.drain(0..fd_locs.len());
    } else {
        fds.clear();
    }
}

/// Reads from a unix stream socket and passes individual messages
/// to given handler.
pub fn socket_read_messages<
    Message: DeserializeOwned + EnumerateInnerFileDescriptors + Clone,
    Handler: Fn(Message),
>(
    handler: Handler,
    socket: Arc<UnixStream>,
) {
    const MIN_READ_SIZE: usize = 16384;
    const INITIAL_SIZE: usize = 65536;
    let fd = socket.as_raw_fd();
    let mut decoder = FrameDecoder::<Message>::new();
    let mut buf = BytesMut::with_capacity(INITIAL_SIZE);
    let mut fds = Vec::<RawFd>::new();
    loop {
        while let Some(mut frame) = decoder.decode(&mut buf) {
            install_file_descriptors(&mut frame, &mut fds);
            handler(frame);
        }
        buf.reserve(MIN_READ_SIZE);
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
        let num_bytes_received = unsafe {
            let mut iov = libc::iovec {
                iov_base: p.add(buf.len()) as *mut std::ffi::c_void,
                iov_len: buf.capacity() - buf.len(),
            };
            let mut cmsgbuf: [u8; 4096] = [0; 4096];
            let mut hdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                msg_control: cmsgbuf.as_mut_ptr() as *mut std::ffi::c_void,
                msg_controllen: 4096,
                msg_flags: flags,
            };
            let num_bytes_received = libc::recvmsg(fd, &mut hdr, flags);
            if num_bytes_received > 0 && hdr.msg_controllen > 0 {
                let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    {
                        let data = libc::CMSG_DATA(cmsg);
                        let len = (*cmsg).cmsg_len - libc::CMSG_LEN(0) as MsgControlLenType;
                        let mut pos = 0;
                        while pos + 4 <= len {
                            let src = std::slice::from_raw_parts(data.add(pos as usize), 4);
                            let mut raw: [libc::c_uchar; 4] = [0, 0, 0, 0];
                            raw.copy_from_slice(src);
                            let fd = RawFd::from_ne_bytes(raw);
                            fds.push(fd);
                            pos += 4;
                        }
                    }
                    cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
                }
            }
            num_bytes_received
        };
        if num_bytes_received > 0 {
            // The unsafe section is required because data was read into the buffer
            // (in above unsafe section). This is actually known to be correctly
            // initialized by system call already.
            unsafe {
                buf.set_len(buf.len() + (num_bytes_received as usize));
            }
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::io::FromRawFd;
    use std::sync::mpsc::sync_channel;

    #[derive(Serialize, Deserialize, Clone)]
    struct TestMessage {
        fd: std::os::unix::io::RawFd,
    }

    impl MuxInto<TestMessage> for TestMessage {
        fn wrap(self, _cookie: u64) -> TestMessage {
            self
        }
    }

    impl EnumerateInnerFileDescriptors for TestMessage {
        fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut RawFd>) {
            fds.push(&mut self.fd);
        }
    }

    #[test]
    fn file_descriptor_passing() {
        // Create a socketpair through which we will communicate.
        let (comm_send, comm_recv) = std::os::unix::net::UnixStream::pair().unwrap();
        let comm_send = Arc::new(comm_send);
        let comm_recv = Arc::new(comm_recv);

        // Create another socketpair -- one of these descriptors will
        // be sent through the channel established by the other 2.
        let (mut test_send, test_recv) = std::os::unix::net::UnixStream::pair().unwrap();

        // Set up sender (to send via "comm_send".
        let sender = UnixStreamMessageWriter::<TestMessage>::new(comm_send);

        // Set up receiver thread (to receive via "comm_recv") and
        // channel to pass result back to test thread.
        let (ch_sender, ch_receiver) = sync_channel::<TestMessage>(1);
        std::thread::spawn(move || {
            socket_read_messages(
                |message: TestMessage| {
                    ch_sender.send(message).unwrap();
                },
                comm_recv,
            );
        });

        // Now send a message passing our file descriptor.
        sender.handle(
            0,
            TestMessage {
                fd: test_recv.as_raw_fd(),
            },
        );

        // Receive message.
        let message = ch_receiver.recv().unwrap();

        // Can stop sender now, don't need it anymore.
        sender.stop();

        // We have now received a new file descriptor that is a duplicate
        // of test_recv. We will close test_recv now, pass something
        // through test_send and receive it through our newly received
        // descriptor to validate that the file descriptor was passed
        // correctly.

        // Newly file descriptor must not be same as old one (receiving
        // must have created a copy).
        assert_ne!(message.fd, test_recv.as_raw_fd());
        drop(test_recv);

        // Convert raw descriptor into socket again.
        let mut test_recv_dup = unsafe { std::os::unix::net::UnixStream::from_raw_fd(message.fd) };

        // Send a test message along test_send -- flush and close socket
        // so receiver terminates.
        test_send.write_all(b"Hello").unwrap();
        test_send.flush().unwrap();
        drop(test_send);

        // Read from the file descriptor received.
        let mut response = String::new();
        test_recv_dup.read_to_string(&mut response).unwrap();
        assert_eq!("Hello", response);
    }
}
