use crate::fdenum::EnumerateInnerFileDescriptors;
use crate::frame_decoder::FrameDecoder;
use crate::rpc::MessageSink;

use bytes::{
    buf::{Buf, BufMut},
    BytesMut,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::marker::PhantomData;
use std::os::unix::{io::AsRawFd, io::RawFd, net::UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::{convert::TryInto, time::Duration};

// The maximum number of file descriptors that can be sent in a single message.
const MAX_NUM_FD_PER_MESSAGE: usize = 16;
// The size of the control message buffer that is used to send file descriptors.
// It should be large enough to store `MAX_NUM_FD_PER_MESSAGE` file descriptors.
const CONTROL_MESSAGE_SIZE: usize = 4096;
// The initial capacity of buffers for sending and receiving data bytes.
const INITIAL_BUFFER_CAPACITY: usize = 65536;
// The minimum buffer capacity for reading in `recv_msg()`.
const MIN_READ_BUFFER_CAPACITY: usize = 16384;

// The timeout after which the IPC buffers are trimmed.
const IDLE_TIMEOUT_TO_TRIM_BUFFER: Duration = Duration::from_secs(50);

// The timeout after which `libc::malloc_trim()` is called to unmap free pages
// of the malloc allocator. Note that this timeout should be higher than
// `IDLE_TIMEOUT_TO_TRIM_BUFFER` to achieve maximum memory reduction.
const IDLE_TIMEOUT_TO_TRIM_MALLOC: Duration = Duration::from_secs(100);

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
    socket: Arc<UnixStream>,
    trigger_background_sending: Condvar,
}
struct UnixStreamMessageWriterInt<Message: 'static + Send> {
    buf: BytesMut,
    fds: Vec<RawFd>,
    sending_in_background: bool,
    quit_requested: bool,
    // This is needed only for testing.
    number_of_timeouts: usize,
    // Phantom data to ensure the writer is correctly parameterized
    // over the type it can write. This needs to be inside the "Int"
    // object to ensure compiler can see it "inside" the mutex
    // (so it doesn't need Sync).
    phantom: PhantomData<Message>,
}

impl<Message: 'static + Serialize + Send + EnumerateInnerFileDescriptors>
    UnixStreamMessageWriter<Message>
{
    fn new(socket: Arc<UnixStream>, idle_timeout_to_trim_buffer: Duration) -> Arc<Self> {
        let instance = Arc::new(UnixStreamMessageWriter {
            state: Mutex::new(UnixStreamMessageWriterInt::<Message> {
                buf: BytesMut::new(),
                fds: vec![],
                sending_in_background: false,
                quit_requested: false,
                number_of_timeouts: 0,
                phantom: PhantomData,
            }),
            socket,
            trigger_background_sending: Condvar::new(),
        });
        let copy_instance = Arc::clone(&instance);
        std::thread::spawn(move || {
            copy_instance.background_sending_thread(idle_timeout_to_trim_buffer);
        });
        instance
    }

    fn background_sending_thread(&self, idle_timeout_to_free_buffer: Duration) {
        // This predicate corresponds to the `trigger_background_sending`
        // condition variable.
        let awaiting_input = |guard: &mut UnixStreamMessageWriterInt<_>| {
            guard.buf.is_empty() && !guard.quit_requested
        };

        loop {
            let (mut buf, mut fds) = {
                let mut guard = self.state.lock().unwrap();
                if awaiting_input(&mut guard) {
                    guard.sending_in_background = false;
                    let result = self
                        .trigger_background_sending
                        .wait_timeout_while(guard, idle_timeout_to_free_buffer, awaiting_input)
                        .unwrap();
                    guard = result.0;
                    if result.1.timed_out() && awaiting_input(&mut guard) {
                        guard.number_of_timeouts += 1;
                        // Trim the buffer and then wait without any timeout.
                        guard.buf = BytesMut::new();
                        guard = self
                            .trigger_background_sending
                            .wait_while(guard, awaiting_input)
                            .unwrap();
                    }
                    assert!(!awaiting_input(&mut guard));
                }
                if guard.quit_requested {
                    return;
                }
                (guard.buf.split(), std::mem::take(&mut guard.fds))
            };
            while !buf.is_empty() {
                send_message(&self.socket, &mut buf, &mut fds, 0);
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
        let state = &mut *guard;
        state.buf.put_u64(data.len() as u64);
        state.buf.extend_from_slice(data);
        state.fds.extend_from_slice(fds);
        if !state.sending_in_background {
            send_message(
                &self.socket,
                &mut state.buf,
                &mut state.fds,
                libc::MSG_DONTWAIT,
            );
            if !state.buf.is_empty() {
                state.sending_in_background = true;
                self.trigger_background_sending.notify_one();
            }
        }
    }

    pub fn stop(&self) {
        let mut guard = self.state.lock().unwrap();
        guard.quit_requested = true;
        self.trigger_background_sending.notify_one();
    }

    // A helper for testing.
    #[cfg(test)]
    fn number_of_timeouts(&self) -> usize {
        let guard = self.state.lock().unwrap();
        guard.number_of_timeouts
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
        let serialized_msg = bincode::serialize(&msg).expect("Failed to serialize message");

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
        let repr = UnixStreamMessageWriter::new(socket, IDLE_TIMEOUT_TO_TRIM_BUFFER);
        Self { repr }
    }

    pub fn make_sink<M: MuxInto<Message> + 'static + Send>(
        &self,
    ) -> Arc<dyn MessageSink<M> + Sync + Send> {
        self.repr.clone()
    }

    pub fn stop(&self) {
        self.repr.stop();
    }
}

/// Config for `socket_read_messages()` function.
/// It controls idle time trimming of the reader buffer and unmapping of free
/// pages of the malloc allocator.
pub struct SocketReaderConfig {
    // Specifies whether to call `libc::malloc_trim()` or not when
    // the socket becomes idle.
    idle_malloc_trim: bool,
    // Specifies the timeout after which the socket is considered idle.
    idle_timeout: Duration,
}

impl Default for SocketReaderConfig {
    fn default() -> Self {
        Self {
            // We don't trim malloc by default because it is an expensive operation.
            // Moreover, the replica process uses jemalloc for which `malloc_trim`
            // is a no-op.
            idle_malloc_trim: false,
            idle_timeout: IDLE_TIMEOUT_TO_TRIM_BUFFER,
        }
    }
}

impl SocketReaderConfig {
    pub fn for_sandbox() -> Self {
        Self {
            idle_malloc_trim: true,
            idle_timeout: IDLE_TIMEOUT_TO_TRIM_MALLOC,
        }
    }

    pub fn for_testing() -> Self {
        Self {
            idle_malloc_trim: true,
            idle_timeout: Duration::from_secs(0),
        }
    }
}

// A helper to read messages from a socket with a timeout.
// It uses the `libc::setsockopt()` syscall to set the timeout and keeps track
// of the currently set timeout in order to reduce the number of syscalls.
struct SocketReaderWithTimeout {
    socket: Arc<UnixStream>,
    socket_timeout: Option<Duration>,
}

impl SocketReaderWithTimeout {
    fn new(socket: Arc<UnixStream>) -> Self {
        Self {
            socket,
            socket_timeout: None,
        }
    }

    // A wrapper around the standalone `receive_message()` function.
    // It takes an additional `timeout` parameter and returns `None`
    // if no message was read within the given timeout.
    // Otherwise, it returns the result of the wrapped function.
    fn receive_message(
        &mut self,
        buf: &mut BytesMut,
        fds: &mut Vec<RawFd>,
        flags: libc::c_int,
        timeout: Option<Duration>,
    ) -> Option<isize> {
        let result = self.update_socket_timeout(timeout);
        if let Err(err) = result {
            // We didn't manage to update the timeout. Since timeout is used
            // for optimization and not for correctness, we can continue
            // without crashing and let `recvmsg` handle `EWOULDBLOCK`.
            eprintln!("Failed to update sandbox IPC socket timeout: {}", err);
        }
        let num_bytes_received = receive_message(&self.socket, buf, fds, flags);
        if num_bytes_received == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            return None;
        }
        Some(num_bytes_received)
    }

    fn update_socket_timeout(&mut self, timeout: Option<Duration>) -> Result<(), std::io::Error> {
        if timeout == self.socket_timeout {
            // The fast path to avoid making the syscall to update the socket
            // timeout to the same value.
            return Ok(());
        }

        let (tv_sec, tv_usec) = match timeout {
            None => (0, 0),
            Some(dur) => {
                let tv_sec = dur.as_secs() as libc::time_t;
                let tv_usec = dur.subsec_micros() as libc::suseconds_t;
                if tv_sec == 0 && tv_usec == 0 {
                    // `setsockopt` interprets `(0, 0)` as no timeout,
                    // so we need to take the next smallest value.
                    (tv_sec, tv_usec + 1)
                } else {
                    (tv_sec, tv_usec)
                }
            }
        };

        let tv = libc::timeval { tv_sec, tv_usec };

        // SAFETY: All parameters are valid.
        let result = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };

        if result == 0 {
            self.socket_timeout = timeout;
            Ok(())
        } else {
            // OS error 9 corresponds to the `BAD_FILE_DESCRIPTOR` error.
            // This error may happen here if the main process terminates the
            // sandbox process and immediately closes the socket while the
            // sandbox process is attempting to update socket timeout here.
            //
            // Note that this is likely to happen in tests that create many
            // `SandboxedExecutionController`s and sandbox processes.
            const BAD_FILE_DESCRIPTOR: i32 = 9;
            let err = std::io::Error::last_os_error();

            // Any error besides `BAD_FILE_DESCRIPTOR` is unexpected.
            debug_assert_eq!(
                err.raw_os_error(),
                Some(BAD_FILE_DESCRIPTOR),
                "setsockopt failed with result={}, error={}, kind={:?}, code={:?}",
                result,
                err,
                err.kind(),
                err.raw_os_error()
            );
            Err(err)
        }
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
    config: SocketReaderConfig,
) {
    let mut decoder = FrameDecoder::<Message>::new();
    let mut buf = BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY);
    let mut fds = Vec::<RawFd>::new();
    let mut reader = SocketReaderWithTimeout::new(socket);
    loop {
        while let Some(mut frame) = decoder.decode(&mut buf) {
            install_file_descriptors(&mut frame, &mut fds);
            handler(frame);
        }

        let num_bytes_received =
            match reader.receive_message(&mut buf, &mut fds, 0, Some(config.idle_timeout)) {
                Some(bytes) => bytes,
                None => {
                    // The operation has timed out.
                    // Trim the buffer and trim malloc if needed.
                    if buf.is_empty() {
                        buf = BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY);
                        if config.idle_malloc_trim {
                            // SAFETY: 0 is always a valid argument to `malloc_trim`.
                            #[cfg(target_os = "linux")]
                            unsafe {
                                libc::malloc_trim(0);
                            }
                        }
                    }
                    // Read the message without any timeout.
                    // The loop is not strictly necessary, but we keep it in
                    // order to make the code robust against failures in
                    // updating the socket timeout.
                    loop {
                        if let Some(bytes) = reader.receive_message(&mut buf, &mut fds, 0, None) {
                            break (bytes);
                        }
                    }
                }
            };

        if num_bytes_received <= 0 {
            break;
        }
    }
}

/// A helper that write the given file descriptors into the file descriptor
/// slots of the given message in the same order defined by `enumerate_fds()`.
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

/// A helper that writes bytes and file descriptors to the given socket.
///
/// It is a wrapper around `libc::sendmsg()` and returns the result of that
/// syscall (which is the number of bytes sent or -1 on error).
///
/// If sending is successful, then the function removes the sent bytes and file
/// descriptors from the given `buf` and `fds`.
///
/// Preconditions:
/// - The number of file descriptors must not exceed the number of data bytes in
///   the buffer. That's because `libc::sendmsg()` can only send file descriptors
///   along with at least 1 byte of payload data.
fn send_message(
    socket: &UnixStream,
    buf: &mut BytesMut,
    fds: &mut Vec<RawFd>,
    flags: libc::c_int,
) -> isize {
    #[cfg(target_os = "linux")]
    let flags = flags | libc::MSG_NOSIGNAL;

    assert!(buf.len() >= fds.len());

    if buf.is_empty() {
        return 0;
    }

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

    let fds_to_send = std::cmp::min(MAX_NUM_FD_PER_MESSAGE, fds.len());
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
    let num_bytes_sent = unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut std::ffi::c_void,
            iov_len: bytes_to_send,
        };
        let mut cmsgbuf: [u8; CONTROL_MESSAGE_SIZE] = [0; CONTROL_MESSAGE_SIZE];
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
            assert!(
                hdr.msg_controllen <= cmsgbuf.len() as MsgControlLenType,
                "Control message buffer overflow: {} > {}",
                hdr.msg_controllen,
                cmsgbuf.len(),
            );
            let cmsg = libc::CMSG_FIRSTHDR(&hdr);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN((std::mem::size_of::<RawFd>() * fds_to_send) as u32)
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

        libc::sendmsg(socket.as_raw_fd(), &hdr, flags)
    };
    if num_bytes_sent > 0 {
        // If at least one byte was sent, then it is guaranteed that
        // the ancillary message (file descriptors) were sent
        // along with it.
        buf.advance(num_bytes_sent.try_into().unwrap());
        fds.drain(0..fds_to_send);
    }

    num_bytes_sent
}

/// A helper that reads bytes and file descriptors from the given socket.
///
/// It is a wrapper around `libc::recvmsg()` and returns the result of that
/// syscall (which is the number of bytes read or -1 on error).
///
/// If reading is successful, then the function pushes the read bytes and file
/// descriptors onto the given `buf` and `fds`.
fn receive_message(
    socket: &UnixStream,
    buf: &mut BytesMut,
    fds: &mut Vec<RawFd>,
    flags: libc::c_int,
) -> isize {
    #[cfg(target_os = "linux")]
    let flags = flags | libc::MSG_NOSIGNAL;

    buf.reserve(MIN_READ_BUFFER_CAPACITY);

    // The unsafe section is required due to raw handling of buffer contents,
    // calling directly into libc send/recv function. This is done because
    // at the time of writing there was no better way known to the author
    // to perform I/O without either silly thread-bouncing or superfluous
    // locking of read side against write side.
    unsafe {
        let buf_start = buf.as_mut_ptr();
        let mut iov = libc::iovec {
            iov_base: buf_start.add(buf.len()) as *mut std::ffi::c_void,
            iov_len: buf.capacity() - buf.len(),
        };
        let mut cmsgbuf: [u8; CONTROL_MESSAGE_SIZE] = [0; CONTROL_MESSAGE_SIZE];
        let mut hdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsgbuf.as_mut_ptr() as *mut std::ffi::c_void,
            msg_controllen: cmsgbuf.len() as MsgControlLenType,
            msg_flags: flags,
        };

        let num_bytes_received = libc::recvmsg(socket.as_raw_fd(), &mut hdr, flags);

        if num_bytes_received > 0 {
            // Update the buffer length to account for the received bytes.
            buf.set_len(buf.len() + (num_bytes_received as usize));

            // Push received file descriptors.
            if hdr.msg_controllen > 0 {
                let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    {
                        let data = libc::CMSG_DATA(cmsg);
                        let len = (*cmsg).cmsg_len - libc::CMSG_LEN(0) as MsgControlLenType;
                        let mut pos = 0;
                        while pos + 4 <= len {
                            // Allow `unnecessary_cast` because `len` is `usize`
                            // for linux and `u32` for darwin.
                            #[allow(clippy::unnecessary_cast)]
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
        }
        num_bytes_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::env::temp_dir;
    use std::fs::File;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
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
        let sender =
            UnixStreamMessageWriter::<TestMessage>::new(comm_send, IDLE_TIMEOUT_TO_TRIM_BUFFER);

        // Set up receiver thread (to receive via "comm_recv") and
        // channel to pass result back to test thread.
        let (ch_sender, ch_receiver) = sync_channel::<TestMessage>(1);
        std::thread::spawn(move || {
            socket_read_messages(
                |message: TestMessage| {
                    ch_sender.send(message).unwrap();
                },
                comm_recv,
                SocketReaderConfig::for_testing(),
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

    #[test]
    fn send_and_receive_single_message() {
        let (send, recv) = std::os::unix::net::UnixStream::pair().unwrap();

        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temp_dir().join("file"))
            .unwrap();
        file.write_all(b"Hello").unwrap();

        let mut send_fds = Vec::new();
        send_fds.push(file.as_raw_fd());

        let mut send_buf = BytesMut::new();
        send_buf.extend_from_slice(&[42; 1]);

        let mut recv_buf = BytesMut::new();
        let mut recv_fds = Vec::new();

        let res = send_message(&send, &mut send_buf, &mut send_fds, 0);
        assert_eq!(res, 1);

        let res = receive_message(&recv, &mut recv_buf, &mut recv_fds, 0);
        assert_eq!(res, 1);
        assert_eq!(recv_buf.iter().copied().collect::<Vec<_>>(), vec![42; 1]);
        assert_eq!(recv_fds.len(), 1);
        let mut file = unsafe { File::from_raw_fd(recv_fds[0]) };
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn send_and_receive_many_messages() {
        let (send, recv) = std::os::unix::net::UnixStream::pair().unwrap();

        let mut files = Vec::new();
        for i in 0..1000 {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(temp_dir().join(format!("file-{}", i)))
                .unwrap();
            file.write_all(format!("msg-{}", i).as_bytes()).unwrap();
            files.push(file);
        }

        let mut send_buf = BytesMut::new();
        send_buf.extend_from_slice(&[42; 1000]);
        let mut send_fds = files.iter().map(|f| f.as_raw_fd()).collect();

        let mut recv_buf = BytesMut::new();
        let mut recv_fds = Vec::new();

        let mut messages = 0;
        loop {
            let res = send_message(&send, &mut send_buf, &mut send_fds, 0);
            if res == 0 {
                break;
            }
            messages += 1;
        }

        for _ in 0..messages {
            let res = receive_message(&recv, &mut recv_buf, &mut recv_fds, 0);
            assert!(res > 0);
        }
        assert_eq!(recv_buf.iter().copied().collect::<Vec<_>>(), vec![42; 1000]);
        assert_eq!(recv_fds.len(), 1000);
        for (i, fd) in recv_fds.into_iter().enumerate() {
            let mut file = unsafe { File::from_raw_fd(fd) };
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut s = String::new();
            file.read_to_string(&mut s).unwrap();
            assert_eq!(s, format!("msg-{}", i));
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct StringMessage {
        payload: String,
    }

    impl MuxInto<StringMessage> for StringMessage {
        fn wrap(self, _cookie: u64) -> StringMessage {
            self
        }
    }

    impl EnumerateInnerFileDescriptors for StringMessage {
        fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut RawFd>) {}
    }

    #[test]
    fn sender_timeout() {
        // Create a socketpair through which we will communicate.
        let (comm_send, comm_recv) = std::os::unix::net::UnixStream::pair().unwrap();
        let comm_send = Arc::new(comm_send);
        let comm_recv = Arc::new(comm_recv);

        // Set up sender (to send via "comm_send".
        let sender =
            UnixStreamMessageWriter::<StringMessage>::new(comm_send, Duration::from_millis(1));

        // Set up receiver thread (to receive via "comm_recv") and
        // channel to pass result back to test thread.
        let (ch_sender, ch_receiver) = sync_channel::<StringMessage>(1);
        std::thread::spawn(move || {
            socket_read_messages(
                |message: StringMessage| {
                    ch_sender.send(message).unwrap();
                },
                comm_recv,
                SocketReaderConfig::for_testing(),
            );
        });

        // Send and receive the message.
        sender.handle(
            0,
            StringMessage {
                payload: String::from_utf8(vec![b'1'; 1_000_000]).unwrap(),
            },
        );
        let message1 = ch_receiver.recv().unwrap();

        // Give some time for the background sender to timeout.
        std::thread::sleep(Duration::from_millis(100));

        // Send and receive the message again.
        sender.handle(
            0,
            StringMessage {
                payload: String::from_utf8(vec![b'2'; 1_000]).unwrap(),
            },
        );
        let message2 = ch_receiver.recv().unwrap();

        // Can stop sender now, don't need it anymore.
        sender.stop();

        assert!(sender.number_of_timeouts() > 0);
        assert_eq!(
            message1.payload,
            String::from_utf8(vec![b'1'; 1_000_000]).unwrap()
        );
        assert_eq!(
            message2.payload,
            String::from_utf8(vec![b'2'; 1_000]).unwrap()
        );
    }

    #[test]
    fn reader_timeout() {
        // Create a socketpair through which we will communicate.
        let (comm_send, comm_recv) = std::os::unix::net::UnixStream::pair().unwrap();

        let mut reader = SocketReaderWithTimeout::new(Arc::new(comm_recv));

        let mut recv_buf = BytesMut::new();
        let mut recv_fds = vec![];
        let bytes = reader.receive_message(
            &mut recv_buf,
            &mut recv_fds,
            0,
            Some(Duration::from_secs(0)),
        );
        assert_eq!(bytes, None);

        let mut send_buf = BytesMut::new();
        send_buf.extend_from_slice(&[42; 1000]);
        let mut send_fds = vec![];
        let bytes = send_message(&comm_send, &mut send_buf, &mut send_fds, 0);
        assert_eq!(bytes, 1000);

        let bytes = reader.receive_message(
            &mut recv_buf,
            &mut recv_fds,
            0,
            Some(Duration::from_secs(0)),
        );
        assert_eq!(bytes, Some(1000));
        assert_eq!(recv_buf.iter().copied().collect::<Vec<_>>(), vec![42; 1000]);

        let bytes = reader.receive_message(
            &mut recv_buf,
            &mut recv_fds,
            0,
            Some(Duration::from_millis(10)),
        );
        assert_eq!(bytes, None);
    }
}
