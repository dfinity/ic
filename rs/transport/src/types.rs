//! Shared types internal to transport crate

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use crate::utils::SendQueueImpl;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{ready, Stream};
use h2::{Reason, RecvStream, SendStream};
use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::{TransportChannelId, TransportEventHandler, TransportPayload};
use ic_logger::{warn, ReplicaLogger};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::{self, Debug, Formatter},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};
use strum::{AsRefStr, IntoStaticStr};
use tokio::io::AsyncWrite;
use tokio::{
    runtime::Handle,
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Duration,
};

/// The size (in bytes) of the transport header
pub const TRANSPORT_HEADER_SIZE: usize = 8;

/// Flag: message is a heartbeat
///
/// When a message has this flag on, it means that the message contains no
/// payload, and that it was sent by the heartbeats mechanism to keep the
/// connection alive.
pub const TRANSPORT_FLAGS_IS_HEARTBEAT: u8 = 2;

/// The transport header format.
///
/// A message is sent on the wire as two writes:
///
///   1. The TransportHeader
///   2. The payload (client message, which is an opaque byte array)
///
/// Note:
///
/// For message framing the transport header must serialize to the
/// same size irrespective of its contents. Fields like NodeId can
/// result violation of the same requirement as it can get serialized
/// to different lengths.
///
/// To maintain the size invariant the header is manually serialized.
/// This struct is ephemeral hence the lack of derivations or tagging.
pub(crate) struct TransportHeader {
    /// The version of the Transport being used (currently 0)
    pub(crate) version: u8, // Currently 0
    /// Transport flags: defined by the constants named `TRANSPORT_FLAGS_*` in
    /// this module
    pub(crate) flags: u8,
    /// Reserved space (currently 0)
    pub(crate) reserved: u16, // Currently 0, serialized little endian.
    /// The length of the byte payload that follows next
    pub(crate) payload_length: u32, // Serialized little endian.
}

/// This is the max frame size that H2 supports
pub const H2_FRAME_SIZE: u32 = 16_777_215;

/// This value was chosen empirically and can be raised if needed
pub const H2_WINDOW_SIZE: u32 = 1_000_000;

/// Transport implementation state struct. The control and data planes provide
/// implementations for this struct.
pub(crate) struct TransportImpl {
    /// The node ID of this replica
    pub node_id: NodeId,
    /// The IP address of this node
    pub node_ip: IpAddr,
    /// Configuration
    pub config: TransportConfig,

    /// Port used to accept connections for this transport-client
    pub accept_port: Mutex<Option<ServerPortState>>,
    /// Mapping of peers to their corresponding state
    pub peer_map: RwLock<HashMap<NodeId, RwLock<PeerState>>>,
    /// Event handler to report back to the transport client
    pub event_handler: Mutex<Option<TransportEventHandler>>,

    // Crypto and data required for TLS handshakes
    /// Clients that are allowed to connect to this node
    pub allowed_clients: RwLock<BTreeSet<NodeId>>,
    /// The latest registry version that is used
    pub latest_registry_version: RwLock<RegistryVersion>,
    /// The registry version of the latest CUP
    pub earliest_registry_version: RwLock<RegistryVersion>,
    /// Reference to the crypto component
    pub crypto: Arc<dyn TlsHandshake + Send + Sync>,

    /// Data plane metrics
    pub data_plane_metrics: DataPlaneMetrics,
    /// Control plane metrics
    pub control_plane_metrics: ControlPlaneMetrics,
    /// Send queue metrics
    pub send_queue_metrics: SendQueueMetrics,

    /// The tokio runtime
    pub rt_handle: Handle,
    /// Logger
    pub log: ReplicaLogger,
    /// Guarded self weak-reference
    pub weak_self: std::sync::RwLock<Weak<TransportImpl>>,
    /// If true, uses http/2 protocol
    pub use_h2: bool,
}

/// Error type for read errors
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum StreamReadError {
    Failed(std::io::Error),
    TimeOut,
    H2ReceiveStreamFailure(String),
    EndOfStream,
}

// Wrapper around SendStream to ensure that we only send data if there is available capacity,
// since send stream uses an unbounded buffer to handle data.
pub(crate) struct H2Writer {
    send_stream: SendStream<Bytes>,
    channel_id_label: String,
    peer_label: String,
    metrics: DataPlaneMetrics,
}

impl H2Writer {
    pub fn new(
        send_stream: SendStream<Bytes>,
        channel_id: TransportChannelId,
        peer_label: String,
        metrics: DataPlaneMetrics,
    ) -> Self {
        Self {
            send_stream,
            channel_id_label: channel_id.to_string(),
            peer_label,
            metrics,
        }
    }
}

// Similar to hyper implementation https://github.com/hyperium/hyper/blob/master/src/proto/h2/mod.rs#L318
impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.metrics
            .h2_write_capacity
            .with_label_values(&[&self.peer_label, &self.channel_id_label])
            .set(self.send_stream.capacity() as i64);

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.send_stream.reserve_capacity(buf.len());

        // We ignore all errors returned by `poll_capacity` and `write`, as we
        // will get the correct from `poll_reset` anyway.

        let cnt = loop {
            match ready!(self.send_stream.poll_capacity(cx)) {
                None => {
                    break Some(0);
                }
                // Sending an empty buffer indicates end of stream. But getting 0
                // from poll_capacity does not mean that the stream is finished. Try again...
                Some(Ok(0)) => continue,
                Some(Ok(cnt)) => {
                    let cap = self
                        .send_stream
                        .send_data(
                            Bytes::copy_from_slice(&buf[..std::cmp::min(cnt, buf.len())]),
                            false,
                        )
                        .ok()
                        .map(|()| std::cmp::min(cnt, buf.len()));
                    break cap;
                }
                Some(Err(_)) => break None,
            }
        };

        if let Some(cnt) = cnt {
            return Poll::Ready(Ok(cnt));
        }

        Poll::Ready(Err(h2_to_io_error(
            match ready!(self.send_stream.poll_reset(cx)) {
                Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                }
                Ok(reason) => reason.into(),
                Err(e) => e,
            },
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.send_stream.send_data(Bytes::default(), true).is_ok() {
            return Poll::Ready(Ok(()));
        }

        Poll::Ready(Err(h2_to_io_error(
            match ready!(self.send_stream.poll_reset(cx)) {
                Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
                Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                }
                Ok(reason) => reason.into(),
                Err(e) => e,
            },
        )))
    }
}

pub(crate) struct H2Reader {
    receive_stream: RecvStream,
    channel_id_label: String,
    peer_label: String,
    metrics: DataPlaneMetrics,
}

impl H2Reader {
    pub fn new(
        receive_stream: RecvStream,
        channel_id: TransportChannelId,
        peer_label: String,
        metrics: DataPlaneMetrics,
    ) -> Self {
        Self {
            receive_stream,
            channel_id_label: channel_id.to_string(),
            peer_label,
            metrics,
        }
    }
}

impl Stream for H2Reader {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.metrics
            .h2_read_used_capacity
            .with_label_values(&[&self.peer_label, &self.channel_id_label])
            .set(self.receive_stream.flow_control().used_capacity() as i64);
        self.metrics
            .h2_read_available_capacity
            .with_label_values(&[&self.peer_label, &self.channel_id_label])
            .set(self.receive_stream.flow_control().available_capacity() as i64);

        let this = self.get_mut();

        match ready!(Pin::new(&mut this.receive_stream).poll_data(cx)) {
            Some(Ok(chunk)) => {
                let len = chunk.len();

                match this.receive_stream.flow_control().release_capacity(len) {
                    Ok(()) => Poll::Ready(Some(Ok(chunk))),
                    Err(err) => Poll::Ready(Some(Err(h2_to_io_error(err)))),
                }
            }
            Some(Err(err)) => Poll::Ready(Some(Err(h2_to_io_error(err)))),
            None => Poll::Ready(None),
        }
    }
}

// Copied from hyper source code.
fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

/// Our role in a connection
#[derive(Debug, PartialEq, Eq, Copy, Clone, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ConnectionRole {
    /// We connect to the peer as a client
    Client,

    /// We are the server
    Server,
}

/// State about the server ports we are listening on
pub(crate) struct ServerPortState {
    /// Handle to the accept task for this port
    pub accept_task: JoinHandle<()>,
}

impl Drop for ServerPortState {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// Per-peer state, specific to a transport client
pub(crate) struct PeerState {
    log: ReplicaLogger,
    /// Peer label, used for metrics
    pub peer_label: String,
    /// Connection state
    connection_state: ConnectionState,
    /// The send queue of this flow
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
    /// Metrics
    control_plane_metrics: ControlPlaneMetrics,
}

impl PeerState {
    pub(crate) fn new(
        log: ReplicaLogger,
        channel_id: TransportChannelId,
        peer_label: String,
        connection_state: ConnectionState,
        queue_size: usize,
        send_queue_metrics: SendQueueMetrics,
        control_plane_metrics: ControlPlaneMetrics,
    ) -> Self {
        let send_queue = Box::new(SendQueueImpl::new(
            peer_label.clone(),
            channel_id,
            queue_size,
            send_queue_metrics,
        ));
        let ret = Self {
            log,
            peer_label,
            connection_state,
            send_queue,
            control_plane_metrics,
        };
        ret.report_connection_state();
        ret
    }

    /// Updates the state of the connection
    pub(crate) fn update(&mut self, connection_state: ConnectionState) {
        self.connection_state.update(connection_state);
        self.report_connection_state();
    }

    /// Reports the state of a flow to metrics
    fn report_connection_state(&self) {
        self.control_plane_metrics
            .flow_state
            .with_label_values(&[&self.peer_label])
            .set(self.connection_state.idx());
        self.control_plane_metrics
            .connection_state
            .with_label_values(&[&self.peer_label])
            .set(self.connection_state.idx());
    }

    pub(crate) fn get_connected(&self) -> Option<&Connected> {
        if let ConnectionState::Connected(connected) = &self.connection_state {
            return Some(connected);
        }
        None
    }
}

impl Drop for PeerState {
    fn drop(&mut self) {
        if self
            .control_plane_metrics
            .flow_state
            .remove_label_values(&[&self.peer_label])
            .is_err()
        {
            warn!(
                self.log,
                "Transport:PeerState drop: Could not remove peer metric {:?}", self.peer_label
            )
        }
    }
}

/// The connection state machine for a flow with a peer
pub(crate) enum ConnectionState {
    /// We are the server, waiting for peer to connect
    Listening,
    /// We are the client, connection in progress
    Connecting(Connecting),
    /// Connection established
    Connected(Connected),
}

/// Info about a flow in ConnectionState::Connecting
pub(crate) struct Connecting {
    /// Server node we are connecting to
    pub peer_addr: SocketAddr,

    /// The connecting task handle
    pub connecting_task: JoinHandle<()>,
}

impl Drop for Connecting {
    fn drop(&mut self) {
        self.connecting_task.abort();
    }
}

pub(crate) struct StreamState {
    /// The read task handle
    pub read_task: JoinHandle<()>,

    /// The write task handle
    pub write_task: JoinHandle<()>,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

/// Info about a flow in ConnectionState::Connected
pub(crate) struct Connected {
    /// Peer node
    pub peer_addr: SocketAddr,

    /// Per stream state data. The field is not dead code because
    /// Drop is implemented for StreamState.
    #[allow(dead_code)]
    pub stream_state: StreamState,

    /// H2 connection polling task
    pub h2_conn: Option<JoinHandle<()>>,

    /// Our role
    pub role: ConnectionRole,
}

impl Drop for Connected {
    fn drop(&mut self) {
        if let Some(h2_conn) = self.h2_conn.take() {
            h2_conn.abort();
        }
    }
}

impl ConnectionState {
    /// Validates/updates the state transition
    fn update(&mut self, next_state: Self) {
        if self.is_valid_transition(&next_state) {
            *self = next_state;
        } else {
            panic!(
                "Invalid connection state change: {:?} -> {:?}",
                *self, next_state
            );
        }
    }

    /// Verifies if it the state transition is allowed according to the state
    /// machine
    fn is_valid_transition(&self, next_state: &Self) -> bool {
        let mut valid = false;
        match self {
            Self::Listening => {
                if let Self::Connected(s) = next_state {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
            }
            Self::Connecting(_) => {
                if let Self::Connected(s) = next_state {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
            }
            Self::Connected(s) => match next_state {
                Self::Listening => {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
                Self::Connecting(_) => {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
                _ => (),
            },
        }
        valid
    }

    fn idx(&self) -> i64 {
        match self {
            Self::Listening => 1,
            Self::Connecting(_) => 2,
            Self::Connected(_) => 3,
        }
    }
}

impl Debug for ConnectionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Listening => {
                write!(f, "ConnectionState::Listening")
            }
            Self::Connecting(state) => {
                write!(
                    f,
                    "ConnectionState::Connecting(peer = {:?})",
                    state.peer_addr
                )
            }
            Self::Connected(state) => {
                write!(
                    f,
                    "ConnectionState::Connected(peer = {:?}, role = {:?})",
                    state.peer_addr, state.role
                )
            }
        }
    }
}

/// Per-flow: send queue
///
/// Single producer, single consumer queues for sending data over
/// sockets. There could be multiple sender threads sending into the
/// queue, but the Impl would guarantee mutually exclusive access to
/// the send queue.
#[async_trait]
pub(crate) trait SendQueue {
    /// Gets the read end to be passed to the write task.
    /// Returns None if the reader is already in use by a previously created
    /// write task.
    fn get_reader(&mut self) -> Box<dyn SendQueueReader + Send + Sync>;

    /// Submits a client message for sending to a peer. If the message
    /// cannot be enqueued, the message is returned back to the caller.
    fn enqueue(&self, message: TransportPayload) -> Option<TransportPayload>;

    /// Discards enqueued messages and clears the queue.
    fn clear(&mut self);
}

/// Per-flow: send queue read end
#[async_trait]
pub(crate) trait SendQueueReader {
    /// Called by the scheduler to get the next enqueued message, if any.
    async fn dequeue(&mut self, bytes_limit: usize, timeout: Duration) -> Vec<TransportPayload>;
}

#[cfg(test)]
mod tests {
    use futures::future::join;
    use h2::{client, server};
    use http::Request;
    use ic_metrics::MetricsRegistry;
    use ic_transport_test_utils::get_free_localhost_port;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Barrier,
    };
    use tokio_util::io::StreamReader;

    use super::*;

    fn connecting_state() -> ConnectionState {
        let connecting_task = tokio::task::spawn(async {});
        ConnectionState::Connecting(Connecting {
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
            connecting_task,
        })
    }

    fn connected_state(role: ConnectionRole) -> ConnectionState {
        let read_task = tokio::task::spawn(async {});
        let write_task = tokio::task::spawn(async {});
        ConnectionState::Connected(Connected {
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
            stream_state: StreamState {
                read_task,
                write_task,
            },
            h2_conn: None,
            role,
        })
    }

    fn verify_state_transitions(
        current_state: ConnectionState,
        results: Vec<(ConnectionState, bool)>,
    ) {
        for (next_state, expected_result) in results {
            assert_eq!(
                current_state.is_valid_transition(&next_state),
                expected_result
            );
        }
    }

    struct H2Setup {
        _client_con: JoinHandle<()>,
        _sever_con: JoinHandle<()>,
        client_writer: H2Writer,
        server_writer: H2Writer,
        client_reader: StreamReader<H2Reader, Bytes>,
        server_reader: StreamReader<H2Reader, Bytes>,
    }

    async fn setup_h2_reader_writer(
        initial_window_size: u32,
        initial_connection_window_size: u32,
        frame_size: u32,
    ) -> H2Setup {
        // Spawn h2 server side.
        let port = get_free_localhost_port().unwrap();

        // Create barrier to make sure we only connect after we binded to the socket.
        let b = Arc::new(Barrier::new(2));
        let b_c = b.clone();
        let h2_server_task = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            b_c.wait().await;
            let (stream, _) = listener.accept().await.unwrap();
            stream
        });

        b.wait().await;
        let client_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        let server_stream = h2_server_task.await.unwrap();

        let client_fut = async move {
            client::Builder::new()
                .initial_window_size(initial_window_size)
                .initial_connection_window_size(initial_connection_window_size)
                .initial_window_size(frame_size)
                .handshake(client_stream)
                .await
                .unwrap()
        };
        let server_fut = async move {
            server::Builder::new()
                .initial_window_size(initial_window_size)
                .initial_connection_window_size(initial_connection_window_size)
                .initial_window_size(frame_size)
                .handshake(server_stream)
                .await
                .unwrap()
        };

        let ((client_send, client_conn), mut server_conn) = join(client_fut, server_fut).await;

        let h2_client_driver = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let client_fut = async move {
            let mut h2 = client_send.ready().await.unwrap();
            let request = Request::new(());
            let (resp_fut, send_stream) = h2.send_request(request, false).unwrap();
            (send_stream, resp_fut)
        };

        let server_fut = async {
            let (request, mut respond) = server_conn.accept().await.unwrap().unwrap();
            let response = http::Response::new(());
            let send_stream = respond.send_response(response, false).unwrap();
            let recv_stream = request.into_body();
            (send_stream, recv_stream)
        };

        let ((client_writer, client_reader_fut), (server_writer, server_reader)) =
            join(client_fut, server_fut).await;

        let h2_server_driver =
            tokio::spawn(async move { while let Some(Ok(_)) = server_conn.accept().await {} });

        let client_reader = client_reader_fut.await.unwrap().into_body();

        let client_reader = StreamReader::new(H2Reader::new(
            client_reader,
            TransportChannelId::from(0),
            String::new(),
            DataPlaneMetrics::new(MetricsRegistry::default()),
        ));
        let client_writer = H2Writer::new(
            client_writer,
            TransportChannelId::from(0),
            String::new(),
            DataPlaneMetrics::new(MetricsRegistry::default()),
        );
        let server_reader = StreamReader::new(H2Reader::new(
            server_reader,
            TransportChannelId::from(0),
            String::new(),
            DataPlaneMetrics::new(MetricsRegistry::default()),
        ));
        let server_writer = H2Writer::new(
            server_writer,
            TransportChannelId::from(0),
            String::new(),
            DataPlaneMetrics::new(MetricsRegistry::default()),
        );

        H2Setup {
            _client_con: h2_client_driver,
            _sever_con: h2_server_driver,
            client_writer,
            server_writer,
            client_reader,
            server_reader,
        }
    }

    #[tokio::test]
    async fn test_connection_state_machine_listening() {
        let state = ConnectionState::Listening;
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), true),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);
    }

    #[tokio::test]
    async fn test_connection_state_machine_connecting() {
        let state = connecting_state();
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), true),
        ];
        verify_state_transitions(state, expected);
    }

    #[tokio::test]
    async fn test_connection_state_machine_connected() {
        let state = connected_state(ConnectionRole::Server);
        let expected = vec![
            (ConnectionState::Listening, true),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);

        let state = connected_state(ConnectionRole::Client);
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), true),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);
    }
    #[tokio::test]
    async fn h2_single_message() {
        let H2Setup {
            _client_con,
            _sever_con,
            mut client_writer,
            mut server_writer,
            mut client_reader,
            mut server_reader,
        } = setup_h2_reader_writer(H2_WINDOW_SIZE, H2_WINDOW_SIZE, H2_FRAME_SIZE).await;

        let message = vec![1; 10];
        client_writer.write_all(&message).await.unwrap();
        let mut buf = vec![0; 10];
        server_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, message);

        let message = vec![1; 10];
        server_writer.write_all(&message).await.unwrap();
        let mut buf = vec![0; 10];
        client_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, message);
    }
}
