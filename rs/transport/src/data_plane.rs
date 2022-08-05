//! Data plane - Transport data path
//!
//! The data plane performs read/write QoS scheduling decisions across peer
//! connections, and performs socket IO. Once the control plane establishes a
//! peer connection, the socket is handed over to the data plane for IOs. As the
//! data plane performs the socket reads/writes, it also detects when a
//! connection is down. If a disconnect is detected, the control for the socket
//! is passed back to the control plane to attempt reconnection. On successful
//! reconnection, the socket is passed back to the data plane by the control
//! plane. The data plane is also responsible for detecting errors in the
//! connection (missing heartbeats, error notifications), and raising these to
//! the control plane. The data plane itself is composed of two async tasks per
//! connection: one each for send and receive. The connections established by
//! the control plane are split into read and write halves and given to these
//! two tasks.
//!
//! The data plane module implements data plane functionality for
//! [`TransportImpl`](../types/struct.TransportImpl.html).

use crate::{
    metrics::{DataPlaneMetrics, IntGaugeResource},
    types::{
        Connected, ConnectionRole, SendQueueReader, TransportHeader, TransportImpl,
        TRANSPORT_FLAGS_IS_HEARTBEAT, TRANSPORT_HEADER_SIZE,
    },
};
use ic_base_types::NodeId;
use ic_crypto_tls_interfaces::{TlsReadHalf, TlsStream, TlsWriteHalf};
use ic_interfaces_transport::{
    FlowTag, TransportEvent, TransportEventHandler, TransportMessage, TransportPayload,
};
use ic_logger::warn;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Weak;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tower::Service;

// DEQUEUE_BYTES is the number of bytes which we will attempt to dequeue and
// aggregate before sending to the network via write_all(). Tokio currently
// does not support writev so aggregation is performed manually. This is
// necessary because we are setting TCP_NODELAY which causes each write to be
// pushed to the network. Without aggregation, we would have many small writes
// and thus many small packets. A value of ~800K here works well with a queue
// size of 1K. Values down to 8K work with queue size >= 4K. Smaller sizes make
// the system more responsive in clearing the queues at the cost of increased
// CPU usage. Larger sizes effectively add to the queue size but make the system
// less responsive to queue clearing. A good compromise size might be 32K with a
// larger queue size.
/// The number of bytes which will be attempted to dequeue and aggregate before
/// sending to the network
const DEQUEUE_BYTES: usize = 100 * 4 * 1490;

// Payloads are received/collected in units of SOCKET_READ_CHUNK_SIZE
/// Size of read chunks
const SOCKET_READ_CHUNK_SIZE: usize = 32 * 1024;

/// Heartbeat send interval (timeout on sender side)
const TRANSPORT_HEARTBEAT_SEND_INTERVAL_MS: u64 = 200;
/// Heartbeat wait interval (timeout on receiver side)
const TRANSPORT_HEARTBEAT_WAIT_INTERVAL_MS: u64 = 5000;

/// Error type for read errors
#[derive(Debug)]
enum ReadError {
    SocketReadFailed(std::io::Error),
    SocketReadTimeOut,
}

/// Create header bytes to send with payload.
fn pack_header(payload: Option<&TransportPayload>, heartbeat: bool) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let mut header = TransportHeader {
        version: 0,
        flags: 0,
        reserved: 0,
        payload_length: match payload {
            Some(data) => data.0.len() as u32,
            None => 0,
        },
    };
    if heartbeat {
        header.flags |= TRANSPORT_FLAGS_IS_HEARTBEAT;
    }
    result.append(&mut header.version.to_le_bytes().to_vec());
    result.append(&mut header.flags.to_le_bytes().to_vec());
    result.append(&mut header.reserved.to_le_bytes().to_vec());
    result.append(&mut header.payload_length.to_le_bytes().to_vec());

    assert_eq!(result.len(), TRANSPORT_HEADER_SIZE);

    result
}

/// Read header bytes received in payload.
fn unpack_header(data: Vec<u8>) -> TransportHeader {
    let mut header = TransportHeader {
        version: 0,
        flags: 0,
        reserved: 0,
        payload_length: 0,
    };
    let (version_byte, rest) = data.split_at(std::mem::size_of::<u8>());
    header.version = u8::from_le_bytes(version_byte.try_into().unwrap());
    let (flags_byte, rest) = rest.split_at(std::mem::size_of::<u8>());
    header.flags = u8::from_le_bytes(flags_byte.try_into().unwrap());
    let (reserved_bytes, rest) = rest.split_at(std::mem::size_of::<u16>());
    header.reserved = u16::from_le_bytes(reserved_bytes.try_into().unwrap());
    let (payload_length_bytes, _rest) = rest.split_at(std::mem::size_of::<u32>());
    header.payload_length = u32::from_le_bytes(payload_length_bytes.try_into().unwrap());

    header
}

/// Per-flow send task. Reads the requests from the send queue and writes to
/// the socket.
fn spawn_write_task(
    peer_id: NodeId,
    flow_tag: FlowTag,
    flow_label: String,
    mut send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    mut writer: Box<TlsWriteHalf>,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    let flow_tag_str = flow_tag.to_string();
    rt_handle.spawn(async move  {
            let _raii_gauge = IntGaugeResource::new(data_plane_metrics.write_tasks.clone());
            loop {
                let loop_start_time = Instant::now();
                // If the TransportImpl has been deleted, abort.
                let arc_self = match weak_self.upgrade() {
                    Some(arc_self) => arc_self,
                    _ => return,
                };
                // Wait for the send requests
                let dequeued = send_queue_reader
                    .dequeue(
                        DEQUEUE_BYTES,
                        Duration::from_millis(TRANSPORT_HEARTBEAT_SEND_INTERVAL_MS),
                    )
                    .await;

                let mut to_send = Vec::<u8>::new();
                if dequeued.is_empty() {
                    // There is nothing to send, so issue a heartbeat message
                    to_send.append(&mut pack_header(None, true));
                    arc_self
                        .data_plane_metrics
                        .heart_beats_sent
                        .with_label_values(&[&flow_label, &flow_tag_str])
                        .inc();
                } else {
                    for mut payload in dequeued {
                        to_send.append(&mut pack_header(
                            Some(&payload),
                            false,
                        ));
                        to_send.append(&mut payload.0);
                    }
                }
                arc_self
                    .data_plane_metrics
                    .write_task_overhead_time_msec
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .observe(loop_start_time.elapsed().as_millis() as f64);

                // Send the payload
                let start_time = Instant::now();
                if let Err(e) = writer.write_all(&to_send).await {
                    warn!(
                        arc_self.log,
                        "DataPlane::flow_write_task(): failed to write payload: peer_id: {:?}, flow_tag: {:?}, {:?}",
                        peer_id,
                        flow_tag,
                        e,
                    );
                    arc_self.on_disconnect(peer_id, flow_tag).await;
                    return;
                }
                // Flush the write
                if let Err(e) = writer.flush().await {
                    warn!(
                        arc_self.log,
                        "DataPlane::flow_write_task(): failed to flush: peer_id: {:?}, flow_tag: {:?}, {:?}", peer_id, flow_tag, e,
                    );
                    arc_self.on_disconnect(peer_id, flow_tag).await;
                    return;
                }

                arc_self
                    .data_plane_metrics
                    .socket_write_time_msec
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .observe(start_time.elapsed().as_millis() as f64);
                arc_self
                    .data_plane_metrics
                    .socket_write_bytes
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .inc_by(to_send.len() as u64);
                arc_self
                    .data_plane_metrics
                    .socket_write_size
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .observe(to_send.len() as f64);
            }
        })
}

/// Per-flow receive task. Reads the messages from the socket and passes to
/// the client.
fn spawn_read_task(
    peer_id: NodeId,
    flow_tag: FlowTag,
    flow_label: String,
    mut event_handler: TransportEventHandler,
    mut reader: Box<TlsReadHalf>,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    let heartbeat_timeout = Duration::from_millis(TRANSPORT_HEARTBEAT_WAIT_INTERVAL_MS);
    let flow_tag_str = flow_tag.to_string();
    rt_handle.spawn(async move {
            let _raii_gauge = IntGaugeResource::new(data_plane_metrics.read_tasks.clone());
            loop {
                // If the TransportImpl has been deleted, abort.
                let arc_self = match weak_self.upgrade() {
                    Some(arc_self) => arc_self,
                    _ => return,
                };

                // Read the next message from the socket
                let ret = read_one_message(&mut reader, heartbeat_timeout).await;
                if ret.is_err() {
                    warn!(
                        arc_self.log,
                        "DataPlane::flow_read_task(): failed to receive message: peer_id: {:?}, flow_tag: {:?}, {:?}",
                        peer_id,
                        flow_tag,
                        ret.as_ref().err(),
                    );

                    if let Err(ReadError::SocketReadTimeOut) = ret {
                        arc_self.data_plane_metrics
                            .socket_heart_beat_timeouts
                            .with_label_values(&[&flow_label, &flow_tag_str])
                            .inc();
                    }
                    arc_self.on_disconnect(peer_id, flow_tag).await;
                    return;
                }

                // Process the received message
                let (header, payload) = ret.unwrap();
                if header.flags & TRANSPORT_FLAGS_IS_HEARTBEAT != 0 {
                    // It's an empty heartbeat message -- do nothing
                    arc_self.data_plane_metrics
                        .heart_beats_received
                        .with_label_values(&[&flow_label, &flow_tag_str])
                        .inc();
                    continue;
                }

                // Pass up the received message
                // Errors out for unsolicited messages, decoding errors and p2p
                // shutdowns.
                let payload = payload.unwrap();
                arc_self.data_plane_metrics
                    .socket_read_bytes
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .inc_by(payload.0.len() as u64);
                let start_time = Instant::now();
                let _ = event_handler
                    .call(TransportEvent::Message(TransportMessage {
                        peer_id,
                        payload,
                    }))
                    .await;
                arc_self.data_plane_metrics
                    .client_send_time_msec
                    .with_label_values(&[&flow_label, &flow_tag_str])
                    .observe(start_time.elapsed().as_millis() as f64);
            }
        })
}

/// Reads and returns the next <message hdr, message payload> from the
/// socket. The timeout is for each socket read (header, payload chunks)
/// and not the full message.
async fn read_one_message(
    reader: &mut Box<TlsReadHalf>,
    timeout: Duration,
) -> Result<(TransportHeader, Option<TransportPayload>), ReadError> {
    // Read the hdr
    let mut header_buffer = vec![0u8; TRANSPORT_HEADER_SIZE];
    read_from_socket(reader, &mut header_buffer, timeout).await?;

    let header = unpack_header(header_buffer);
    if header.flags & TRANSPORT_FLAGS_IS_HEARTBEAT != 0 {
        return Ok((header, None));
    }

    // Read the payload in chunks
    let mut payload_buffer = vec![0u8; header.payload_length as usize];
    let mut remaining = header.payload_length as usize;
    let mut cur_offset = 0;
    while remaining > 0 {
        let cur_chunk_size = std::cmp::min(remaining, SOCKET_READ_CHUNK_SIZE);
        assert!(cur_chunk_size <= remaining);
        read_from_socket(
            reader,
            &mut payload_buffer[cur_offset..(cur_offset + cur_chunk_size)],
            timeout,
        )
        .await?;

        remaining -= cur_chunk_size;
        cur_offset += cur_chunk_size;
    }

    let payload = TransportPayload(payload_buffer);
    Ok((header, Some(payload)))
}

/// Reads the requested bytes from the socket with a timeout
async fn read_from_socket(
    reader: &mut Box<TlsReadHalf>,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), ReadError> {
    let read_future = reader.read_exact(buf);
    match tokio::time::timeout(timeout, read_future).await {
        Err(_) => Err(ReadError::SocketReadTimeOut),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(ReadError::SocketReadFailed(e)),
    }
}

/// Handle connection setup. Starts flow read and write tasks.
pub(crate) fn create_connected_state(
    peer_id: NodeId,
    flow_tag: FlowTag,
    flow_label: String,
    send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    role: ConnectionRole,
    peer_addr: SocketAddr,
    tls_stream: TlsStream,
    event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> Connected {
    let (tls_reader, tls_writer) = tls_stream.split();
    // Spawn write task
    let write_task = spawn_write_task(
        peer_id,
        flow_tag,
        flow_label.clone(),
        send_queue_reader,
        Box::new(tls_writer),
        data_plane_metrics.clone(),
        weak_self.clone(),
        rt_handle.clone(),
    );

    let read_task = spawn_read_task(
        peer_id,
        flow_tag,
        flow_label,
        event_handler,
        Box::new(tls_reader),
        data_plane_metrics,
        weak_self,
        rt_handle,
    );

    Connected {
        peer_addr,
        read_task,
        write_task,
        role,
    }
}
