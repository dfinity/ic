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
        ChannelReader, ChannelWriter, Connected, ConnectionRole, PayloadData, SendQueueReader,
        SendStreamWrapper, TransportHeader, TransportImpl, H2_FRAME_SIZE, H2_WINDOW_SIZE,
        TRANSPORT_FLAGS_IS_HEARTBEAT, TRANSPORT_HEADER_SIZE,
    },
};
use h2::RecvStream;
use ic_base_types::NodeId;
use ic_crypto_tls_interfaces::TlsStream;
use ic_interfaces_transport::{
    TransportChannelId, TransportEvent, TransportEventHandler, TransportMessage, TransportPayload,
};
use ic_logger::{info, warn};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Weak;
use strum::IntoStaticStr;
use tokio::io::AsyncRead;
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

const READ_RESULT_ERROR: &str = "error";
const READ_RESULT_HEARTBEAT: &str = "heartbeat";
const READ_RESULT_MESSAGE: &str = "message";

/// Error type for read errors
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum StreamReadError {
    Failed(std::io::Error),
    TimeOut,
    H2ReceiveStreamFailure(String),
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
    channel_id: TransportChannelId,
    mut send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    mut writer: ChannelWriter,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    let channel_id_str = channel_id.to_string();
    rt_handle.spawn(async move  {
        let _ = &data_plane_metrics;
        let _raii_gauge = IntGaugeResource::new(data_plane_metrics.write_tasks.clone());
        loop {
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

            let mut payload_data_vec = vec![];
            let mut total_msg_length = 0;
            if dequeued.is_empty() {
                // There is nothing to send, so issue a heartbeat message
                let payload_data = PayloadData {
                    header: pack_header(None, true),
                    body: vec![],
                };
                total_msg_length = payload_data.header.len();
                payload_data_vec.push(payload_data);

                arc_self
                    .data_plane_metrics
                    .heart_beats_sent
                    .with_label_values(&[&channel_id_str, arc_self.transport_api_label()])
                    .inc();
            } else {
                for payload in dequeued {
                    let payload_data = PayloadData {
                        header: pack_header(Some(&payload),false),
                        body: payload.0,
                    };
                    total_msg_length += payload_data.header.len() + payload_data.body.len();
                    payload_data_vec.push(payload_data);
                }
            }
            // Send the payload
            let start_time = Instant::now();

            if let Err(err) = write_one_message(&mut writer, payload_data_vec).await {
                warn!(
                    arc_self.log,
                    "DataPlane::spawn_write_task(): failed to write payload: peer_id = {:?}, channel_id = {:?}, error ={:?}",
                    peer_id,
                    channel_id,
                    err,
                );
                arc_self.on_disconnect(peer_id, channel_id).await;
                return;
            }

            arc_self
                .data_plane_metrics
                .send_message_duration
                .with_label_values(&[&channel_id_str,  arc_self.transport_api_label()])
                .observe(start_time.elapsed().as_secs() as f64);
            arc_self
                .data_plane_metrics
                .write_bytes_total
                .with_label_values(&[&channel_id_str, arc_self.transport_api_label()])
                .inc_by(total_msg_length as u64);
        }
    })
}

async fn write_one_message(
    writer: &mut ChannelWriter,
    data: Vec<PayloadData>,
) -> Result<(), std::io::Error> {
    match writer {
        ChannelWriter::Legacy(writer) => {
            let mut bytes_to_send = vec![];
            for mut payload in data {
                bytes_to_send.append(&mut payload.header);
                bytes_to_send.append(&mut payload.body);
            }
            writer.write_all(&bytes_to_send).await?;
            writer.flush().await
        }
        ChannelWriter::H2SendStream(send_stream) => {
            // Use SendStreamWrapper to manage capacity and send data as capacity becomes available
            SendStreamWrapper::new(send_stream, data).await
        }
    }
}

/// Per-flow receive task. Reads the messages from the socket and passes to
/// the client.
fn spawn_read_task(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    mut event_handler: TransportEventHandler,
    mut reader: ChannelReader,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    rt_handle.spawn(async move {
        let _ = &data_plane_metrics;
        let _raii_gauge = IntGaugeResource::new(data_plane_metrics.read_tasks.clone());
        let heartbeat_timeout = Duration::from_millis(TRANSPORT_HEARTBEAT_WAIT_INTERVAL_MS);
        let channel_id_str = channel_id.to_string();
        loop {
            // If the TransportImpl has been deleted, abort.
            let arc_self = match weak_self.upgrade() {
                Some(arc_self) => arc_self,
                _ => return,
            };
            // Read the next message from the socket
            let read_message_start = Instant::now();
            let read_one_msg_result = match reader {
                ChannelReader::Legacy(ref mut tls_reader) => read_one_message(tls_reader, heartbeat_timeout).await,
                ChannelReader::H2RecvStream(ref mut receive_stream) => read_one_message_h2(receive_stream, heartbeat_timeout).await,
            };

            match read_one_msg_result {
                Err(err) => {
                    info!(
                        arc_self.log,
                        "DataPlane::spawn_read_task(): failed to receive a single message: peer_id = {:?}, channel_id = {:?}, error = {:?}",
                        peer_id,
                        channel_id,
                        err,
                    );
                    arc_self.data_plane_metrics
                        .read_message_duration
                        .with_label_values(&[&channel_id_str, READ_RESULT_ERROR, arc_self.transport_api_label()])
                        .observe(read_message_start.elapsed().as_secs() as f64);

                    arc_self.data_plane_metrics
                        .message_read_errors_total
                        .with_label_values(&[&channel_id_str, err.into(), arc_self.transport_api_label()])
                        .inc();
                    arc_self.on_disconnect(peer_id, channel_id).await;
                    return;
                },
                Ok((header, payload)) => {
                    if header.flags & TRANSPORT_FLAGS_IS_HEARTBEAT != 0 {
                        // It's an empty heartbeat message -- do nothing
                        arc_self.data_plane_metrics
                            .heart_beats_received
                            .with_label_values(&[&channel_id_str, arc_self.transport_api_label()])
                            .inc();
                        arc_self.data_plane_metrics
                            .read_message_duration
                            .with_label_values(&[&channel_id_str, READ_RESULT_HEARTBEAT, arc_self.transport_api_label()])
                            .observe(read_message_start.elapsed().as_secs() as f64);
                        continue;
                    }
                    arc_self.data_plane_metrics
                        .read_message_duration
                        .with_label_values(&[&channel_id_str, READ_RESULT_MESSAGE, arc_self.transport_api_label()])
                        .observe(read_message_start.elapsed().as_secs() as f64);

                    // Pass up the received message.
                    // Errors out for unsolicited messages, decoding errors and p2p
                    // shutdowns.
                    arc_self.data_plane_metrics
                        .read_bytes_total
                        .with_label_values(&[&channel_id_str, arc_self.transport_api_label()])
                        .inc_by(payload.0.len() as u64);
                    let _callback_start_time = arc_self.data_plane_metrics
                        .event_handler_message_duration
                        .with_label_values(&[&channel_id_str, arc_self.transport_api_label()]).start_timer();
                    event_handler
                        .call(TransportEvent::Message(TransportMessage {
                            peer_id,
                            payload,
                        }))
                        .await
                        .expect("Can't panic on infallible");
                }
            }
        }
    })
}

/// Reads and returns the next <message hdr, message payload> from the
/// socket. The timeout is for each socket read (header, payload chunks)
/// and not the full message.
async fn read_one_message<T: AsyncRead + Unpin>(
    reader: &mut T,
    timeout: Duration,
) -> Result<(TransportHeader, TransportPayload), StreamReadError> {
    // Read the hdr
    let mut header_buffer = vec![0u8; TRANSPORT_HEADER_SIZE];
    read_into_buffer(reader, &mut header_buffer, timeout).await?;
    let header = unpack_header(header_buffer);
    if header.flags & TRANSPORT_FLAGS_IS_HEARTBEAT != 0 {
        return Ok((header, TransportPayload::default()));
    }

    // Read the payload in chunks
    let mut payload_buffer = vec![0u8; header.payload_length as usize];
    let mut remaining = header.payload_length as usize;
    let mut cur_offset = 0;
    while remaining > 0 {
        let cur_chunk_size = std::cmp::min(remaining, SOCKET_READ_CHUNK_SIZE);
        assert!(cur_chunk_size <= remaining);
        read_into_buffer(
            reader,
            &mut payload_buffer[cur_offset..(cur_offset + cur_chunk_size)],
            timeout,
        )
        .await?;

        remaining -= cur_chunk_size;
        cur_offset += cur_chunk_size;
    }

    let payload = TransportPayload(payload_buffer);
    Ok((header, payload))
}

/// Reads and returns the header and message payload.
/// Note: both the header and message may come in as 1+ frames
/// TODO: in final state, we cannot assume that there is exactly 1 message to read without an excess
async fn read_one_message_h2(
    receive_stream: &mut RecvStream,
    timeout: Duration,
) -> Result<(TransportHeader, TransportPayload), StreamReadError> {
    // First frame should be full or partial header.  From there, keeping reading frames until
    // full header is processed.
    let (complete_header, partial_body) = build_message(
        receive_stream,
        vec![],
        TRANSPORT_HEADER_SIZE,
        "header".to_string(),
        timeout,
    )
    .await?;
    let header = unpack_header(complete_header);

    if header.flags & TRANSPORT_FLAGS_IS_HEARTBEAT != 0 {
        // Process heartbeat
        return Ok((header, TransportPayload::default()));
    }

    let (complete_payload, _) = build_message(
        receive_stream,
        partial_body,
        header.payload_length.try_into().unwrap(),
        "body".to_string(),
        timeout,
    )
    .await?;

    let payload = TransportPayload(complete_payload);
    Ok((header, payload))
}

/// Reads frames until target length is reached.
/// After each frame is read, capacity is released.
/// Timeout is applied to each frame read.
async fn build_message(
    receive_stream: &mut RecvStream,
    mut buffer: Vec<u8>,
    target_len: usize,
    msg_type: String,
    timeout: Duration,
) -> Result<(Vec<u8>, Vec<u8>), StreamReadError> {
    while buffer.len() < target_len {
        let read_future = receive_stream.data();
        match tokio::time::timeout(timeout, read_future).await {
            Err(_) => return Err(StreamReadError::TimeOut),
            Ok(Some(Ok(chunk))) => {
                buffer.append(&mut chunk.to_vec());
                let _ = receive_stream.flow_control().release_capacity(chunk.len());
            }
            // If stream returns empty frame, continue polling
            Ok(None) => {}
            Ok(Some(Err(h2_error))) => {
                return Err(StreamReadError::H2ReceiveStreamFailure(format!(
                    "{:?} for {:?}",
                    h2_error.to_string(),
                    msg_type
                )));
            }
        }
    }
    let extra_buffer = buffer.split_off(target_len as usize);
    Ok((buffer, extra_buffer))
}

/// Reads the requested bytes from the socket with a timeout
async fn read_into_buffer<T: AsyncRead + Unpin>(
    reader: &mut T,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), StreamReadError> {
    let read_future = reader.read_exact(buf);
    match tokio::time::timeout(timeout, read_future).await {
        Err(_) => Err(StreamReadError::TimeOut),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(StreamReadError::Failed(e)),
    }
}

/// Handle connection setup. Starts flow read and write tasks.
pub(crate) async fn create_connected_state(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    role: ConnectionRole,
    peer_addr: SocketAddr,
    tls_stream: Box<dyn TlsStream>,
    event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
    use_h2: bool,
) -> Result<Connected, Box<dyn std::error::Error + Send + Sync>> {
    if !use_h2 {
        let (tls_reader, tls_writer) = Box::new(tls_stream).split();
        let channel_reader = ChannelReader::new_with_legacy(tls_reader);
        let channel_writer = ChannelWriter::new_with_legacy(tls_writer);
        // Spawn write task
        let write_task = spawn_write_task(
            peer_id,
            channel_id,
            send_queue_reader,
            channel_writer,
            data_plane_metrics.clone(),
            weak_self.clone(),
            rt_handle.clone(),
        );
        //
        let read_task = spawn_read_task(
            peer_id,
            channel_id,
            event_handler,
            channel_reader,
            data_plane_metrics,
            weak_self,
            rt_handle,
        );

        Ok(Connected {
            peer_addr,
            read_task,
            write_task,
            role,
        })
    } else {
        match role {
            ConnectionRole::Client => {
                create_connected_state_for_h2_client(
                    peer_id,
                    channel_id,
                    send_queue_reader,
                    peer_addr,
                    tls_stream,
                    event_handler,
                    data_plane_metrics,
                    weak_self,
                    rt_handle,
                )
                .await
            }
            ConnectionRole::Server => {
                create_connected_state_for_h2_server(
                    peer_id,
                    channel_id,
                    send_queue_reader,
                    peer_addr,
                    tls_stream,
                    event_handler,
                    data_plane_metrics,
                    weak_self,
                    rt_handle,
                )
                .await
            }
        }
    }
}

pub(crate) async fn create_connected_state_for_h2_client(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    peer_addr: SocketAddr,
    tls_stream: Box<dyn TlsStream>,
    event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> Result<Connected, Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let rt_handle_clone = rt_handle.clone();
    let rt_handle_clone2 = rt_handle.clone();

    rt_handle.clone().spawn(async move {
        match h2::client::Builder::new()
            .initial_window_size(H2_WINDOW_SIZE)
            .initial_connection_window_size(H2_WINDOW_SIZE)
            .max_frame_size(H2_FRAME_SIZE)
            .handshake(tls_stream)
            .await
        {
            Ok((mut client, connection)) => {
                // This needs to be running before we send a request for server to accept the request
                rt_handle.clone().spawn(async move {
                    if (connection.await).is_err() {
                        // TODO handle error
                    }
                });
                let request = http::Request::new(());

                // accept the first request
                match client.send_request(request, false) {
                    Ok((response, send_stream)) => {
                        match response.await {
                            Ok(response) => {
                                let recv_stream = response.into_body();

                                if tx.send((send_stream, recv_stream)).is_err() {
                                    // TODO: We need to handle the error.
                                }
                            }
                            Err(_) => {
                                drop(tx);
                            }
                        }
                    }
                    Err(_) => {
                        // TODO metrics
                        drop(tx);
                    }
                }
            }
            Err(_) => {
                // TODO metrics
                drop(tx);
            }
        }
    });

    match rx.await {
        Ok((send_stream, recv_stream)) => {
            let write_task = spawn_write_task(
                peer_id,
                channel_id,
                send_queue_reader,
                ChannelWriter::new_with_h2_send_stream(send_stream),
                data_plane_metrics.clone(),
                weak_self.clone(),
                rt_handle_clone,
            );

            let read_task = spawn_read_task(
                peer_id,
                channel_id,
                event_handler,
                ChannelReader::new_with_h2_recv_stream(recv_stream),
                data_plane_metrics,
                weak_self,
                rt_handle_clone2,
            );

            Ok(Connected {
                peer_addr,
                read_task,
                write_task,
                role: ConnectionRole::Client,
            })
        }
        Err(_) => Err("Client handshake failed".into()),
    }
}

pub(crate) async fn create_connected_state_for_h2_server(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    peer_addr: SocketAddr,
    tls_stream: Box<dyn TlsStream>,
    event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImpl>,
    rt_handle: tokio::runtime::Handle,
) -> Result<Connected, Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    rt_handle.clone().spawn(async move {
        match h2::server::Builder::new()
            .initial_window_size(H2_WINDOW_SIZE)
            .initial_connection_window_size(H2_WINDOW_SIZE)
            .max_frame_size(H2_FRAME_SIZE)
            .handshake(tls_stream)
            .await
        {
            Ok(mut connection) => {
                // accept the first request
                if let Some(res) = connection.accept().await {
                    match res {
                        Ok((request, mut respond)) => {
                            let response = http::Response::new(());
                            // TODO: We need to handle the error.
                            match respond.send_response(response, false) {
                                Ok(send_stream) => {
                                    let recv_stream = request.into_body();

                                    if tx.send((send_stream, recv_stream)).is_err() {
                                        // TODO: We need to handle the error.
                                    }
                                    // do nothing with other requests for now
                                    while connection.accept().await.is_some() {}
                                }
                                Err(_) => {
                                    // TODO metrics
                                    drop(tx);
                                }
                            }
                        }
                        Err(_) => {
                            // TODO metrics
                            drop(tx);
                        }
                    }
                }
            }
            Err(_) => {
                // TODO metrics
                drop(tx);
            }
        }
    });

    match rx.await {
        Ok(res) => {
            let (send_stream, recv_stream) = res;
            let write_task = spawn_write_task(
                peer_id,
                channel_id,
                send_queue_reader,
                ChannelWriter::new_with_h2_send_stream(send_stream),
                data_plane_metrics.clone(),
                weak_self.clone(),
                rt_handle.clone(),
            );

            let read_task = spawn_read_task(
                peer_id,
                channel_id,
                event_handler,
                ChannelReader::new_with_h2_recv_stream(recv_stream),
                data_plane_metrics,
                weak_self,
                rt_handle,
            );

            Ok(Connected {
                peer_addr,
                read_task,
                write_task,
                role: ConnectionRole::Server,
            })
        }
        Err(_) => Err("Server handshake failed".into()),
    }
}
