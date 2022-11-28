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
    metrics::DataPlaneMetrics,
    types::{ConnectedH2, ConnectionRole, SendQueueReader, TransportImplH2},
};
use ic_base_types::NodeId;
use ic_crypto_tls_interfaces::TlsStream;
use ic_interfaces_transport::{TransportChannelId, TransportEventHandler};
use std::net::SocketAddr;
use std::sync::Weak;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::task::JoinHandle;

/// Per-flow send task. Reads the requests from the send queue and writes to
/// the socket.
fn spawn_write_task(
    _peer_id: NodeId,
    _channel_id: TransportChannelId,
    _peer_label: String,
    _send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    _writer: WriteHalf<Box<dyn TlsStream>>,
    _data_plane_metrics: DataPlaneMetrics,
    _weak_self: Weak<TransportImplH2>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    rt_handle.spawn(async move {})
}

/// Per-flow receive task. Reads the messages from the socket and passes to
/// the client.
fn spawn_read_task(
    _peer_id: NodeId,
    _channel_id: TransportChannelId,
    _peer_label: String,
    _event_handler: TransportEventHandler,
    _reader: ReadHalf<Box<dyn TlsStream>>,
    _data_plane_metrics: DataPlaneMetrics,
    _weak_self: Weak<TransportImplH2>,
    rt_handle: tokio::runtime::Handle,
) -> JoinHandle<()> {
    rt_handle.spawn(async move {})
}

/// Handle connection setup. Starts flow read and write tasks.
pub(crate) fn create_connected_state_write_path(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    peer_label: String,
    send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    role: ConnectionRole,
    peer_addr: SocketAddr,
    tls_stream: Box<dyn TlsStream>,
    _event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImplH2>,
    rt_handle: tokio::runtime::Handle,
) -> ConnectedH2 {
    let (_tls_reader, tls_writer) = tokio::io::split(tls_stream);
    // Spawn write task
    let write_task = spawn_write_task(
        peer_id,
        channel_id,
        peer_label,
        send_queue_reader,
        tls_writer,
        data_plane_metrics,
        weak_self,
        rt_handle,
    );

    ConnectedH2 {
        peer_addr,
        _task: write_task,
        role,
    }
}

/// Handle connection setup. Starts flow read and write tasks.
pub(crate) fn create_connected_state_read_path(
    peer_id: NodeId,
    channel_id: TransportChannelId,
    peer_label: String,
    _send_queue_reader: Box<dyn SendQueueReader + Send + Sync>,
    role: ConnectionRole,
    peer_addr: SocketAddr,
    tls_stream: Box<dyn TlsStream>,
    event_handler: TransportEventHandler,
    data_plane_metrics: DataPlaneMetrics,
    weak_self: Weak<TransportImplH2>,
    rt_handle: tokio::runtime::Handle,
) -> ConnectedH2 {
    let (tls_reader, _tls_writer) = tokio::io::split(tls_stream);
    // Spawn read task
    let read_task = spawn_read_task(
        peer_id,
        channel_id,
        peer_label,
        event_handler,
        tls_reader,
        data_plane_metrics,
        weak_self,
        rt_handle,
    );

    ConnectedH2 {
        peer_addr,
        _task: read_task,
        role,
    }
}
