//! Quic Transport connection handle.
//!
//! Contains a wrapper, called `ConnectionHandle`, around quinn's Connection.
//! The `ConnectionHandle` implements `rpc` and `push` methods for the given
//! connection.
//!
use axum::http::{Request, Response};
use bytes::Bytes;
use ic_base_types::NodeId;
use quinn::Connection;

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_FINISH, ERROR_TYPE_OPEN, ERROR_TYPE_READ,
        ERROR_TYPE_STOPPED, ERROR_TYPE_WRITE, REQUEST_TYPE_PUSH, REQUEST_TYPE_RPC,
    },
    utils::{read_response, write_request},
    ConnId, MessagePriority,
};

#[derive(Clone, Debug)]
pub(crate) struct ConnectionHandle {
    pub peer_id: NodeId,
    pub connection: Connection,
    pub metrics: QuicTransportMetrics,
    conn_id: ConnId,
}

impl ConnectionHandle {
    pub(crate) fn new(
        peer_id: NodeId,
        connection: Connection,
        metrics: QuicTransportMetrics,
        conn_id: ConnId,
    ) -> Self {
        Self {
            peer_id,
            connection,
            metrics,
            conn_id,
        }
    }

    pub(crate) fn conn_id(&self) -> ConnId {
        self.conn_id
    }

    pub(crate) async fn rpc(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, anyhow::Error> {
        let _timer = self
            .metrics
            .connection_handle_duration_seconds
            .with_label_values(&[request.uri().path()])
            .start_timer();
        self.metrics
            .connection_handle_bytes_sent_total
            .with_label_values(&[request.uri().path()])
            .inc_by(request.body().len() as u64);
        let in_counter = self
            .metrics
            .connection_handle_bytes_received_total
            .with_label_values(&[request.uri().path()]);

        let (mut send_stream, recv_stream) = self.connection.open_bi().await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_OPEN]);
            err
        })?;

        let priority = request
            .extensions()
            .get::<MessagePriority>()
            .copied()
            .unwrap_or_default();
        let _ = send_stream.set_priority(priority.into());

        write_request(&mut send_stream, request)
            .await
            .map_err(|err| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_WRITE])
                    .inc();
                err
            })?;

        send_stream.finish().map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_FINISH])
                .inc();
            err
        })?;

        send_stream.stopped().await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_STOPPED])
                .inc();
            err
        })?;

        let mut response = read_response(recv_stream).await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_READ])
                .inc();
            err
        })?;

        // Propagate PeerId from this request to upper layers.
        response.extensions_mut().insert(self.peer_id);

        in_counter.inc_by(response.body().len() as u64);
        Ok(response)
    }
}
