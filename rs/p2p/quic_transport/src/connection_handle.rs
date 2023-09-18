//! Quic Transport connection handle.
//!
//! Contains a wrapper, called `ConnectionHandle`, around quinn's Connection.
//! The `ConnectionHandle` implements `rpc` and `push` methods for the given
//! connection.
//!
use bytes::Bytes;
use http::{Request, Response};
use ic_base_types::NodeId;
use quinn::Connection;

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_FINISH, ERROR_TYPE_OPEN, ERROR_TYPE_READ,
        ERROR_TYPE_WRITE, REQUEST_TYPE_PUSH, REQUEST_TYPE_RPC,
    },
    utils::{read_response, write_request},
    ConnId, SendError,
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
        mut request: Request<Bytes>,
    ) -> Result<Response<Bytes>, SendError> {
        self.metrics
            .connection_handle_requests_total
            .with_label_values(&[REQUEST_TYPE_RPC])
            .inc();

        // Propagate PeerId from this connection to lower layers.
        request.extensions_mut().insert(self.peer_id);

        let (mut send_stream, recv_stream) = self.connection.open_bi().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_OPEN]);
            SendError::SendRequestFailed {
                reason: e.to_string(),
            }
        })?;

        write_request(&mut send_stream, request)
            .await
            .map_err(|e| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_WRITE]);
                SendError::SendRequestFailed { reason: e }
            })?;

        send_stream.finish().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_FINISH]);
            SendError::SendRequestFailed {
                reason: e.to_string(),
            }
        })?;

        let mut response = read_response(recv_stream).await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_READ]);
            SendError::RecvResponseFailed { reason: e }
        })?;

        // Propagate PeerId from this request to upper layers.
        response.extensions_mut().insert(self.peer_id);

        Ok(response)
    }

    pub(crate) async fn push(&self, mut request: Request<Bytes>) -> Result<(), SendError> {
        self.metrics
            .connection_handle_requests_total
            .with_label_values(&[REQUEST_TYPE_PUSH])
            .inc();

        // Propagate PeerId from this connection to lower layers.
        request.extensions_mut().insert(self.peer_id);

        let mut send_stream = self.connection.open_uni().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_OPEN]);
            SendError::SendRequestFailed {
                reason: e.to_string(),
            }
        })?;

        write_request(&mut send_stream, request)
            .await
            .map_err(|e| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_WRITE]);
                SendError::SendRequestFailed { reason: e }
            })?;

        send_stream.finish().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_FINISH]);
            SendError::SendRequestFailed {
                reason: e.to_string(),
            }
        })?;

        Ok(())
    }
}
