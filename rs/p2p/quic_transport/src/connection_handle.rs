//! Quic Transport connection handle.
//!
//! Contains the handle returned by transport `get_peer_handle` API.
//! The connection handler implements the tower service trait so it
//! can be wrapped with layers if needed.
use std::io;

use bytes::Bytes;
use http::{Request, Response};
use ic_types::NodeId;
use quinn::Connection;

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_FINISH, ERROR_TYPE_OPEN, ERROR_TYPE_READ,
        ERROR_TYPE_WRITE, REQUEST_TYPE_PUSH, REQUEST_TYPE_RPC,
    },
    utils::{read_response, write_request},
    TransportError,
};

impl From<quinn::WriteError> for TransportError {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            quinn::WriteError::Stopped(e) => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()),
            },
            quinn::WriteError::ConnectionLost(cause) => TransportError::Disconnected {
                connection_error: cause.to_string(),
            },
            quinn::WriteError::UnknownStream => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionReset, "unknown quic stream"),
            },
            quinn::WriteError::ZeroRttRejected => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionRefused, "zero rtt rejected"),
            },
        }
    }
}

impl From<quinn::ConnectionError> for TransportError {
    fn from(value: quinn::ConnectionError) -> Self {
        match value {
            quinn::ConnectionError::VersionMismatch => TransportError::Io {
                error: io::Error::new(io::ErrorKind::Unsupported, "Quic version mismatch"),
            },
            quinn::ConnectionError::TransportError(e) => TransportError::Io {
                error: io::Error::new(io::ErrorKind::Unsupported, e.to_string()),
            },
            quinn::ConnectionError::Reset => TransportError::Io {
                error: io::Error::from(io::ErrorKind::ConnectionReset),
            },
            quinn::ConnectionError::TimedOut => TransportError::Io {
                error: io::Error::from(io::ErrorKind::TimedOut),
            },
            quinn::ConnectionError::ConnectionClosed(e) => TransportError::Disconnected {
                connection_error: e.to_string(),
            },
            quinn::ConnectionError::ApplicationClosed(e) => TransportError::Disconnected {
                connection_error: e.to_string(),
            },
            quinn::ConnectionError::LocallyClosed => TransportError::Disconnected {
                connection_error: "Connection closed locally".to_string(),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionHandle {
    pub peer_id: NodeId,
    pub connection: Connection,
    pub metrics: QuicTransportMetrics,
}

impl ConnectionHandle {
    pub(crate) fn new(
        peer_id: NodeId,
        connection: Connection,
        metrics: QuicTransportMetrics,
    ) -> Self {
        Self {
            peer_id,
            connection,
            metrics,
        }
    }

    pub(crate) async fn rpc(
        &self,
        mut request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError> {
        self.metrics
            .connection_handle_requests_total
            .with_label_values(&[REQUEST_TYPE_RPC])
            .inc();

        // Propagate PeerId from this connection to lower layers.
        request.extensions_mut().insert(self.peer_id);

        let (mut send_stream, mut recv_stream) = self.connection.open_bi().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_OPEN]);
            e
        })?;

        write_request(&mut send_stream, request)
            .await
            .map_err(|e| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_WRITE]);
                TransportError::Io { error: e }
            })?;

        send_stream.finish().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_FINISH]);
            e
        })?;

        let mut response = read_response(&mut recv_stream).await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_READ]);
            TransportError::Io { error: e }
        })?;

        // Propagate PeerId from this request to upper layers.
        response.extensions_mut().insert(self.peer_id);

        Ok(response)
    }

    pub(crate) async fn push(&self, mut request: Request<Bytes>) -> Result<(), TransportError> {
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
            e
        })?;

        write_request(&mut send_stream, request)
            .await
            .map_err(|e| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_WRITE]);
                TransportError::Io { error: e }
            })?;

        send_stream.finish().await.map_err(|e| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_FINISH]);
            e
        })?;

        Ok(())
    }
}
