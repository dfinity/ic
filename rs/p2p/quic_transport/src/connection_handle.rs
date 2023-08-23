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
use tokio::sync::{mpsc::Sender, oneshot};

use crate::{
    metrics::{QuicTransportMetrics, REQUEST_TYPE_PUSH, REQUEST_TYPE_RPC},
    ConnCmd, TransportError,
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

#[derive(Debug, Clone)]
pub(crate) struct ConnectionHandle {
    pub peer_id: NodeId,
    pub cmd_tx: Sender<ConnCmd>,
    pub metrics: QuicTransportMetrics,
}

#[derive(Debug)]
pub(crate) struct QuicConnWithPeerId {
    pub peer_id: NodeId,
    pub connection: Connection,
}

impl ConnectionHandle {
    pub(crate) fn new(
        peer_id: NodeId,
        cmd_tx: Sender<ConnCmd>,
        metrics: QuicTransportMetrics,
    ) -> Self {
        Self {
            peer_id,
            cmd_tx,
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

        let (rpc_tx, rpc_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::Rpc(request, rpc_tx))
            .await
            .map_err(|_err| TransportError::Disconnected {
                connection_error: "no existing connection event loop".to_string(),
            })?;

        let mut response = rpc_rx.await.unwrap()?;

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

        let (push_tx, push_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::Push(request, push_tx))
            .await
            .map_err(|_err| TransportError::Disconnected {
                connection_error: "no existing connection event loop".to_string(),
            })?;
        push_rx.await.unwrap()
    }
}
