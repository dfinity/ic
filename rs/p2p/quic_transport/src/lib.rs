use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use ic_types::NodeId;

#[derive(Debug)]
pub enum TransportError {
    Disconnected {
        peer_id: NodeId,
        // Potential reason for not being connected
        connection_error: Option<String>,
    },
    Io {
        peer_id: NodeId,
        error: std::io::Error,
    },
    /// Transport is shutdown.
    Stopped,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected {
                peer_id,
                connection_error: _,
            } => {
                write!(f, "Disconnected/No connection to peer {}.", peer_id)
            }
            Self::Io { peer_id, error } => {
                write!(f, "Io error with peer {}. Reason: {}", peer_id, error)
            }
            Self::Stopped => {
                write!(f, "Transport Stopped")
            }
        }
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn rpc(
        &self,
        peer: &NodeId,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError>;

    fn broadcast(&self, msg: Request<Bytes>) -> Result<(), TransportError>;
}
