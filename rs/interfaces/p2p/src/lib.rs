//! The P2P public interface.
use ic_types::messages::SignedIngress;
use tower::{util::BoxCloneService, BoxError};

// TODO(NET-825): make IngressIngestionService infallible and remove IngressError.
#[derive(Debug, Clone)]
pub enum IngressError {
    /// Ingress service is overloaded.
    Overloaded,
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overloaded => write!(f, "ingress service is overloaded"),
        }
    }
}

impl std::error::Error for IngressError {}

/// This Service can be used to submit an ingress message to P2P event channels
/// for processing. It encapsulates the given ingress message in a *Gossip*
/// artifact and sends it to the P2P `GossipArtifact` channel. It is mainly to
/// be used by the HTTP handler to submit ingress messages.
pub type IngressIngestionService =
    BoxCloneService<SignedIngress, Result<(), IngressError>, BoxError>;
