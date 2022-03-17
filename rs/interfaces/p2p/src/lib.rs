//! The P2P public interface.
use ic_types::{canonical_error::CanonicalError, messages::SignedIngress};
use std::convert::Infallible;
use tower::{buffer::Buffer, util::BoxService};

/// This Service can be used to submit an ingress message to P2P event channels
/// for processing. It encapsulates the given ingress message in a *Gossip*
/// artifact and sends it to the P2P `GossipArtifact` channel. It is mainly to
/// be used by the HTTP handler to submit ingress messages.
pub type IngressIngestionService =
    Buffer<BoxService<SignedIngress, Result<(), CanonicalError>, Infallible>, SignedIngress>;
