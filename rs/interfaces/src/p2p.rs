//! The P2P public interface.
use ic_types::{canonical_error::CanonicalError, messages::SignedIngress};
use tower::{buffer::Buffer, load_shed::LoadShed, util::BoxService};

/// This Service can be used to submit an ingress message to P2P event channels
/// for processing. It encapsulates the given ingress message in a *Gossip*
/// artifact and sends it to the P2P `GossipArtifact` channel. It is mainly to
/// be used by the HTTP handler to submit ingress messages.
pub type IngressIngestionService =
    LoadShed<Buffer<BoxService<SignedIngress, (), CanonicalError>, SignedIngress>>;

/// P2P exposes channels that are used to hold artifacts sent by
/// the *Transport* layer or the HTTP handler. These channels also hold any
/// errors and notifications sent by the *Transport* layer (such as
/// connection/disconnection events). `P2PRunner` provides the run interface
/// used by the replica to start reading from these channels. The artifacts or
/// notifications received from these channels are sent to *Gossip* for
/// processing.
pub trait P2PRunner: Send {
    /// The method starts the execution of the `P2PRunner`.
    fn run(&mut self);
}
