//! The ingress pool public interface.
use crate::{consensus_pool::ValidatedArtifact, p2p::consensus::UnvalidatedArtifact};
use ic_types::{
    CanisterId, CountBytes, NodeId, Time,
    artifact::IngressMessageId,
    messages::{MessageId, SignedIngress, extract_effective_canister_id},
};
use std::sync::OnceLock;

// tag::interface[]

/// IngressObject is the format stored in the unvalidated/validated sections of
/// the ingress pool. This is basically a wrapper around the SignedIngress
/// message
#[derive(Clone)]
pub struct IngressPoolObject {
    /// The received ingress message
    signed_ingress: SignedIngress,

    /// The MessageId of the RawIngress message
    pub message_id: MessageId,

    // TODO: Once/if we start signing ingress messages, determine the `originator_id` by extracting
    // the signer from the signature.
    /// Which the ingress message originates from.
    pub originator_id: NodeId,

    /// Byte size of the ingress message.
    byte_size: usize,

    /// The result of [`extract_effective_canister_id`] for the ingress message,
    /// computed on first use by the method
    /// [`IngressPoolObject::effective_canister_id`].
    effective_canister_id: OnceLock<Result<Option<CanisterId>, InvalidManagementMessage>>,
}

/// The effective canister ID of an ingress message addressed to the management
/// canister cannot be determined.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidManagementMessage;

impl IngressPoolObject {
    pub fn new(originator_id: NodeId, signed_ingress: SignedIngress) -> Self {
        let message_id = signed_ingress.id();
        let byte_size = signed_ingress.count_bytes();

        Self {
            signed_ingress,
            message_id,
            originator_id,
            byte_size,
            effective_canister_id: OnceLock::new(),
        }
    }

    /// Returns the signed ingress message wrapped by this pool object.
    ///
    /// The message is immutable because the cached effective canister ID is
    /// derived from its contents.
    pub fn signed_ingress(&self) -> &SignedIngress {
        &self.signed_ingress
    }

    /// Returns the effective canister ID of the ingress message, as determined by
    /// [`extract_effective_canister_id`]. It is computed on the first call (decoding
    /// the method payload of management canister messages) and cached afterwards,
    /// including if it cannot be determined.
    pub fn effective_canister_id(&self) -> Result<Option<CanisterId>, InvalidManagementMessage> {
        *self.effective_canister_id.get_or_init(|| {
            extract_effective_canister_id(self.signed_ingress.content())
                .map_err(|_| InvalidManagementMessage)
        })
    }
}

impl CountBytes for IngressPoolObject {
    fn count_bytes(&self) -> usize {
        self.byte_size
    }
}

impl From<&IngressPoolObject> for IngressMessageId {
    fn from(obj: &IngressPoolObject) -> IngressMessageId {
        IngressMessageId::new(obj.signed_ingress().expiry_time(), obj.message_id.clone())
    }
}

/// Validated ingress artifact
pub type ValidatedIngressArtifact = ValidatedArtifact<IngressPoolObject>;

/// Unvalidated ingress artifact
pub type UnvalidatedIngressArtifact = UnvalidatedArtifact<IngressPoolObject>;

/// List of mutations
pub type Mutations = Vec<ChangeAction>;

/// Change actions applicable to the ingress pool.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ChangeAction {
    /// Moves an artifact from the unvalidated to validated section of the pool
    MoveToValidated(IngressMessageId),
    /// Removes an artifact from the unvalidated pool section.
    RemoveFromUnvalidated(IngressMessageId),
    /// Removes an artifact from the validated pool section.
    RemoveFromValidated(IngressMessageId),
    /// Remove expired artifact from both pools.
    PurgeBelowExpiry(Time),
}

/// A Pool section is a part of the ingress pool which contains
/// either validated or unvalidated ingress messages
/// Artifacts in the pool are accessible by their id.
pub trait PoolSection<T> {
    /// Lookup an artifact by the id. Return the ingress message
    /// if it exists, or None otherwise.
    fn get(&self, message_id: &IngressMessageId) -> Option<&T>;

    /// Get reference to all artifacts
    fn get_all_by_expiry_range(
        &self,
        range: std::ops::RangeInclusive<Time>,
    ) -> Box<dyn Iterator<Item = &T> + '_>;

    /// Lookup the timestamp of an artifact by its id.
    fn get_timestamp(&self, message_id: &IngressMessageId) -> Option<Time>;

    /// Get the number of artifacts in the pool.
    fn size(&self) -> usize;
}

/// The ingress pool contains all the ingress artifacts received by P2P and
/// produced by the local node.
///
/// It contains two sections:
/// - The validated section contains artifacts that have been validated by
///   IngressHandler.
///
/// - The unvalidated section contains artifacts that have been received but
///   haven't yet been validated.
pub trait IngressPool: Send + Sync {
    /// Validated Ingress Pool Section
    fn validated(&self) -> &dyn PoolSection<ValidatedIngressArtifact>;

    /// Unvalidated Ingress Pool Section
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedIngressArtifact>;

    /// Check whether we already have too many messages from the node.
    fn exceeds_limit(&self, originator_id: &NodeId) -> bool;
}

/// Interface to throttle user ingress messages
pub trait IngressPoolThrottler {
    /// Checks if the total number of entries is within the configured threshold
    fn exceeds_threshold(&self) -> bool;
}
// end::interface[]
