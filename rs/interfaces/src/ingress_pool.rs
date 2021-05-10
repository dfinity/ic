//! The ingress pool public interface.
use crate::artifact_pool::{UnvalidatedArtifact, ValidatedArtifact};
use ic_types::{
    artifact::{IngressMessageAttribute, IngressMessageId},
    crypto::CryptoHash,
    messages::{MessageId, SignedIngress},
    CountBytes, Time,
};
// tag::interface[]

/// IngressObject is the format stored in the unvalidated/validated sections of
/// the ingress pool. This is basically a wrapper around the SignedIngress
/// message
#[derive(Clone)]
pub struct IngressPoolObject {
    /// The received ingress message
    pub signed_ingress: SignedIngress,

    /// The MessageId of the RawIngress message
    pub message_id: MessageId,

    /// Byte size of the ingress message.
    byte_size: usize,
}

impl CountBytes for IngressPoolObject {
    fn count_bytes(&self) -> usize {
        self.byte_size
    }
}

impl From<SignedIngress> for IngressPoolObject {
    fn from(signed_ingress: SignedIngress) -> Self {
        let message_id = signed_ingress.id();
        let byte_size = signed_ingress.count_bytes();
        Self {
            signed_ingress,
            message_id,
            byte_size,
        }
    }
}

impl From<&IngressPoolObject> for IngressMessageId {
    fn from(obj: &IngressPoolObject) -> IngressMessageId {
        IngressMessageId::new(obj.signed_ingress.expiry_time(), obj.message_id.clone())
    }
}

/// Validated ingress artifact
pub type ValidatedIngressArtifact = ValidatedArtifact<IngressPoolObject>;

/// Unvalidated ingress artifact
pub type UnvalidatedIngressArtifact = UnvalidatedArtifact<IngressPoolObject>;

/// Change set for processing unvalidated ingress messages
pub type ChangeSet = Vec<ChangeAction>;

pub type IngressChangeArtifact = (IngressMessageId, usize, IngressMessageAttribute, CryptoHash);

/// Change actions applicable to the ingress pool.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum ChangeAction {
    /// Moves an artifact from the unvalidated to validated section of the pool
    MoveToValidated(IngressChangeArtifact),
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
pub trait IngressPool {
    /// Validated Ingress Pool Section
    fn validated(&self) -> &dyn PoolSection<ValidatedIngressArtifact>;

    /// Unvalidated Ingress Pool Section
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedIngressArtifact>;
}

/// Mutable operations on top of IngressPool.
pub trait MutableIngressPool: IngressPool {
    /// Insert an unvalidated artifact.
    fn insert(&mut self, unvalidated_artifact: UnvalidatedArtifact<SignedIngress>);

    /// Apply the change set.
    fn apply_changeset(&mut self, change_set: ChangeSet);
}

/// Indicate whether something should be selected, and whether selection should
/// continue:
/// - 'Selected': select the object and continue;
/// - 'Skip': skip the object and continue;
/// - 'Abort': abort the selection process.
pub enum SelectResult<T> {
    Selected(T),
    Skip,
    Abort,
}

/// A query interface that selects qualifying artifacts from the validated pool.
pub trait IngressPoolSelect {
    /// Select qualifying objects from the validated pool.
    fn select_validated<'a>(
        &self,
        range: std::ops::RangeInclusive<Time>,
        f: Box<dyn FnMut(&IngressPoolObject) -> SelectResult<SignedIngress> + 'a>,
    ) -> Vec<SignedIngress>;
}

/// Interface to throttle user ingress messages
pub trait IngressPoolThrottler {
    /// Checks if the total number of entries is within the configured threshold
    fn exceeds_threshold(&self) -> bool;
}
// end::interface[]
