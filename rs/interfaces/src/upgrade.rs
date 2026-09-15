use ic_types::NodeId;
use ic_types::artifact::UpgradePermitAuthorizationShareId;
use ic_types::consensus::UpgradePermitAuthorizationShare;

#[derive(Debug, Eq, PartialEq)]
pub enum InvalidUpgradePayloadReason {
    /// A `Request` was issued for a node other than the block maker.
    RequestNodeMismatch { node: NodeId, proposer: NodeId },
    /// A `Return` was issued for a node other than the block maker.
    ReturnNodeMismatch { node: NodeId, proposer: NodeId },
    /// The number of outstanding permits (requested or authorized) meets
    /// the subnet's maximum number of rebooting nodes.
    SlotsExhausted { slots_in_use: usize, permits: usize },
    /// An `Authorize` was issued for a node with no outstanding request.
    AuthorizeNoOutstandingRequest { node: NodeId },
    /// An `Authorize` contains an invalid share (bad signature, content
    /// mismatch, or signer is not a member).
    AuthorizeInvalidShare { signer: NodeId },
    /// An `Authorize` does not carry enough valid shares (≥ the active
    /// staying nodes).
    AuthorizeInsufficientShares { collected: usize, threshold: usize },
    /// Failed to decode the upgrade payload from protobuf.
    DecodeFailed(String),
}

/// Change actions that can be applied to the [`UpgradePermitAuthPool`].
#[derive(Debug)]
pub enum UpgradePermitAuthChangeAction {
    /// Add a locally-produced share directly to validated.
    AddToValidated(UpgradePermitAuthorizationShare),
    /// Move a gossiped share from unvalidated to validated (after signature
    /// verification).
    MoveToValidated(UpgradePermitAuthorizationShare),
    /// Remove a validated share (e.g. after the request was authorized or
    /// timed out).
    RemoveValidated(UpgradePermitAuthorizationShareId),
    /// Remove an unvalidated share.
    RemoveUnvalidated(UpgradePermitAuthorizationShareId),
    /// Handle an invalid share (bad signature, no matching request, etc.).
    HandleInvalid(UpgradePermitAuthorizationShareId, String),
}

pub type UpgradePermitAuthChangeSet = Vec<UpgradePermitAuthChangeAction>;

/// Query interface for the upgrade permit authorization pool.
pub trait UpgradePermitAuthPool: Send + Sync {
    /// Return an iterator over all validated shares.
    fn get_validated_shares(
        &self,
    ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_>;
    /// Return an iterator over all unvalidated shares.
    fn get_unvalidated_shares(
        &self,
    ) -> Box<dyn Iterator<Item = &UpgradePermitAuthorizationShare> + '_>;
}
