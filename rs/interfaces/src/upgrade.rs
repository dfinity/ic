//! Validation error types for the Phase-2 upgrade payload section.

use ic_types::NodeId;

/// The reason why an upgrade payload was determined to be invalid. These are
/// reproducible: the same block will always be rejected.
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
