//! Validation error types for the Phase-2 upgrade payload section.

use ic_types::{NodeId, RegistryVersion};

/// The reason why an upgrade payload was determined to be invalid. These are
/// reproducible: the same block will always be rejected.
#[derive(Debug)]
pub enum InvalidUpgradePayloadReason {
    /// A `Request` was issued for a node other than the block maker.
    RequestNodeMismatch { node: NodeId, proposer: NodeId },
    /// A `Request` pins a registry version other than the one the block is
    /// validated against.
    RequestRegistryVersionMismatch {
        node: NodeId,
        registry_version: RegistryVersion,
        expected: RegistryVersion,
    },
    /// A `Return` was issued for a node other than the block maker.
    ReturnNodeMismatch { node: NodeId, proposer: NodeId },
    /// The number of outstanding reboot requests meets or exceeds the subnet's
    /// capacity `P` (faults tolerated), so no further requests are permitted.
    SlotsExhausted { slots_in_use: usize, capacity: usize },
    /// An `Authorize` was issued for a node with no outstanding request.
    AuthorizeNoOutstandingRequest { node: NodeId },
    /// An `Authorize` contains an invalid share (bad signature, content
    /// mismatch, or signer is not a member).
    AuthorizeInvalidShare { signer: NodeId },
    /// An `Authorize` does not carry enough valid shares (≥ N−P).
    AuthorizeInsufficientShares { collected: usize, threshold: usize },
    /// Failed to decode the upgrade payload from protobuf.
    DecodeFailed(String),
}
