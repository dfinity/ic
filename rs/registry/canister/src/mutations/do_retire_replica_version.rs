use candid::{CandidType, Deserialize};
use serde::Serialize;

/// DEPRECATED
/// This payload and proposal type is superseded by ReviseElectedGuestosVersions
///
/// The payload of a proposal to retire a set of replica versions.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from an
/// RetireReplicaVersionPayload, it is possible to construct a ReplicaVersionRecord.
///
/// See /rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RetireReplicaVersionPayload {
    /// Version IDs. These can be anything, they have no semantics.
    pub replica_version_ids: Vec<String>,
}
