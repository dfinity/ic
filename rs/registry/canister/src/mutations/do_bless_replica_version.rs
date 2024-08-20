use candid::{CandidType, Deserialize};
use serde::Serialize;

/// DEPRECATED
/// This payload and proposal type is superseded by ReviseElectedGuestosVersions
///
/// The payload of a proposal to bless a given replica version.
///
/// To decouple proposal payload and registry content, this does not directly
/// import any part of the registry schema. However it is required that, from a
/// BlessReplicaVersionPayload, it is possible to construct a ReplicaVersionRecord.
///
/// See /rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlessReplicaVersionPayload {
    /// Version ID. This can be anything, it has not semantics. The reason it is
    /// part of the payload is that it will be needed in the subsequent step
    /// of upgrading individual subnets.
    pub replica_version_id: String,

    /// The URL against which a HTTP GET request will return a replica binary
    /// that corresponds to this version
    /// DEPRECATED: Not used, kept only for compatibility.
    pub binary_url: String,

    /// The hex-formatted SHA-256 hash of the binary served by 'binary_url'
    /// DEPRECATED: Not used, kept only for compatibility.
    pub sha256_hex: String,

    /// The URL against which a HTTP GET request will return a node manager
    /// binary that corresponds to this version
    /// DEPRECATED: Not used, kept only for compatibility.
    pub node_manager_binary_url: String,

    /// The hex-formatted SHA-256 hash of the binary served by
    /// 'node_manager_binary_url'
    /// DEPRECATED: Not used, kept only for compatibility.
    pub node_manager_sha256_hex: String,

    /// The URL against which a HTTP GET request will return a release package
    /// that corresponds to this version
    /// DEPRECATED. Superseded by release_package_urls (plural).
    pub release_package_url: String,

    /// The hex-formatted SHA-256 hash of the archive file served by
    /// 'release_package_urls'
    pub release_package_sha256_hex: String,

    /// The URLs against which a HTTP GET request will return the same release
    /// package that corresponds to this version
    /// This field is not optional but this is the only way to add a new field
    /// into a Candid message without breaking backward compatibility.
    pub release_package_urls: Option<Vec<String>>,

    /// The hex-formatted SHA-256 hash measurement of the SEV guest launch context.
    pub guest_launch_measurement_sha256_hex: Option<String>,
}
