/// Information about a Replica version
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaVersionRecord {
    /// The URL against which a HTTP GET request will return a release package
    /// that corresponds to this version
    #[prost(string, tag="5")]
    pub release_package_url: ::prost::alloc::string::String,
    /// The hex-formatted SHA-256 hash of the archive file served by 'release_package_url'
    #[prost(string, tag="6")]
    pub release_package_sha256_hex: ::prost::alloc::string::String,
}
/// A list of blessed versions of the IC Replica
///
/// New versions are added here after a vote has been accepted by token
/// holders. Subnetworks can then be upgraded to any of those version.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlessedReplicaVersions {
    /// A list of version information ids.
    #[prost(string, repeated, tag="1")]
    pub blessed_version_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
