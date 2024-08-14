/// Information about a HostOS version
///
/// New versions are added as keys with a common prefix, after a vote has been
/// accepted by token holders. Nodes can then be upgraded to any of those
/// versions. hostos_version_id commonly matches release_package_sha256_hex,
/// and is used in the key for this record.
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HostosVersionRecord {
    /// The URLs against which a HTTP GET request will return a release package
    /// that corresponds to this version.
    #[prost(string, repeated, tag = "1")]
    pub release_package_urls: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The hex-formatted SHA-256 hash of the archive file served by 'release_package_url'.
    #[prost(string, tag = "2")]
    pub release_package_sha256_hex: ::prost::alloc::string::String,
    /// The ID used to reference this version. (This is often the same as release_package_sha256_hex, but does not have to be.)
    #[prost(string, tag = "3")]
    pub hostos_version_id: ::prost::alloc::string::String,
}
