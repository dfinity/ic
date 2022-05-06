#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChangelogEntry {
    /// The version that this mutation produced.
    #[prost(uint64, tag="1")]
    pub version: u64,
    /// Serialized value of
    /// ic_registry_transport.pb.v1.RegistryAtomicMutateRequest, with all
    /// preconditions removed (as they had been checked already).
    ///
    /// We use bytes instead of actual value to make sure that the hash
    /// of a changelog entry never changes. If we stored the protobuf
    /// type, this might not be the case. E.g., if some field that was
    /// present in old entries is removed from the proto schema.
    #[prost(bytes="vec", tag="2")]
    pub encoded_mutation: ::prost::alloc::vec::Vec<u8>,
}
/// Just a container for a set of RegistryDelta that can be used to
/// serialize/deserialize the content of the registry.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryStableStorage {
    /// Version of the stable store representation.
    ///
    /// The fields below can be present / missing depending on the value
    /// of this field.  See comments for the Version enum above for more
    /// details.
    #[prost(enumeration="registry_stable_storage::Version", tag="2")]
    pub version: i32,
    /// Only present if version == VERSION_UNSPECIFIED.
    #[prost(message, repeated, tag="1")]
    pub deltas: ::prost::alloc::vec::Vec<::ic_registry_transport::pb::v1::RegistryDelta>,
    /// Only present if version == VERSION_1.
    #[prost(message, repeated, tag="3")]
    pub changelog: ::prost::alloc::vec::Vec<ChangelogEntry>,
}
/// Nested message and enum types in `RegistryStableStorage`.
pub mod registry_stable_storage {
    /// Difference between stable versions
    /// ==================================
    ///
    /// The original representation (VERSION_UNSPECIFIED) is based on
    /// RegistryDelta structure, which is indexed by key:
    ///
    /// ```text
    ///     \[key1\] => { (v1, value11), (v3, value12) }    // first delta
    ///     \[key2\] => { (v2, value21), (v3, value22) }    // second delta
    /// ```
    ///
    /// VERSION_1 representation is based on ChangelogEntry structure
    /// that is indexed by version and preserve the history of changes
    /// applied to the registry:
    ///
    /// ```text
    ///     \[v1\] => { (UPSERT, key1, value11) } // first changelog entry
    ///     \[v2\] => { (UPSERT, key2, value21) } // second changelog entry
    ///     \[v3\] => { (UPSERT, key1, value12)
    ///             , (UPSERT, key2, value22) } // third changelog entry
    /// ```
    ///
    /// Those representations are almost equivalent. It's easy to go
    /// from the new representation to the old one, but not so trivial
    /// to go into the opposite direction.
    ///
    /// In order to make the conversion unique, we normalize entries in the
    /// changelog:
    ///
    ///   * We sort keys in each mutation request.
    ///   * We replace INSERT/UPDATE/UPSERT with just UPSERT.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Version {
        /// The original representation that contains a list of
        /// RegistryDeltas (tag 1).
        Unspecified = 0,
        /// The representation based on changelog (tag 3).
        Version1 = 1,
    }
}
/// A container for the what gets written to stable storage,
/// from the registry canister.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryCanisterStableStorage {
    #[prost(message, optional, tag="2")]
    pub registry: ::core::option::Option<RegistryStableStorage>,
    /// Used to check that the latest version of the registry has not been rolled
    /// back after an upgrade
    #[prost(uint64, optional, tag="3")]
    pub pre_upgrade_version: ::core::option::Option<u64>,
}
/// Maps Node Provider IDs to the amount (in 10,000ths of an SDR) they should be
/// rewarded for providing nodes to the Internet Computer for the month.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeProvidersMonthlyXdrRewards {
    #[prost(map="string, uint64", tag="1")]
    pub rewards: ::std::collections::HashMap<::prost::alloc::string::String, u64>,
}
