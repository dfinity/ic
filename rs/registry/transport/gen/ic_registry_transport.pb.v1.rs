/// Message corresponding to an error while performing
/// an operation on the registry.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryError {
    #[prost(enumeration="registry_error::Code", tag="1")]
    pub code: i32,
    /// The reason for the error.
    /// This is optional.
    #[prost(string, tag="2")]
    pub reason: ::prost::alloc::string::String,
    /// The key on which the error occurred.
    /// This is optional and only present for by-key errors.
    #[prost(bytes="vec", tag="3")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `RegistryError`.
pub mod registry_error {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Code {
        /// The message had a problem like a missing field
        /// or a field that was set when it shouldn't.
        MalformedMessage = 0,
        /// The 'key' specified on the request was not present
        /// in the registry.
        KeyNotPresent = 1,
        /// The 'key' specified on the request was already present.
        KeyAlreadyPresent = 2,
        /// The 'version' specified in a precondition for a mutation
        /// was not the lastest version.
        VersionNotLatest = 3,
        /// The 'version' specified in a precondition for a mutation
        /// is beyond the latest version in the registry.
        VersionBeyondLatest = 4,
        /// A generic internal error occurred in the registry.
        InternalError = 999,
    }
}
/// A single change made to a key in the registry.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryValue {
    /// The value that was set in this mutation. If the
    /// mutation is a deletion, the field has no meaning.
    #[prost(bytes="vec", tag="1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    /// The version at which this mutation happened.
    #[prost(uint64, tag="2")]
    pub version: u64,
    /// If true, this change represents a deletion.
    #[prost(bool, tag="3")]
    pub deletion_marker: bool,
}
/// A sequence of changes made to a key in the registry.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryDelta {
    #[prost(bytes="vec", tag="1")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag="2")]
    pub values: ::prost::alloc::vec::Vec<RegistryValue>,
}
/// Message to retrieve all the changes from the registry
/// since 'version'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryGetChangesSinceRequest {
    #[prost(uint64, tag="1")]
    pub version: u64,
}
/// Message corresponding to the response from the registry
/// canister to a get_latest_version() request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryGetChangesSinceResponse {
    /// If anything went wrong, the registry canister
    /// will set this error.
    #[prost(message, optional, tag="1")]
    pub error: ::core::option::Option<RegistryError>,
    /// The last version of the registry.
    #[prost(uint64, tag="2")]
    pub version: u64,
    /// A list of all the keys and all the values that change
    /// and all the intermediate changes since the version
    /// requested.
    #[prost(message, repeated, tag="3")]
    pub deltas: ::prost::alloc::vec::Vec<RegistryDelta>,
}
/// Message to retrieve a version of some registry key
/// from the registry canister.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryGetValueRequest {
    /// The version of the registry key to retrieve.
    /// Optional: If not set (or set to the default value, 0), the method
    /// will return the last version.
    #[prost(message, optional, tag="1")]
    pub version: ::core::option::Option<u64>,
    /// The byte array corresponding to the key to retrieve
    /// from the registry.
    /// Required.
    #[prost(bytes="vec", tag="2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
/// Message corresponding to the response from the canister
/// to a get_value() request.
///
/// Both 'version' and 'value' are mandatorily set if 'error'
/// is not set.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryGetValueResponse {
    /// If anything went wrong, the registry canister
    /// will set this error.
    #[prost(message, optional, tag="1")]
    pub error: ::core::option::Option<RegistryError>,
    /// the version at which the value corresponding to the queried
    /// key was last mutated (inserted, updated, or deleted)
    /// before at or at the version specified
    /// in the RegistryGetValueRequest.
    #[prost(uint64, tag="2")]
    pub version: u64,
    /// The value retrieved from the registry.
    #[prost(bytes="vec", tag="3")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Message corresponding to the response from the canister
/// to a get_latest_version() request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryGetLatestVersionResponse {
    /// the latest registry version
    #[prost(uint64, tag="1")]
    pub version: u64,
}
/// A single mutation in the registry.
#[derive(candid::CandidType, candid::Deserialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryMutation {
    /// The type of the mutation to apply to the registry.
    /// Always required.
    #[prost(enumeration="registry_mutation::Type", tag="1")]
    pub mutation_type: i32,
    /// The key of the entry to mutate in the registry.
    /// Always required.
    #[prost(bytes="vec", tag="2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    /// The value to mutate in the registry.
    /// Required for insert, update, but not for delete.
    #[prost(bytes="vec", tag="3")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `RegistryMutation`.
pub mod registry_mutation {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        /// Key is expected to not exist in the registry at the current version.
        /// (This includes the case of a key that has existed in the past and
        /// later got deleted).
        /// The mutation will fail otherwise.
        Insert = 0,
        /// Key is expected to exist in the registry at the current version.
        /// The mutation will fail otherwise.
        Update = 1,
        /// Key is expected to exist in the registry at the current version.
        /// The mutation will fail otherwise.
        Delete = 2,
        /// If the key does not exist at the current version, it will be created.
        /// Otherwise, the value will be updated. The name is common in the
        /// database world, and means Update or Insert.
        Upsert = 4,
    }
}
/// A precondition on the version at which the value of a given key was
/// last mutated.
#[derive(candid::CandidType, candid::Deserialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Precondition {
    #[prost(bytes="vec", tag="1")]
    pub key: ::prost::alloc::vec::Vec<u8>,
    /// The precondition is satisfied if and only is the version in the
    /// RegistryValue for the key is equal to this.
    #[prost(uint64, tag="2")]
    pub expected_version: u64,
}
/// Message corresponding to a list of mutations to apply, atomically, to the
/// registry canister. If any of the mutations fails, the whole operation will fail.
#[derive(candid::CandidType, candid::Deserialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryAtomicMutateRequest {
    /// The set of mutations to apply to the registry.
    #[prost(message, repeated, tag="1")]
    pub mutations: ::prost::alloc::vec::Vec<RegistryMutation>,
    /// Preconditions at the key level.
    #[prost(message, repeated, tag="5")]
    pub preconditions: ::prost::alloc::vec::Vec<Precondition>,
}
/// Message corresponding to the response of an atomic_mutate request. If any of
/// mutations failed the corresponding errors will be reflected in 'errors'.
/// Otherwise 'version' will contain the version under which all the mutations
/// were applied.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryAtomicMutateResponse {
    /// If anything went wrong, the registry canister
    /// will set this error.
    #[prost(message, repeated, tag="1")]
    pub errors: ::prost::alloc::vec::Vec<RegistryError>,
    /// The last version of the registry.
    #[prost(uint64, tag="2")]
    pub version: u64,
}
/// Message encoding a response to any *_certified method call.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertifiedResponse {
    /// The hash tree encoding both the response and the intermediate
    /// nodes required to recompute the root hash stored in
    /// "certified_data" of the canister.
    ///
    /// Note that the contents of the tree depends on the type of request
    /// issued.
    #[prost(message, optional, tag="1")]
    pub hash_tree: ::core::option::Option<::ic_protobuf::messaging::xnet::v1::MixedHashTree>,
    /// The certificate obtained from the system using
    /// ic0.data_certificate_copy.
    #[prost(bytes="vec", tag="2")]
    pub certificate: ::prost::alloc::vec::Vec<u8>,
}
