//! The types defined here used to be defined in
//! rs/registry/transport/proto/ic_registry_transport/pb/v1/transport.proto .
//!
//! For the purposes of encoding responses (from the Registry canister), these
//! have been superceded by new types in transport.proto whose names begin with
//! "HighCapacity". Nevertheless, these types are still used internally within
//! the Registry canister; therefore, they have been transplanted here from the
//! Prost-generated code in the gen directory. Some light modifications have
//! been made to strip away the ability to do Protocol Buffers encoding and
//! decoding.

/// A single change made to a key in the registry.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RegistryValue {
    /// The value that was set in this mutation. If the
    /// mutation is a deletion, the field has no meaning.
    pub value: Vec<u8>,

    /// The version at which this mutation happened.
    pub version: u64,

    /// If true, this change represents a deletion.
    pub deletion_marker: bool,

    /// The timestamp at which the registry mutation happened.
    pub timestamp_nanoseconds: u64,
}

/// A sequence of changes made to a key in the registry.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RegistryDelta {
    pub key: Vec<u8>,

    pub values: Vec<RegistryValue>,
}
