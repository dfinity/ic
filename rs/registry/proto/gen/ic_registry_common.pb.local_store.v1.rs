/// Set of all mutations that, when applied to the registry at version v,
/// produce the registry at version v+1
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChangelogEntry {
    /// The default, an empty list, is _invalid_ here.
    #[prost(message, repeated, tag="1")]
    pub key_mutations: ::prost::alloc::vec::Vec<KeyMutation>,
}
/// A mutation of a single key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyMutation {
    /// Key.
    #[prost(string, tag="1")]
    pub key: ::prost::alloc::string::String,
    /// Protobuf encoded value.
    #[prost(bytes="vec", tag="2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    /// If this is `UNSET`, `value` must assume the default value.
    #[prost(enumeration="MutationType", tag="3")]
    pub mutation_type: i32,
}
/// The time when the last certified update was successfully received.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertifiedTime {
    /// Number of nano seconds since UNIX EPOCH
    #[prost(uint64, tag="1")]
    pub unix_epoch_nanos: u64,
}
/// A changelog that is applicable at a specific registry version.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Delta {
    #[prost(uint64, tag="1")]
    pub registry_version: u64,
    #[prost(message, repeated, tag="2")]
    pub changelog: ::prost::alloc::vec::Vec<ChangelogEntry>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MutationType {
    /// Illegal state.
    InvalidState = 0,
    /// The value was SET in this delta.
    Set = 1,
    /// The value was UNSET in this delta.
    Unset = 2,
}
