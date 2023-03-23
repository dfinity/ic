#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateMetadata {
    #[prost(message, optional, tag = "1")]
    pub manifest: ::core::option::Option<super::sync::v1::Manifest>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatesMetadata {
    /// Checkpoint metadata indexed by height.
    #[prost(btree_map = "uint64, message", tag = "1")]
    pub by_height: ::prost::alloc::collections::BTreeMap<u64, StateMetadata>,
}
