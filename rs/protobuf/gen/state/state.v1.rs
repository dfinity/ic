#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateMetadata {
    #[prost(message, optional, tag="1")]
    pub manifest: ::core::option::Option<super::sync::v1::Manifest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatesMetadata {
    /// Checkpoint metadata indexed by height.
    #[prost(btree_map="uint64, message", tag="1")]
    pub by_height: ::prost::alloc::collections::BTreeMap<u64, StateMetadata>,
    /// The largest height passed to `StateManager::remove_states_below()`.
    #[prost(uint64, tag="2")]
    pub oldest_required_state: u64,
}
