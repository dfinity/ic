#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterSnapshotBits {
    #[prost(uint64, tag = "1")]
    pub snapshot_id: u64,
    #[prost(message, optional, tag = "2")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag = "3")]
    pub taken_at_timestamp: u64,
    #[prost(uint64, tag = "4")]
    pub canister_version: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub certified_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub binary_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, optional, tag = "7")]
    pub wasm_chunk_store_metadata:
        ::core::option::Option<super::super::canister_state_bits::v1::WasmChunkStoreMetadata>,
    #[prost(uint64, tag = "8")]
    pub stable_memory_size: u64,
    #[prost(uint64, tag = "9")]
    pub wasm_memory_size: u64,
    #[prost(uint64, tag = "10")]
    pub total_size: u64,
}
