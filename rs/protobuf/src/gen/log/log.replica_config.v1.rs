#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaConfig {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub subnet_id: ::prost::alloc::vec::Vec<u8>,
}
