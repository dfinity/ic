#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtoRegistry {
    #[prost(message, repeated, tag="1")]
    pub records: ::prost::alloc::vec::Vec<ProtoRegistryRecord>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtoRegistryRecord {
    #[prost(string, tag="1")]
    pub key: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub version: u64,
    #[prost(message, optional, tag="3")]
    pub value: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
