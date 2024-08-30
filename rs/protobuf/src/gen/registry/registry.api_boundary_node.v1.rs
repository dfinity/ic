#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApiBoundaryNodeRecord {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
}
