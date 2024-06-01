/// State tree root hash.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationContent {
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// Certification of state tree root hash.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Certification {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<CertificationContent>,
    #[prost(message, optional, tag = "3")]
    pub signature: ::core::option::Option<super::super::super::types::v1::ThresholdSignature>,
}
/// Certification signed by a single replica
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationShare {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub content: ::core::option::Option<CertificationContent>,
    #[prost(message, optional, tag = "3")]
    pub signature: ::core::option::Option<super::super::super::types::v1::ThresholdSignatureShare>,
}
/// XNet stream slice with certification and matching Merkle proof.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertifiedStreamSlice {
    /// Serialized part of the state tree containing the stream data.
    #[prost(bytes = "vec", tag = "1")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    /// Witness that can be used to recompute the root hash from the payload.
    #[prost(bytes = "vec", tag = "2")]
    pub merkle_proof: ::prost::alloc::vec::Vec<u8>,
    /// Certification of the root hash.
    #[prost(message, optional, tag = "3")]
    pub certification: ::core::option::Option<Certification>,
}
