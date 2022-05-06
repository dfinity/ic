/// A list of subnets that can sign with this ECDSA key.
/// This allows replicas to route their signing requests to the right subnets.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaSigningSubnetList {
    #[prost(message, repeated, tag="2")]
    pub subnets: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
/// A public key. Described by its `AlgorithmId`, the key's value and proof data holding, e.g., a proof of possession (PoP).
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(enumeration="AlgorithmId", tag="2")]
    pub algorithm: i32,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="4")]
    pub proof_data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// DER-encoded X509 public key certificate
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509PublicKeyCert {
    #[prost(bytes="vec", tag="1")]
    pub certificate_der: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(candid::CandidType, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyId {
    #[prost(enumeration="EcdsaCurve", tag="1")]
    pub curve: i32,
    #[prost(string, tag="2")]
    pub name: ::prost::alloc::string::String,
}
/// An algorithm ID. This is used to specify the signature algorithm associated with a public key.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AlgorithmId {
    Unspecified = 0,
    MultiBls12381 = 1,
    ThresBls12381 = 2,
    SchnorrSecp256k1 = 3,
    StaticDhSecp256k1 = 4,
    HashSha256 = 5,
    Tls = 6,
    Ed25519 = 7,
    Secp256k1 = 8,
    Groth20Bls12381 = 9,
    NidkgGroth20Bls12381 = 10,
    EcdsaP256 = 11,
    EcdsaSecp256k1 = 12,
    IcCanisterSignature = 13,
    RsaSha256 = 14,
    ThresholdEcdsaSecp256k1 = 15,
    MegaSecp256k1 = 16,
}
/// Types of curves that can be used for ECDSA signatures.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(candid::CandidType)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EcdsaCurve {
    Unspecified = 0,
    Secp256k1 = 1,
}
