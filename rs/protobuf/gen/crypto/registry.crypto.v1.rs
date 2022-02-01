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
    MegaSecp256k1 = 14,
}
