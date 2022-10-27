/// A list of subnets that can sign with this ECDSA key.
/// This allows replicas to route their signing requests to the right subnets.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaSigningSubnetList {
    #[prost(message, repeated, tag = "2")]
    pub subnets: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
/// A public key. Described by its `AlgorithmId`, the key's value and proof data holding, e.g., a proof of possession (PoP).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(enumeration = "AlgorithmId", tag = "2")]
    pub algorithm: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Number of non-leap-milliseconds since January 1, 1970 UTC.
    #[prost(message, optional, tag = "5")]
    pub timestamp: ::core::option::Option<u64>,
}
/// DER-encoded X509 public key certificate
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509PublicKeyCert {
    #[prost(bytes = "vec", tag = "1")]
    pub certificate_der: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyId {
    #[prost(enumeration = "EcdsaCurve", tag = "1")]
    pub curve: i32,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
}
/// An algorithm ID. This is used to specify the signature algorithm associated with a public key.
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
impl AlgorithmId {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AlgorithmId::Unspecified => "ALGORITHM_ID_UNSPECIFIED",
            AlgorithmId::MultiBls12381 => "ALGORITHM_ID_MULTI_BLS12_381",
            AlgorithmId::ThresBls12381 => "ALGORITHM_ID_THRES_BLS12_381",
            AlgorithmId::SchnorrSecp256k1 => "ALGORITHM_ID_SCHNORR_SECP256K1",
            AlgorithmId::StaticDhSecp256k1 => "ALGORITHM_ID_STATIC_DH_SECP256K1",
            AlgorithmId::HashSha256 => "ALGORITHM_ID_HASH_SHA256",
            AlgorithmId::Tls => "ALGORITHM_ID_TLS",
            AlgorithmId::Ed25519 => "ALGORITHM_ID_ED25519",
            AlgorithmId::Secp256k1 => "ALGORITHM_ID_SECP256K1",
            AlgorithmId::Groth20Bls12381 => "ALGORITHM_ID_GROTH20_BLS12_381",
            AlgorithmId::NidkgGroth20Bls12381 => "ALGORITHM_ID_NIDKG_GROTH20_BLS12_381",
            AlgorithmId::EcdsaP256 => "ALGORITHM_ID_ECDSA_P256",
            AlgorithmId::EcdsaSecp256k1 => "ALGORITHM_ID_ECDSA_SECP_256K1",
            AlgorithmId::IcCanisterSignature => "ALGORITHM_ID_IC_CANISTER_SIGNATURE",
            AlgorithmId::RsaSha256 => "ALGORITHM_ID_RSA_SHA256",
            AlgorithmId::ThresholdEcdsaSecp256k1 => "ALGORITHM_ID_THRESHOLD_ECDSA_SECP_256K1",
            AlgorithmId::MegaSecp256k1 => "ALGORITHM_ID_MEGA_SECP_256K1",
        }
    }
}
/// Types of curves that can be used for ECDSA signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EcdsaCurve {
    Unspecified = 0,
    Secp256k1 = 1,
}
impl EcdsaCurve {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            EcdsaCurve::Unspecified => "ECDSA_CURVE_UNSPECIFIED",
            EcdsaCurve::Secp256k1 => "ECDSA_CURVE_SECP256K1",
        }
    }
}
