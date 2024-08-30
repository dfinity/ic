/// A list of subnets that can sign with this ECDSA key.
/// This allows replicas to route their signing requests to the right subnets.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaSigningSubnetList {
    #[prost(message, repeated, tag = "2")]
    pub subnets: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
/// A list of subnets that can sign with a given chain key.
/// This allows replicas to route their signing requests to the right subnets.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainKeySigningSubnetList {
    #[prost(message, repeated, tag = "1")]
    pub subnets: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
/// A public key. Described by its `AlgorithmId`, the key's value and proof data holding, e.g., a proof of possession (PoP).
#[allow(clippy::derive_partial_eq_without_eq)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509PublicKeyCert {
    #[prost(bytes = "vec", tag = "1")]
    pub certificate_der: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyId {
    #[prost(enumeration = "EcdsaCurve", tag = "1")]
    pub curve: i32,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchnorrKeyId {
    #[prost(enumeration = "SchnorrAlgorithm", tag = "1")]
    pub algorithm: i32,
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MasterPublicKeyId {
    #[prost(oneof = "master_public_key_id::KeyId", tags = "1, 2")]
    pub key_id: ::core::option::Option<master_public_key_id::KeyId>,
}
/// Nested message and enum types in `MasterPublicKeyId`.
pub mod master_public_key_id {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum KeyId {
        #[prost(message, tag = "1")]
        Ecdsa(super::EcdsaKeyId),
        #[prost(message, tag = "2")]
        Schnorr(super::SchnorrKeyId),
    }
}
/// An algorithm ID. This is used to specify the signature algorithm associated with a public key.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
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
    ThresholdEcdsaSecp256r1 = 17,
    ThresholdSchnorrBip340 = 18,
    ThresholdEd25519 = 19,
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
            AlgorithmId::ThresholdEcdsaSecp256r1 => "ALGORITHM_ID_THRESHOLD_ECDSA_SECP_256R1",
            AlgorithmId::ThresholdSchnorrBip340 => "ALGORITHM_ID_THRESHOLD_SCHNORR_BIP340",
            AlgorithmId::ThresholdEd25519 => "ALGORITHM_ID_THRESHOLD_ED25519",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ALGORITHM_ID_UNSPECIFIED" => Some(Self::Unspecified),
            "ALGORITHM_ID_MULTI_BLS12_381" => Some(Self::MultiBls12381),
            "ALGORITHM_ID_THRES_BLS12_381" => Some(Self::ThresBls12381),
            "ALGORITHM_ID_SCHNORR_SECP256K1" => Some(Self::SchnorrSecp256k1),
            "ALGORITHM_ID_STATIC_DH_SECP256K1" => Some(Self::StaticDhSecp256k1),
            "ALGORITHM_ID_HASH_SHA256" => Some(Self::HashSha256),
            "ALGORITHM_ID_TLS" => Some(Self::Tls),
            "ALGORITHM_ID_ED25519" => Some(Self::Ed25519),
            "ALGORITHM_ID_SECP256K1" => Some(Self::Secp256k1),
            "ALGORITHM_ID_GROTH20_BLS12_381" => Some(Self::Groth20Bls12381),
            "ALGORITHM_ID_NIDKG_GROTH20_BLS12_381" => Some(Self::NidkgGroth20Bls12381),
            "ALGORITHM_ID_ECDSA_P256" => Some(Self::EcdsaP256),
            "ALGORITHM_ID_ECDSA_SECP_256K1" => Some(Self::EcdsaSecp256k1),
            "ALGORITHM_ID_IC_CANISTER_SIGNATURE" => Some(Self::IcCanisterSignature),
            "ALGORITHM_ID_RSA_SHA256" => Some(Self::RsaSha256),
            "ALGORITHM_ID_THRESHOLD_ECDSA_SECP_256K1" => Some(Self::ThresholdEcdsaSecp256k1),
            "ALGORITHM_ID_MEGA_SECP_256K1" => Some(Self::MegaSecp256k1),
            "ALGORITHM_ID_THRESHOLD_ECDSA_SECP_256R1" => Some(Self::ThresholdEcdsaSecp256r1),
            "ALGORITHM_ID_THRESHOLD_SCHNORR_BIP340" => Some(Self::ThresholdSchnorrBip340),
            "ALGORITHM_ID_THRESHOLD_ED25519" => Some(Self::ThresholdEd25519),
            _ => None,
        }
    }
}
/// Types of curves that can be used for ECDSA signatures.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
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
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ECDSA_CURVE_UNSPECIFIED" => Some(Self::Unspecified),
            "ECDSA_CURVE_SECP256K1" => Some(Self::Secp256k1),
            _ => None,
        }
    }
}
/// Types of curves that can be used for Schnorr signatures.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum SchnorrAlgorithm {
    Unspecified = 0,
    Bip340secp256k1 = 1,
    Ed25519 = 2,
}
impl SchnorrAlgorithm {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            SchnorrAlgorithm::Unspecified => "SCHNORR_ALGORITHM_UNSPECIFIED",
            SchnorrAlgorithm::Bip340secp256k1 => "SCHNORR_ALGORITHM_BIP340SECP256K1",
            SchnorrAlgorithm::Ed25519 => "SCHNORR_ALGORITHM_ED25519",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SCHNORR_ALGORITHM_UNSPECIFIED" => Some(Self::Unspecified),
            "SCHNORR_ALGORITHM_BIP340SECP256K1" => Some(Self::Bip340secp256k1),
            "SCHNORR_ALGORITHM_ED25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}
