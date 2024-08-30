//! Cryptographic types

// We disable clippy warnings for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module).
// (cf. DFN-467).
#![allow(clippy::unit_arg)]

pub use conversions::CspSecretKeyConversionError;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_crypto_internal_threshold_sig_ecdsa::{CommitmentOpeningBytes, MEGaKeySetK256Bytes};
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_types::crypto::AlgorithmId;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, IntoStaticStr};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod conversions;
mod external_conversion_utilities;

#[cfg(test)]
use ic_crypto_internal_threshold_sig_ecdsa::EccScalarBytes;
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use proptest_derive::Arbitrary;

#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

#[cfg(test)]
use test_utils::*;

pub use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;

/// The secret part of a public/private key pair.
///
/// This enum can be persisted in a `SecretKeyStore`.
#[derive(
    Clone, Eq, IntoStaticStr, PartialEq, Serialize, Deserialize, EnumCount, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspSecretKey {
    #[cfg_attr(test, proptest(strategy(arbitrary_ed25519_secret_key)))]
    Ed25519(ed25519_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_multi_bls12381_secret_key)))]
    MultiBls12_381(multi_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_threshold_bls12381_secret_key)))]
    ThresBls12_381(threshold_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_tls_ed25519_secret_key)))]
    TlsEd25519(TlsEd25519SecretKeyDerBytes),
    #[cfg_attr(test, proptest(value(default_fs_encryption_key_set)))]
    FsEncryption(CspFsEncryptionKeySet),
    #[cfg_attr(test, proptest(strategy(arbitrary_mega_k256_encryption_key_set)))]
    MEGaEncryptionK256(MEGaKeySetK256Bytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_threshold_ecdsa_opening)))]
    IDkgCommitmentOpening(CommitmentOpeningBytes),
}

impl CspSecretKey {
    /// Returns the enum name of this `CspSecretKey` instance as `&'static str`
    /// e.g. `CspSecretKey::Ed25519` returns "Ed25519"
    pub fn enum_variant(&self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
impl std::fmt::Debug for CspSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CspSecretKey::Ed25519(_) => write!(f, "CspSecretKey::Ed25519 - REDACTED"),
            CspSecretKey::MultiBls12_381(_) => write!(f, "CspSecretKey::MultiBls12_381 - REDACTED"),
            CspSecretKey::ThresBls12_381(_) => write!(f, "CspSecretKey::ThresBls12_381 - REDACTED"),
            CspSecretKey::TlsEd25519(_) => write!(f, "CspSecretKey::TlsEd25519 - REDACTED"),
            CspSecretKey::FsEncryption(_) => write!(f, "CspSecretKey::FsEncryption - REDACTED"),
            CspSecretKey::MEGaEncryptionK256(_) => {
                write!(f, "CspSecretKey::MEGaEncryptionK256 - REDACTED")
            }
            Self::IDkgCommitmentOpening(CommitmentOpeningBytes::Simple(s)) => {
                write!(
                    f,
                    "CspSecretKey::IDkgCommitmentOpening::Simple::{} - REDACTED",
                    s.curve_type(),
                )
            }
            Self::IDkgCommitmentOpening(CommitmentOpeningBytes::Pedersen(s, _)) => {
                write!(
                    f,
                    "CspSecretKey::IDkgCommitmentOpening::Pedersen::{} - REDACTED",
                    s.curve_type()
                )
            }
        }
    }
}

/// The public part of a public/private key pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspPublicKey {
    #[cfg_attr(test, proptest(strategy(arbitrary_ecdsa_secp256r1_public_key)))]
    EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_ecdsa_secp256k1_public_key)))]
    EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_ed25519_public_key)))]
    Ed25519(ed25519_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_multi_bls12381_public_key)))]
    MultiBls12_381(multi_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_rsa_public_key)))]
    RsaSha256(rsa::RsaPublicKey),
}

impl CspPublicKey {
    /// Return the ECDSA P-256 public key, or else None if the wrong type
    pub fn ecdsa_p256_bytes(&self) -> Option<&[u8]> {
        match self {
            CspPublicKey::EcdsaP256(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    /// Return the Ed25519 public key, or else None if the wrong type
    pub fn ed25519_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            CspPublicKey::Ed25519(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    /// Return the BLS12-381 public key, or else None if the wrong type
    pub fn multi_bls12_381_bytes(&self) -> Option<&[u8]> {
        match self {
            CspPublicKey::MultiBls12_381(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    /// Return the algorithm identifier of this public key
    pub fn algorithm_id(&self) -> AlgorithmId {
        match self {
            CspPublicKey::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspPublicKey::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspPublicKey::Ed25519(_) => AlgorithmId::Ed25519,
            CspPublicKey::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
            CspPublicKey::RsaSha256(_) => AlgorithmId::RsaSha256,
        }
    }

    /// Return the binary encoding of this public key
    pub fn pk_bytes(&self) -> &[u8] {
        match self {
            CspPublicKey::EcdsaSecp256k1(pk_bytes) => &pk_bytes.0,
            CspPublicKey::EcdsaP256(pk_bytes) => &pk_bytes.0,
            CspPublicKey::Ed25519(pk_bytes) => &pk_bytes.0,
            CspPublicKey::MultiBls12_381(pk_bytes) => &pk_bytes.0,
            CspPublicKey::RsaSha256(pk_bytes) => pk_bytes.as_der(),
        }
    }
}

/// A Proof of Possession (PoP)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CspPop {
    MultiBls12_381(multi_types::PopBytes),
}

/// A cryptographic signature generated by a private key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspSignature {
    #[cfg_attr(test, proptest(strategy(arbitrary_ecdsa_secp256r1_signature)))]
    EcdsaP256(ecdsa_secp256r1_types::SignatureBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_secp256k1_signature)))]
    EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_ed25519_signature)))]
    Ed25519(ed25519_types::SignatureBytes),
    MultiBls12_381(MultiBls12_381_Signature),
    ThresBls12_381(ThresBls12_381_Signature),
    RsaSha256(Vec<u8>),
}

impl std::fmt::Debug for CspSignature {
    /// Prints in a developer-friendly format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CspSignature::*;
        match self {
            EcdsaP256(data) => write!(f, "CspSignature::EcdsaP256({:?})", data),
            EcdsaSecp256k1(data) => write!(f, "CspSignature::EcdsaSecp256k1({:?})", data),
            Ed25519(data) => write!(f, "CspSignature::Ed25519({:?})", data),
            MultiBls12_381(data) => write!(f, "CspSignature::MultiBls12_381({:?})", data),
            ThresBls12_381(data) => write!(f, "CspSignature::ThresBls12_381({:?})", data),
            RsaSha256(data) => write!(f, "CspSignature::RsaSha256({:?})", base64::encode(data)),
        }
    }
}

/// A cryptographic signature generated by a BLS12-381 multisig key
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum MultiBls12_381_Signature {
    #[cfg_attr(
        test,
        proptest(strategy(arbitrary_multi_bls12381_individual_signature))
    )]
    Individual(multi_types::IndividualSignatureBytes),
    #[cfg_attr(test, proptest(strategy(arbitrary_multi_bls12381_combined_signature)))]
    Combined(multi_types::CombinedSignatureBytes),
}

/// A threshold BLS12-381 signature
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum ThresBls12_381_Signature {
    #[cfg_attr(
        test,
        proptest(strategy(arbitrary_threshold_bls12381_individual_signature))
    )]
    Individual(threshold_types::IndividualSignatureBytes),
    #[cfg_attr(
        test,
        proptest(strategy(arbitrary_threshold_bls12381_combined_signature))
    )]
    Combined(threshold_types::CombinedSignatureBytes),
}

impl CspSignature {
    #[cfg(test)]
    pub fn ed25519_bytes(&self) -> Option<&[u8; 64]> {
        match self {
            CspSignature::Ed25519(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    /// Return what algorithm was used to generate this signature
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            CspSignature::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspSignature::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspSignature::Ed25519(_) => AlgorithmId::Ed25519,
            CspSignature::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
            CspSignature::ThresBls12_381(_) => AlgorithmId::ThresBls12_381,
            CspSignature::RsaSha256(_) => AlgorithmId::RsaSha256,
        }
    }
}

/// A struct for converting signatures
///
/// Use SigConverter::for_target(alg).try_from_basic(signature) to convert
/// from the bytes of a signature to a CspSignature
pub struct SigConverter {
    target_algorithm: AlgorithmId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExternalPublicKeys {
    pub node_signing_public_key: PublicKey,
    pub committee_signing_public_key: PublicKey,
    pub tls_certificate: X509PublicKeyCert,
    pub dkg_dealing_encryption_public_key: PublicKey,
    pub idkg_dealing_encryption_public_key: PublicKey,
}
