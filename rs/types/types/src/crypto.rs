//! Defines crypto component types.
pub mod canister_threshold_sig;
pub mod dkg;
pub mod error;
pub mod threshold_sig;

use crate::crypto::threshold_sig::ni_dkg::DkgId;
use crate::registry::RegistryClientError;
use crate::{CountBytes, NodeId, RegistryVersion, SubnetId};
use core::fmt::Formatter;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::ThresholdSigPublicKeyBytesConversionError;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use phantom_newtype::Id;
#[cfg(all(test, not(target_arch = "wasm32")))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use strum_macros::EnumIter;

/// An id of a key. These ids are used to refer to entries in the crypto secret
/// key store.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyId(pub [u8; 32]);
ic_crypto_internal_types::derive_serde!(KeyId, 32);

#[cfg(test)]
mod tests;

impl KeyId {
    pub fn get(&self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}
impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}

/// A cryptographic hash.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct CryptoHash(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl fmt::Debug for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoHash(0x{})", hex::encode(self.0.clone()))
    }
}

/// A cryptographic hash for content of type `T`
pub type CryptoHashOf<T> = Id<T, CryptoHash>;

/// Signed contains the signed content and its signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signed<T, S> {
    pub content: T,
    pub signature: S,
}

impl<T: CountBytes, S: CountBytes> CountBytes for Signed<T, S> {
    fn count_bytes(&self) -> usize {
        self.content.count_bytes() + self.signature.count_bytes()
    }
}

/// Signed bytes, not containing a domain separator. Also refer to the doc of
/// `SignedBytesWithoutDomainSeparator::
/// as_signed_bytes_without_domain_separator`.
pub trait SignedBytesWithoutDomainSeparator {
    /// Returns a bytes-representation of the object for digital signatures.
    /// The returned value together with a domain-separator (that can be empty,
    /// depending on the type) are the bytes that are used for
    /// signing/verification.
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8>;
}

/// A purpose of a key. This is used for storing and retrieving keys from the
/// registry.
// WARNING: The integer values of those enums discriminant is used in serialized
// data. This means that existing discriminants should never change. Obsolete
// discriminants should be marked as being never reusable.
#[derive(
    Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cfg_attr(all(test, not(target_arch = "wasm32")), derive(Arbitrary))]
pub enum KeyPurpose {
    Placeholder = 0,
    NodeSigning = 1,
    QueryResponseSigning = 2,
    DkgDealingEncryption = 3,
    CommitteeSigning = 4,
    IDkgMEGaEncryption = 5,
}

/// An algorithm ID. This is used to specify the signature algorithm associated
/// with a public key.
#[derive(
    Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize,
)]
#[cfg_attr(all(test, not(target_arch = "wasm32")), derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum AlgorithmId {
    Placeholder = 0,
    MultiBls12_381 = 1,
    ThresBls12_381 = 2,
    SchnorrSecp256k1 = 3,
    StaticDhSecp256k1 = 4,
    HashSha256 = 5,
    Tls = 6,
    Ed25519 = 7,
    Secp256k1 = 8,
    Groth20_Bls12_381 = 9,
    NiDkg_Groth20_Bls12_381 = 10,
    EcdsaP256 = 11,
    EcdsaSecp256k1 = 12,
    IcCanisterSignature = 13,
    RsaSha256 = 14,
    ThresholdEcdsaSecp256k1 = 15,
}

impl From<CspThresholdSigPublicKey> for AlgorithmId {
    fn from(public_key: CspThresholdSigPublicKey) -> Self {
        match public_key {
            CspThresholdSigPublicKey::ThresBls12_381(_) => AlgorithmId::ThresBls12_381,
        }
    }
}

impl From<&CspPublicCoefficients> for AlgorithmId {
    fn from(public_coeffs: &CspPublicCoefficients) -> Self {
        match public_coeffs {
            CspPublicCoefficients::Bls12_381(_) => AlgorithmId::ThresBls12_381,
        }
    }
}

impl From<usize> for KeyPurpose {
    fn from(key_purpose: usize) -> Self {
        match key_purpose {
            1 => KeyPurpose::NodeSigning,
            2 => KeyPurpose::QueryResponseSigning,
            3 => KeyPurpose::DkgDealingEncryption,
            4 => KeyPurpose::CommitteeSigning,
            _ => KeyPurpose::Placeholder,
        }
    }
}

impl From<i32> for AlgorithmId {
    fn from(algorithm_id: i32) -> Self {
        match algorithm_id {
            1 => AlgorithmId::MultiBls12_381,
            2 => AlgorithmId::ThresBls12_381,
            3 => AlgorithmId::SchnorrSecp256k1,
            4 => AlgorithmId::StaticDhSecp256k1,
            5 => AlgorithmId::HashSha256,
            6 => AlgorithmId::Tls,
            7 => AlgorithmId::Ed25519,
            8 => AlgorithmId::Secp256k1,
            9 => AlgorithmId::Groth20_Bls12_381,
            10 => AlgorithmId::NiDkg_Groth20_Bls12_381,
            11 => AlgorithmId::EcdsaP256,
            12 => AlgorithmId::EcdsaSecp256k1,
            13 => AlgorithmId::IcCanisterSignature,
            14 => AlgorithmId::RsaSha256,
            15 => AlgorithmId::ThresholdEcdsaSecp256k1,
            _ => AlgorithmId::Placeholder,
        }
    }
}

/// A public key of a user interacting with the IC.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserPublicKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub algorithm_id: AlgorithmId,
}

impl fmt::Display for UserPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "algorithm_id: {:?}, key: 0x{}",
            self.algorithm_id,
            hex::encode(&self.key)
        )
    }
}

impl CountBytes for UserPublicKey {
    fn count_bytes(&self) -> usize {
        self.key.len()
    }
}

/// An error returned by the crypto component.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoError {
    /// The arguments are semantically incorrect.
    /// This error is not retriable.
    /// This is equivalent to HTTP 422: The request was well-formed but was
    /// unable to be followed due to semantic errors.
    InvalidArgument { message: String },
    /// Public key for given (entity, purpose) pair not found at given registry
    /// version.
    PublicKeyNotFound {
        node_id: NodeId,
        key_purpose: KeyPurpose,
        registry_version: RegistryVersion,
    },
    /// TLS cert for given node_id not found at given registry version.
    TlsCertNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    /// Secret key not found in SecretKeyStore.
    SecretKeyNotFound {
        algorithm: AlgorithmId,
        key_id: KeyId,
    },
    /// TLS secret key not found in SecretKeyStore.
    TlsSecretKeyNotFound { certificate_der: Vec<u8> },
    /// Secret key could not be parsed or is otherwise invalid.
    MalformedSecretKey {
        algorithm: AlgorithmId,
        internal_error: String,
    },
    /// Public key could not be parsed or is otherwise invalid.
    MalformedPublicKey {
        algorithm: AlgorithmId,
        key_bytes: Option<Vec<u8>>,
        internal_error: String,
    },
    /// Signature could not be parsed or is otherwise invalid.
    MalformedSignature {
        algorithm: AlgorithmId,
        sig_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Pop could not be parsed or is otherwise invalid.
    MalformedPop {
        algorithm: AlgorithmId,
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Signature could not be verified.
    SignatureVerification {
        algorithm: AlgorithmId,
        public_key_bytes: Vec<u8>,
        sig_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Pop could not be verified.
    PopVerification {
        algorithm: AlgorithmId,
        public_key_bytes: Vec<u8>,
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Multi-signature: inconsistent (multiple) algorithms.
    InconsistentAlgorithms {
        algorithms: BTreeSet<AlgorithmId>,
        key_purpose: KeyPurpose,
        registry_version: RegistryVersion,
    },
    /// Algorithm not supported.
    AlgorithmNotSupported {
        algorithm: AlgorithmId,
        reason: String,
    },
    /// Error querying the registry.
    RegistryClient(RegistryClientError),
    /// Threshold signature data store did not contain the expected data (public
    /// coefficients and node indices)
    ThresholdSigDataNotFound { dkg_id: DkgId },
    /// DKG transcript for given subnet ID not found at given registry version.
    DkgTranscriptNotFound {
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    },
    /// Root subnet public key not found at given registry version.
    RootSubnetPublicKeyNotFound { registry_version: RegistryVersion },
}

impl From<ThresholdSigPublicKeyBytesConversionError> for CryptoError {
    fn from(error: ThresholdSigPublicKeyBytesConversionError) -> Self {
        match error {
            ThresholdSigPublicKeyBytesConversionError::Malformed {
                key_bytes,
                internal_error,
            } => CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::ThresBls12_381,
                key_bytes,
                internal_error,
            },
        }
    }
}

impl CryptoError {
    pub fn is_public_key_not_found(&self) -> bool {
        matches!(self, CryptoError::PublicKeyNotFound { .. })
    }

    pub fn is_secret_key_not_found(&self) -> bool {
        matches!(self, CryptoError::SecretKeyNotFound { .. })
    }

    pub fn is_malformed_secret_key(&self) -> bool {
        matches!(self, CryptoError::MalformedSecretKey { .. })
    }

    pub fn is_malformed_public_key(&self) -> bool {
        matches!(self, CryptoError::MalformedPublicKey { .. })
    }

    pub fn is_malformed_signature(&self) -> bool {
        matches!(self, CryptoError::MalformedSignature { .. })
    }

    pub fn is_signature_verification_error(&self) -> bool {
        matches!(self, CryptoError::SignatureVerification { .. })
    }

    pub fn is_pop_verification_error(&self) -> bool {
        matches!(self, CryptoError::PopVerification { .. })
    }

    pub fn is_inconsistent_algorithms(&self) -> bool {
        matches!(self, CryptoError::InconsistentAlgorithms { .. })
    }

    pub fn is_algorithm_not_supported(&self) -> bool {
        matches!(self, CryptoError::AlgorithmNotSupported { .. })
    }

    pub fn is_registry_client_error(&self) -> bool {
        matches!(self, CryptoError::RegistryClient(_))
    }

    pub fn is_threshold_sig_data_not_found(&self) -> bool {
        matches!(self, CryptoError::ThresholdSigDataNotFound { .. })
    }

    pub fn is_dkg_transcript_not_found(&self) -> bool {
        matches!(self, CryptoError::DkgTranscriptNotFound { .. })
    }

    pub fn is_invalid_argument(&self) -> bool {
        matches!(self, CryptoError::InvalidArgument { .. })
    }
}

impl From<RegistryClientError> for CryptoError {
    fn from(registry_client_error: RegistryClientError) -> Self {
        CryptoError::RegistryClient(registry_client_error)
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::RegistryClient(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidArgument { message } => {
                write!(f, "Semantic error in argument: {}", message)
            }
            CryptoError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            } => write!(
                f,
                "Cannot find public key registry record for node with \
                 ID {:?} with purpose {:?} at registry version {:?}",
                node_id, key_purpose, registry_version
            ),

            CryptoError::TlsCertNotFound { node_id, registry_version } => write!(
                f,
                "Cannot find TLS public key certificate record for node with ID {:?} at registry version {:?} ",
                node_id, registry_version
            ),

            CryptoError::SecretKeyNotFound { algorithm, key_id } => write!(
                f,
                "Cannot find {:?} secret key with ID {:?}",
                algorithm, key_id
            ),

            CryptoError::TlsSecretKeyNotFound { certificate_der } => write!(
                f,
                "Cannot find TLS secret key for certificate (DER encoding) 0x{}",
                hex::encode(&certificate_der)
            ),

            CryptoError::MalformedSecretKey { algorithm, .. } => {
                write!(f, "Malformed {:?} secret key", algorithm)
            }

            CryptoError::MalformedPublicKey {
                algorithm,
                key_bytes: Some(key_bytes),
                internal_error,
            } => write!(
                f,
                "Malformed {:?} public key: {}, error: {}",
                algorithm,
                hex::encode(&key_bytes),
                internal_error,
            ),
            CryptoError::MalformedPublicKey {
                algorithm,
                internal_error,
                ..
            } => write!(
                f,
                "Malformed {:?} public key: {}",
                algorithm, internal_error
            ),

            CryptoError::MalformedSignature {
                algorithm,
                sig_bytes,
                internal_error,
            } => write!(
                f,
                "Malformed {:?} signature: [{}] error: '{}'",
                algorithm,
                hex::encode(&sig_bytes),
                internal_error
            ),
            CryptoError::MalformedPop {
                algorithm,
                pop_bytes,
                internal_error,
            } => write!(
                f,
                "Malformed {:?} PoP: [{}] error: '{}'",
                algorithm,
                hex::encode(&pop_bytes),
                internal_error
            ),

            CryptoError::SignatureVerification {
                algorithm,
                public_key_bytes,
                sig_bytes,
                internal_error,
            } => write!(
                f,
                "{:?} signature could not be verified: public key {}, signature {}, error: {}",
                algorithm,
                hex::encode(&public_key_bytes),
                hex::encode(&sig_bytes),
                internal_error,
            ),
            CryptoError::PopVerification {
                algorithm,
                public_key_bytes,
                pop_bytes,
                internal_error,
            } => write!(
                f,
                "{:?} PoP could not be verified: public key {}, pop {}, error: {}",
                algorithm,
                hex::encode(&public_key_bytes),
                hex::encode(&pop_bytes),
                internal_error,
            ),

            CryptoError::InconsistentAlgorithms {
                algorithms,
                key_purpose,
                registry_version,
            } => write!(
                f,
                "Expected the given nodes' public key registry records for key purpose \
                 {:?} and registry version {:?} to all have the same algorithm but \
                 instead found the following algorithms {:?}.",
                key_purpose, registry_version, algorithms
            ),

            CryptoError::AlgorithmNotSupported { algorithm, reason } => {
                write!(f, "Algorithm {:?} not supported: {}", algorithm, reason)
            }

            CryptoError::RegistryClient(e) => write!(f, "Cannot query registry: {}", e),

            CryptoError::ThresholdSigDataNotFound { dkg_id } => write!(
                f,
                "Cannot find transcript data for DKG ID {:?} in data store",
                dkg_id
            ),
            CryptoError::DkgTranscriptNotFound {
                subnet_id,
                registry_version,
            } => write!(
                f,
                "Cannot find initial DKG transcript for subnet ID {:?} at registry version {:?}",
                subnet_id, registry_version
            ),
            CryptoError::RootSubnetPublicKeyNotFound { registry_version } => write!(
                f,
                "Cannot find root subnet public key at registry version {:?}",
                registry_version
            )
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A `Result` with an error of type `CryptoError`.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// A basic signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BasicSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A basic signature for content of type `T`
pub type BasicSigOf<T> = Id<T, BasicSig>; // Use newtype instead? E.g., `pub struct BasicSigOf<T>(Id<T, BasicSig>);`

impl CountBytes for BasicSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for BasicSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

/// An individual multi-signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndividualMultiSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// An individual multi-signature for content of type `T`
pub type IndividualMultiSigOf<T> = Id<T, IndividualMultiSig>; // Use newtype instead?

impl CountBytes for IndividualMultiSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for IndividualMultiSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

/// A combined multi-signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedMultiSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A combined multi-signature for content of type `T`
pub type CombinedMultiSigOf<T> = Id<T, CombinedMultiSig>; // Use newtype instead?

impl CountBytes for CombinedMultiSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for CombinedMultiSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

/// A threshold signature share.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSigShare(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A threshold signature share for content of type `T`
pub type ThresholdSigShareOf<T> = Id<T, ThresholdSigShare>; // Use newtype instead?

/// A combined threshold signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedThresholdSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A combined threshold signature for content of type `T`
pub type CombinedThresholdSigOf<T> = Id<T, CombinedThresholdSig>; // Use newtype instead?

/// A canister signature (ICCSA).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
/// A canister signature for content of type `T`
pub type CanisterSigOf<T> = Id<T, CanisterSig>;
