use crate::crypto::impl_display_using_debug;
use crate::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::NiDkgId;
use crate::crypto::CryptoError;
use crate::crypto::HexEncoding;
use crate::crypto::SignedBytesWithoutDomainSeparator;
use ic_base_types::PrincipalId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(test)]
mod test;

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdArgs {
    pub ni_dkg_id: NiDkgId,
    pub derivation_domain: VetKdDerivationDomain,
    #[serde(with = "serde_bytes")]
    pub derivation_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encryption_public_key: Vec<u8>,
}

impl fmt::Debug for VetKdArgs {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdArgs")
            .field("ni_dkg_id", &self.ni_dkg_id)
            .field("derivation_domain", &self.derivation_domain)
            .field("derivation_id", &HexEncoding::from(&self.derivation_id))
            .field(
                "encryption_public_key",
                &HexEncoding::from(&self.encryption_public_key),
            )
            .finish()
    }
}
impl_display_using_debug!(VetKdArgs);

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKeyShareContent(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for VetKdEncryptedKeyShareContent {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("VetKdEncryptedKeyShareContent")
            .field(&HexEncoding::from(&self.0))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKeyShareContent);

impl SignedBytesWithoutDomainSeparator for VetKdEncryptedKeyShareContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKeyShare {
    pub encrypted_key_share: VetKdEncryptedKeyShareContent,
    /// Node's Ed25519 signature for optimized variant
    #[serde(with = "serde_bytes")]
    pub node_signature: Vec<u8>,
}

impl std::fmt::Debug for VetKdEncryptedKeyShare {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdEncryptedKeyShare")
            .field("encrypted_key_share", &self.encrypted_key_share)
            .field("node_signature", &HexEncoding::from(&self.node_signature))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKeyShare);

#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdEncryptedKey {
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}

impl std::fmt::Debug for VetKdEncryptedKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdEncryptedKey")
            .field("encrypted_key", &HexEncoding::from(&self.encrypted_key))
            .finish()
    }
}
impl_display_using_debug!(VetKdEncryptedKey);

/// Metadata used to derive keys for vetKD.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct VetKdDerivationDomain {
    pub caller: PrincipalId,
    #[serde(with = "serde_bytes")]
    pub domain: Vec<u8>,
}

impl std::fmt::Debug for VetKdDerivationDomain {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("VetKdDerivationDomain")
            .field("caller", &self.caller)
            .field("domain", &HexEncoding::from(&self.domain))
            .finish()
    }
}
impl_display_using_debug!(VetKdDerivationDomain);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareCreationError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    KeyIdInstantiationError(String),
    InternalError(String),
    InvalidArgumentEncryptionPublicKey,
    KeyShareSigningError(CryptoError),
    TransientInternalError(String),
}
impl_display_using_debug!(VetKdKeyShareCreationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareVerificationError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    VerificationError(CryptoError),
}
impl_display_using_debug!(VetKdKeyShareVerificationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyShareCombinationError {
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    InvalidArgumentMasterPublicKey,
    InvalidArgumentEncryptionPublicKey,
    InvalidArgumentEncryptedKeyShare,
    IndividualPublicKeyComputationError(CryptoError),
    CombinationError(String),
    InternalError(String),
    UnsatisfiedReconstructionThreshold {
        threshold: usize,
        share_count: usize,
    },
}
impl_display_using_debug!(VetKdKeyShareCombinationError);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdKeyVerificationError {
    InvalidArgumentEncryptedKey,
    ThresholdSigDataNotFound(ThresholdSigDataNotFoundError),
    InternalError(String),
    InvalidArgumentMasterPublicKey,
    InvalidArgumentEncryptionPublicKey,
    VerificationError,
}
impl_display_using_debug!(VetKdKeyVerificationError);
