use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterEcdsaPublicKey};
use ic_types::crypto::AlgorithmId;
use ic_types::{NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use ic_types::crypto::canister_threshold_sig::EcdsaPublicKey;
pub use ic_types::NodeIndex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaError {
    CurveMismatch,
    InvalidRandomOracleInput,
    InconsistentCiphertext,
    InconsistentCommitments,
    InsufficientDealings,
    InterpolationError,
    InvalidArguments(String),
    InvalidDerivationPath,
    InvalidFieldElement,
    InvalidComplaint,
    InvalidOpening,
    InvalidPoint,
    InvalidProof,
    InvalidRecipients,
    InvalidScalar,
    InvalidSecretShare,
    InvalidThreshold(usize, usize),
    SerializationError(String),
}

pub type ThresholdEcdsaResult<T> = std::result::Result<T, ThresholdEcdsaError>;

mod complaints;
mod dealings;
mod ecdsa;
mod fe;
mod group;
mod hash2curve;
mod key_derivation;
mod mega;
mod poly;
pub mod ro;
mod seed;
pub mod sign;
mod transcript;
mod xmd;
pub mod zk;

pub use crate::complaints::IDkgComplaintInternal;
pub use crate::dealings::*;
pub use crate::fe::*;
pub use crate::group::*;
pub use crate::mega::*;
pub use crate::poly::*;
pub use crate::seed::*;
pub use crate::transcript::*;
pub use crate::xmd::*;

pub use crate::key_derivation::DerivationPath;
pub use sign::{ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaSigShareInternal};

/// Create MEGa encryption keypair
pub fn gen_keypair(
    curve_type: EccCurveType,
    seed: Randomness,
) -> Result<(MEGaPublicKey, MEGaPrivateKey), ThresholdEcdsaError> {
    use rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.get());
    let private_key = MEGaPrivateKey::generate(curve_type, &mut rng)?;

    let public_key = private_key.public_key()?;

    Ok((public_key, private_key))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdkgCreateDealingInternalError {
    UnsupportedAlgorithm,
    InvalidRecipients,
    // Contains the requested threshold and the number of receivers
    InvalidThreshold(usize, usize),
    InvalidSecretShare,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IdkgCreateDealingInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::InvalidRecipients => Self::InvalidRecipients,
            ThresholdEcdsaError::InvalidSecretShare => Self::InvalidSecretShare,
            ThresholdEcdsaError::InvalidThreshold(t, r) => Self::InvalidThreshold(t, r),
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create a dealing for threshold ECDSA
pub fn create_dealing(
    algorithm_id: ic_types::crypto::AlgorithmId,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    threshold: NumberOfNodes,
    recipients: &[MEGaPublicKey],
    shares: &SecretShares,
    randomness: Randomness,
) -> Result<IDkgDealingInternal, IdkgCreateDealingInternalError> {
    let curve = match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => Ok(EccCurveType::K256),
        _ => Err(IdkgCreateDealingInternalError::UnsupportedAlgorithm),
    }?;

    let seed = Seed::from_randomness(&randomness);

    IDkgDealingInternal::new(
        shares,
        curve,
        seed,
        threshold.get() as usize,
        recipients,
        dealer_index,
        associated_data,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgCreateTranscriptInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientDealings,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IDkgCreateTranscriptInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            ThresholdEcdsaError::InsufficientDealings => Self::InsufficientDealings,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create a new IDkg transcript
pub fn create_transcript(
    algorithm_id: AlgorithmId,
    reconstruction_threshold: NumberOfNodes,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    operation_mode: &IDkgTranscriptOperationInternal,
) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptInternalError> {
    let curve = match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => Ok(EccCurveType::K256),
        _ => Err(IDkgCreateTranscriptInternalError::UnsupportedAlgorithm),
    }?;

    IDkgTranscriptInternal::new(
        curve,
        reconstruction_threshold.get() as usize,
        verified_dealings,
        operation_mode,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgLoadTranscriptInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientDealings,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IDkgLoadTranscriptInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            ThresholdEcdsaError::InsufficientDealings => Self::InsufficientDealings,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

pub fn compute_secret_shares(
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    transcript: &IDkgTranscriptInternal,
    context_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, IDkgLoadTranscriptInternalError> {
    CommitmentOpening::from_dealings(
        verified_dealings,
        transcript,
        context_data,
        receiver_index,
        secret_key,
        public_key,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IDkgVerifyDealingInternalError {
    UnsupportedAlgorithm,
    InvalidCommitment,
    InvalidProof,
    InvalidRecipients,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IDkgVerifyDealingInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::InvalidProof => Self::InvalidProof,
            ThresholdEcdsaError::InconsistentCommitments => Self::InvalidCommitment,
            ThresholdEcdsaError::InvalidRecipients => Self::InvalidRecipients,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a dealing using public information
///
/// Verify that the dealing has the expected type of ciphertext
/// and commitment (depending on the type of dealing)
///
/// When CRP-1158 is completed this will also verify the zero
/// knowledge proofs
pub fn publicly_verify_dealing(
    algorithm_id: AlgorithmId,
    dealing: &IDkgDealingInternal,
    transcript_type: &IDkgTranscriptOperationInternal,
    reconstruction_threshold: NumberOfNodes,
    dealer_index: NodeIndex,
    number_of_receivers: NumberOfNodes,
    associated_data: &[u8],
) -> Result<(), IDkgVerifyDealingInternalError> {
    let curve = match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => Ok(EccCurveType::K256),
        _ => Err(IDkgVerifyDealingInternalError::UnsupportedAlgorithm),
    }?;

    dealing
        .publicly_verify(
            curve,
            transcript_type,
            reconstruction_threshold,
            dealer_index,
            number_of_receivers,
            associated_data,
        )
        .map_err(|e| e.into())
}

/// Verify a dealing using private information
///
/// This private verification must be done after the dealing has been publically
/// verified. This operation decrypts the dealing and verifies that the
/// decrypted value is consistent with the commitment in the dealing.
#[allow(clippy::too_many_arguments)]
pub fn privately_verify_dealing(
    algorithm_id: AlgorithmId,
    dealing: &IDkgDealingInternal,
    private_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    recipient_index: NodeIndex,
) -> Result<(), IDkgVerifyDealingInternalError> {
    let curve = match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => Ok(EccCurveType::K256),
        _ => Err(IDkgVerifyDealingInternalError::UnsupportedAlgorithm),
    }?;

    dealing
        .privately_verify(
            curve,
            private_key,
            public_key,
            associated_data,
            dealer_index,
            recipient_index,
        )
        .map_err(|e| e.into())
}

impl From<&ExtendedDerivationPath> for DerivationPath {
    fn from(extended_derivation_path: &ExtendedDerivationPath) -> Self {
        // We use generalized derivation for all path bytestrings after prepending
        // the caller's principal. It means only big-endian encoded 4-byte values
        // less than 2^31 are compatible with BIP-32 non-hardened derivation path.
        Self::new_arbitrary(
            std::iter::once(extended_derivation_path.caller.to_vec())
                .chain(extended_derivation_path.derivation_path.clone().into_iter())
                .map(key_derivation::DerivationIndex::Generalized)
                .collect::<Vec<_>>(),
        )
    }
}

impl ThresholdEcdsaSigShareInternal {
    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(raw: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(raw)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaGenerateSigShareInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdEcdsaGenerateSigShareInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

fn signature_parameters(algorithm_id: AlgorithmId) -> Option<(EccCurveType, usize)> {
    match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => {
            Some((EccCurveType::K256, EccCurveType::K256.scalar_bytes()))
        }
        _ => None,
    }
}

/// Create a new threshold ECDSA signature share
///
/// The derivation_path
///
/// The nonce should be random and shared by all nodes, for instance
/// by deriving a value from the random tape.
///
/// The presig_transcript is the transcript of the pre-signature (kappa)
///
/// lambda, kappa_times_lambda, and key_times_lambda are our openings
/// of the commitments in the associated transcripts.
///
/// The hashed message must have the same size as the underlying curve
/// order, for instance for P-256 a 256-bit hash function must be
/// used.
#[allow(clippy::too_many_arguments)]
pub fn sign_share(
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    nonce: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    lambda: &CommitmentOpening,
    kappa_times_lambda: &CommitmentOpening,
    key_times_lambda: &CommitmentOpening,
    algorithm_id: AlgorithmId,
) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaGenerateSigShareInternalError> {
    let (curve_type, hash_len) = signature_parameters(algorithm_id)
        .ok_or(ThresholdEcdsaGenerateSigShareInternalError::UnsupportedAlgorithm)?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaGenerateSigShareInternalError::UnsupportedAlgorithm);
    }

    ThresholdEcdsaSigShareInternal::new(
        derivation_path,
        hashed_message,
        nonce,
        key_transcript,
        presig_transcript,
        lambda,
        kappa_times_lambda,
        key_times_lambda,
        curve_type,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifySigShareInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InvalidSignatureShare,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdEcdsaVerifySigShareInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a signature share
///
/// The values provided must be consistent with when the signature share
/// was created
#[allow(clippy::too_many_arguments)]
pub fn verify_signature_share(
    sig_share: &ThresholdEcdsaSigShareInternal,
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    signer_index: NodeIndex,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    lambda: &IDkgTranscriptInternal,
    kappa_times_lambda: &IDkgTranscriptInternal,
    key_times_lambda: &IDkgTranscriptInternal,
    algorithm_id: AlgorithmId,
) -> Result<(), ThresholdEcdsaVerifySigShareInternalError> {
    let (curve_type, hash_len) = signature_parameters(algorithm_id)
        .ok_or(ThresholdEcdsaVerifySigShareInternalError::UnsupportedAlgorithm)?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaVerifySigShareInternalError::UnsupportedAlgorithm);
    }

    let accept = sig_share.verify(
        derivation_path,
        hashed_message,
        randomness,
        signer_index,
        key_transcript,
        presig_transcript,
        lambda,
        kappa_times_lambda,
        key_times_lambda,
        curve_type,
    )?;

    if !accept {
        return Err(ThresholdEcdsaVerifySigShareInternalError::InvalidSignatureShare);
    }

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaCombineSigSharesInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientShares,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdEcdsaCombineSigSharesInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            ThresholdEcdsaError::InsufficientDealings => Self::InsufficientShares,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Combine sufficient signature shares into an ECDSA signature
///
/// The signature shares must be verified prior to use, and there must
/// be at least reconstruction_threshold many of them.
#[allow(clippy::too_many_arguments)]
pub fn combine_sig_shares(
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    reconstruction_threshold: NumberOfNodes,
    sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    algorithm_id: AlgorithmId,
) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesInternalError> {
    let curve_type = match algorithm_id {
        AlgorithmId::ThresholdEcdsaSecp256k1 => EccCurveType::K256,
        _ => return Err(ThresholdEcdsaCombineSigSharesInternalError::UnsupportedAlgorithm),
    };

    sign::ThresholdEcdsaCombinedSigInternal::new(
        derivation_path,
        hashed_message,
        randomness,
        key_transcript,
        presig_transcript,
        reconstruction_threshold,
        sig_shares,
        curve_type,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifySignatureInternalError {
    InvalidSignature,
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdEcdsaVerifySignatureInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a threshold ECDSA signature
///
/// In addition to checking that the ECDSA signature itself is
/// consistent with the provided message and the public key associated
/// with `derivation_path`, this function also verifies that the
/// signature was generated correctly with regards to the provided
/// presignature transcript and randomness.
pub fn verify_threshold_signature(
    signature: &ThresholdEcdsaCombinedSigInternal,
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    presig_transcript: &IDkgTranscriptInternal,
    key_transcript: &IDkgTranscriptInternal,
    algorithm_id: AlgorithmId,
) -> Result<(), ThresholdEcdsaVerifySignatureInternalError> {
    let (curve_type, hash_len) = signature_parameters(algorithm_id)
        .ok_or(ThresholdEcdsaVerifySignatureInternalError::UnsupportedAlgorithm)?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaVerifySignatureInternalError::UnsupportedAlgorithm);
    }

    let accept = signature.verify(
        derivation_path,
        hashed_message,
        randomness,
        presig_transcript,
        key_transcript,
        curve_type,
    )?;

    if !accept {
        return Err(ThresholdEcdsaVerifySignatureInternalError::InvalidSignature);
    }

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaDerivePublicKeyError {
    InvalidArgument(String),
    InternalError(ThresholdEcdsaError),
}

impl From<ThresholdEcdsaError> for ThresholdEcdsaDerivePublicKeyError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::InvalidArguments(s) => Self::InvalidArgument(s),
            ThresholdEcdsaError::CurveMismatch
            | ThresholdEcdsaError::InconsistentCiphertext
            | ThresholdEcdsaError::InconsistentCommitments
            | ThresholdEcdsaError::InsufficientDealings
            | ThresholdEcdsaError::InterpolationError
            | ThresholdEcdsaError::InvalidComplaint
            | ThresholdEcdsaError::InvalidDerivationPath
            | ThresholdEcdsaError::InvalidFieldElement
            | ThresholdEcdsaError::InvalidOpening
            | ThresholdEcdsaError::InvalidPoint
            | ThresholdEcdsaError::InvalidProof
            | ThresholdEcdsaError::InvalidRecipients
            | ThresholdEcdsaError::InvalidScalar
            | ThresholdEcdsaError::InvalidSecretShare
            | ThresholdEcdsaError::InvalidRandomOracleInput
            | ThresholdEcdsaError::InvalidThreshold(_, _)
            | ThresholdEcdsaError::SerializationError(_) => Self::InternalError(e),
        }
    }
}

pub fn derive_public_key(
    master_public_key: &MasterEcdsaPublicKey,
    derivation_path: &DerivationPath,
) -> Result<EcdsaPublicKey, ThresholdEcdsaDerivePublicKeyError> {
    Ok(crate::sign::derive_public_key(
        master_public_key,
        derivation_path,
    )?)
}

pub use crate::complaints::generate_complaints;
