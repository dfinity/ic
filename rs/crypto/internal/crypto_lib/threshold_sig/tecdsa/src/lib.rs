use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterEcdsaPublicKey};
use ic_types::crypto::AlgorithmId;
use ic_types::{NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError,
    IDkgVerifyTranscriptError,
};
pub use ic_types::crypto::canister_threshold_sig::EcdsaPublicKey;
pub use ic_types::NodeIndex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaError {
    CurveMismatch,
    InvalidRandomOracleInput,
    InconsistentCiphertext,
    InconsistentCommitments,
    InsufficientDealings,
    InsufficientOpenings,
    InterpolationError,
    InvalidArguments(String),
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
mod fe;
mod group;
mod hash2curve;
mod key_derivation;
mod mega;
mod poly;
pub mod ro;
mod seed;
pub mod sign;
pub mod test_utils;
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

pub use crate::key_derivation::{DerivationIndex, DerivationPath};
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
pub enum IDkgVerifyTranscriptInternalError {
    IncorrectTranscript,
    FailedToCreateTranscript(IDkgCreateTranscriptInternalError),
}

impl From<IDkgVerifyTranscriptInternalError> for IDkgVerifyTranscriptError {
    fn from(verify_transcript_internal_error: IDkgVerifyTranscriptInternalError) -> Self {
        type Vtie = IDkgVerifyTranscriptInternalError;
        type Vte = IDkgVerifyTranscriptError;
        match verify_transcript_internal_error {
            Vtie::IncorrectTranscript => Vte::InvalidTranscript,
            Vtie::FailedToCreateTranscript(create_transcript_error) => Vte::InvalidArgument(
                format!("failed to create transcript: {:?}", create_transcript_error),
            ),
        }
    }
}

/// Verifies the consistency of the transcript with the set of `verified_dealings`.
pub fn verify_transcript(
    internal_transcript: &IDkgTranscriptInternal,
    algorithm_id: AlgorithmId,
    reconstruction_threshold: NumberOfNodes,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    operation_mode: &IDkgTranscriptOperationInternal,
) -> Result<(), IDkgVerifyTranscriptInternalError> {
    let transcript = create_transcript(
        algorithm_id,
        reconstruction_threshold,
        verified_dealings,
        operation_mode,
    );

    match transcript {
        Ok(transcript) => {
            if &transcript == internal_transcript {
                Ok(())
            } else {
                Err(IDkgVerifyTranscriptInternalError::IncorrectTranscript)
            }
        }

        Err(e) => Err(IDkgVerifyTranscriptInternalError::FailedToCreateTranscript(
            e,
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgComputeSecretSharesInternalError {
    InconsistentCommitments,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IDkgComputeSecretSharesInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::CurveMismatch => Self::InconsistentCommitments,
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Computes secret shares (in the form of commitment openings) from
/// the given dealings.
///
/// # Errors
/// * `InconsistentCommitments` if the commitments are inconsistent. This
///   indicates that complaints can be created with [`generate_complaints`].
pub fn compute_secret_shares(
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    transcript: &IDkgTranscriptInternal,
    context_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, IDkgComputeSecretSharesInternalError> {
    CommitmentOpening::from_dealings(
        verified_dealings,
        &transcript.combined_commitment,
        context_data,
        receiver_index,
        secret_key,
        public_key,
    )
    .map_err(IDkgComputeSecretSharesInternalError::from)
}

/// Computes secret shares (in the form of commitment openings) from
/// the given dealings and openings.
///
/// # Preconditions
/// * The openings have all been verified to be valid.
/// * There are sufficient valid openings (at least `reconstruction_threshold`
///   many) for each corrupted dealing.
///
/// # Errors
/// * `InsufficientOpenings` if we require openings for a corrupted dealing but
///   do not have sufficiently many openings for that dealing.
/// * `InconsistentCommitments` if the commitments are inconsistent. This
///   indicates that there is a corrupted dealing for which we have no openings
///   at all.
pub fn compute_secret_shares_with_openings(
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
    transcript: &IDkgTranscriptInternal,
    context_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, IDkgComputeSecretSharesInternalError> {
    CommitmentOpening::from_dealings_and_openings(
        verified_dealings,
        openings,
        &transcript.combined_commitment,
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

impl From<IDkgVerifyDealingInternalError> for IDkgVerifyDealingPrivateError {
    fn from(error: IDkgVerifyDealingInternalError) -> Self {
        type Vdie = IDkgVerifyDealingInternalError;
        type Vdpe = IDkgVerifyDealingPrivateError;
        match error {
            Vdie::InvalidCommitment | Vdie::InvalidProof | Vdie::InvalidRecipients => {
                Vdpe::InvalidDealing(format!("{:?}", error))
            }
            Vdie::UnsupportedAlgorithm => Vdpe::InvalidArgument(format!("{:?}", error)),
            Vdie::InternalError(e) => Vdpe::InternalError(e),
        }
    }
}

/// Verifies a dealing using public information
///
/// This function checks that the dealing has the expected type of
/// ciphertext and commitment (depending on the type of dealing)
///
/// It also verifies zero knowledge proofs attached to the dealing.
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
        Self::new(
            std::iter::once(extended_derivation_path.caller.to_vec())
                .chain(extended_derivation_path.derivation_path.clone().into_iter())
                .map(key_derivation::DerivationIndex)
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
            | ThresholdEcdsaError::InsufficientOpenings
            | ThresholdEcdsaError::InterpolationError
            | ThresholdEcdsaError::InvalidComplaint
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgGenerateComplaintsInternalError {
    InvalidArguments(String),
    InternalError(String),
}

impl From<IDkgGenerateComplaintsInternalError> for IDkgLoadTranscriptError {
    fn from(generate_complaints_internal_error: IDkgGenerateComplaintsInternalError) -> Self {
        type Igcie = IDkgGenerateComplaintsInternalError;
        type Ilte = IDkgLoadTranscriptError;
        match generate_complaints_internal_error {
            Igcie::InvalidArguments(internal_error) => Ilte::InvalidArguments { internal_error },
            Igcie::InternalError(internal_error) => Ilte::InternalError { internal_error },
        }
    }
}

impl From<ThresholdEcdsaError> for IDkgGenerateComplaintsInternalError {
    fn from(threshold_ecdsa_error: ThresholdEcdsaError) -> Self {
        type Tee = ThresholdEcdsaError;
        match threshold_ecdsa_error {
            Tee::InvalidArguments(err) => Self::InvalidArguments(err),
            Tee::CurveMismatch => Self::InvalidArguments("curve mismatch".to_string()),
            Tee::InvalidRandomOracleInput => {
                Self::InvalidArguments("invalid random oracle input".to_string())
            }
            Tee::InvalidScalar => Self::InvalidArguments("invalid scalar".to_string()),
            other => Self::InternalError(format!("{:?}", other)),
        }
    }
}

/// The generate_complaints interface decrypts every dealing and
/// checks the resulting plaintext against the dealing.
///
/// For all incorrect plaintexts it creates a complaint that includes a
/// proof of equivalence of discrete log, showing that the plaintext
/// was wrong.
///
/// This function assumes there is at least one erroneous dealing that
/// requires complaining.
pub fn generate_complaints(
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    associated_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
    seed: Seed,
) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgGenerateComplaintsInternalError> {
    Ok(complaints::generate_complaints(
        verified_dealings,
        associated_data,
        receiver_index,
        secret_key,
        public_key,
        seed,
    )?)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgVerifyComplaintInternalError {
    InvalidComplaint,
    InvalidArgument(String),
    InternalError(String),
}

impl From<ThresholdEcdsaError> for IDkgVerifyComplaintInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::InvalidProof => Self::InvalidComplaint,
            ThresholdEcdsaError::InvalidComplaint => Self::InvalidComplaint,
            ThresholdEcdsaError::CurveMismatch => Self::InvalidComplaint,
            ThresholdEcdsaError::InvalidArguments(e) => Self::InvalidArgument(e),
            other => Self::InternalError(format!("{:?}", other)),
        }
    }
}

impl From<IDkgVerifyComplaintInternalError> for IDkgVerifyComplaintError {
    fn from(verify_complaint_internal_error: IDkgVerifyComplaintInternalError) -> Self {
        type Vcie = IDkgVerifyComplaintInternalError;
        type Vce = IDkgVerifyComplaintError;
        match verify_complaint_internal_error {
            Vcie::InvalidComplaint => Vce::InvalidComplaint,
            Vcie::InternalError(internal_error) => Vce::InternalError { internal_error },
            Vcie::InvalidArgument(internal_error) => Vce::InvalidArgument { internal_error },
        }
    }
}

/// Verifies a complaint against a dealing.
pub fn verify_complaint(
    complaint: &IDkgComplaintInternal,
    complainer_index: NodeIndex,
    complainer_key: &MEGaPublicKey,
    dealing: &IDkgDealingInternal,
    dealer_index: NodeIndex,
    associated_data: &[u8],
) -> Result<(), IDkgVerifyComplaintInternalError> {
    Ok(complaint.verify(
        dealing,
        dealer_index,
        complainer_index,
        complainer_key,
        associated_data,
    )?)
}

#[derive(Clone, Debug)]
pub enum ThresholdOpenDealingInternalError {
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdOpenDealingInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        Self::InternalError(format!("{:?}", e))
    }
}

/// Opens a dealing in response to a complaint
///
/// The opening is done with respect to information available to this opener,
/// given by `opener_index`, which is the openers index within the
/// dealing. Normally several openings are needed in order to reconstruct the
/// opening for the dealing commitment.
///
/// # Preconditions
/// * The dealing has already been publically verified
/// * The complaint which caused us to provide an opening for this dealing has
///   already been verified to be valid.
pub fn open_dealing(
    verified_dealing: &IDkgDealingInternal,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    opener_index: NodeIndex,
    opener_secret_key: &MEGaPrivateKey,
    opener_public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, ThresholdOpenDealingInternalError> {
    CommitmentOpening::open_dealing(
        verified_dealing,
        associated_data,
        dealer_index,
        opener_index,
        opener_secret_key,
        opener_public_key,
    )
    .map_err(|e| e.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdVerifyOpeningInternalError {
    InconsistentCommitments,
    InternalError(String),
}

impl From<ThresholdEcdsaError> for ThresholdVerifyOpeningInternalError {
    fn from(e: ThresholdEcdsaError) -> Self {
        match e {
            ThresholdEcdsaError::InconsistentCommitments => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verifies an opening of a dealing
///
/// This checks that the opening received by a peer in response to a
/// complaint is a valid opening for the dealing.
///
/// # Preconditions
/// * The dealing has already been publically verified
pub fn verify_dealing_opening(
    verified_dealing: &IDkgDealingInternal,
    opener_index: NodeIndex,
    opening: &CommitmentOpening,
) -> Result<(), ThresholdVerifyOpeningInternalError> {
    verified_dealing
        .commitment
        .check_opening(opener_index, opening)?;

    Ok(())
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum MEGaKeyVerificationError {
    InvalidPublicKey,
}

/// Verifies the validity of a MEGa public key
///
/// Checks that a serialized MEGa public key is a valid point on the curve
pub fn verify_mega_public_key(
    curve_type: EccCurveType,
    raw_bytes: &[u8],
) -> Result<(), MEGaKeyVerificationError> {
    if MEGaPublicKey::deserialize(curve_type, raw_bytes).is_ok() {
        Ok(())
    } else {
        Err(MEGaKeyVerificationError::InvalidPublicKey)
    }
}
