//!
//! # Threshold ECDSA
//!
//! The public interface for the threshold ECDSA implementation is in `src/lib.rs`.
//!
//! Internally within the library, the error type `CanisterThresholdError` is used. In
//! the public interfaces, this error is mapped onto function specific error types.
//!
//! ## Attack Model
//!
//! The code in this crate endeavors to be safe with regards to timing and
//! cache based side channels. No provision is made with regards to power
//! analysis attacks, fault attacks, etc.
//!
//! ## Protocol: Dealings
//!
//! File: `dealings.rs`
//!
//! A dealing [`IDkgDealingInternal`] consists of a [MEGa
//! ciphertext](#protocol-mega-encryption), a commitment to the values
//! encrypted, and potentially a [`dealings::ZkProof`](zero knowledge
//! proof).
//!
//! The dealing will either be "masked" (the commitments are Pedersen commitments)
//! or "unmasked" (the commitments are simple dlog commitments).
//!
//! There are five types of dealings
//!  - RandomUnmasked: outputs unmasked dealing, no proof
//!  - Random: outputs masked dealing, no proof
//!  - ReshareOfUnmasked: outputs unmasked dealing, no proof is
//!    required since equivalence is provable from the commitments
//!  - ReshareOfMasked: outputs unmasked dealing, contains proof
//!    that the resharing is correct (`ProofOfMaskedResharing`)
//!  - UnmaskedTimesMasked: outputs masked dealing, contains
//!    proof of product (`ProofOfProduct`)
//!
//! In addition to being generated, dealings have two forms of verification: public
//! and private. Public verification can be performed by any party, and checks that
//! the proof (if included) is correct and that the commitments are of the expected
//! type. Private verification decrypts the dealing ciphertext and verifies that
//! the decrypted plaintext is consistent with the commitments.
//!
//! ## Protocol: Complaints
//!
//! File: `complaints.rs`
//!
//! Defines a type for a complaint [`IDkgComplaintInternal`]. Complaints can
//! be generated and verified. The function `generate_complaints` attempts
//! to decrypt a set of dealings; any dealing which cannot be decrypted
//! correctly (with regards to the included commitment) results in a
//! complaint being generated.
//!
//! ## Protocol: Transcripts
//!
//! File: `transcript.rs`
//!
//! A transcript is a combination of dealings which have been publicly verified.
//! [`IDkgTranscriptInternal`] is a commitment which commits to the value which is
//! formed by the set of dealings. Both the transcript and the dealings which
//! created it are normally provided for further operations.
//!
//! Transcript verification refers to the process of creating a new transcript from
//! a set of dealings. If the new transcript is equal to the given transcript, the
//! transcript is considered verified with respect to the dealings.
//!
//! ## Protocol: Signature Generation and Verification
//!
//! File: `sign.rs`
//!
//! * Generation and verification of signature shares
//! * Generation and verification of combined signatures
//!
//! ## Protocol: Multi-encryption gadget (MEGa)
//!
//! File: `mega.rs`
//!
//! Implements the MEGa encryption/decryption scheme, including key
//! generation.
//!
//! [`RandomOracle`](#utility-functions-random-oracle) is used to
//! generate the additive masking values.
//!
//! ## Protocol: Polynomial Arithmetic and Commitments
//!
//! File: `poly.rs`
//!
//! Defines [`poly::Polynomial`] - a polynomial with coefficients that
//! are integers modulo the order of an elliptic curve.
//!
//! Also defines two types of commitments to polynomials:
//! [`poly::SimpleCommitment`] (simple (dlog) commitments)
//! and [`poly::PedersenCommitment`] (Pedersen commitments).
//!
//! ## Protocol: Zero Knowledge Proofs
//!
//! File: `zk.rs`
//!
//! Defines three zero knowledge proofs used in the protocol:
//!
//!  * [`zk::ProofOfEqualOpenings`]: a proof of equal openings of
//!    simple and Pedersen commitments
//!  * [`zk::ProofOfProduct`]: a proof that a Pedersen commitment
//!    opens to the value of the product of openings of a simple and
//!    another Pedersen commitment.
//!  * [`zk::ProofOfDLogEquivalence`]: a proof of equal discrete logarithm
//!
//! ## Protocol: Key Derivation
//!
//! File: `key_derivation.rs`
//!
//! Performs (extended) BIP32 key derivation.
//!
//! Instead of only using 32-bit indices for the derivation path, this
//! derivation supports arbitrary byte strings.
//!
//! In the case that only 32-bit values are used, it is compatible with
//! standard BIP32.
//!
//! ## Utility Functions: Elliptic Curve Group
//!
//! Files: `group.rs` and `group/*.rs`
//!
//! To insulate the implementation from API changes in dependencies, and also
//! to provide a consistent abstraction across multiple curves, wrapper
//! types are provided, namely [`EccScalar`] and [`EccPoint`].
//!
//! An important exception to the general policy of avoiding timing
//! attacks is in this file. The function [`EccPoint::mul_by_node_index`]
//! takes advantage of the fact that node indexes are both small and
//! public. Uses a simple square-and-multiply implementation, which provides
//! notable performance improvements.
//!
//! Currently, curve arithmetic is implemented using the `k256` and `p256`
//! crates from the RustCrypto project. Wrappers for these types are
//! included in the `group` subdirectory.
//!
//! ## Utility Functions: H2C and XMD
//!
//! Files: `hash2curve.rs`, and `xmd.rs` in `seed` crate
//!
//! An implementation of IETF standard hash2curve is implemented in
//! `hash2curve.rs`. This is actually never called in production; we do
//! use h2c to derive a `h` generator unrelated to the standard group
//! generator for Pedersen commitments, but this is done offline.
//!
//! The primary entry point for hash2curve is [`EccPoint::hash_to_point`].
//!
//! [Note: we may use hash2curve in the future for Proof Of Possession of
//! MEGa private keys]
//!
//! The XMD hash used in hash2curve is implemented in `xmd.rs`. This
//! derivation function is used elsewhere, namely in [`Seed`] and the
//! [random oracle](#utility-functions-random-oracle).
//!
//! ## Utility Functions: Seed
//!
//! File: `lib.rs` in `seed` crate
//!
//! This crate is deterministic; all randomness is provided by the
//! caller. We may require several different random inputs for various
//! purposes. To accomplish this, a type called [`Seed`] encapsulates
//! a crypto variable which can be used to derive additional values
//! (using XMD) or be turned into a random number generator
//! (ChaCha20).
//!
//! ## Utility Functions: Random Oracle
//!
//! File: `ro.rs`
//!
//! For purposes including MEGa encryption and while computing zero
//! knowledge proofs, we must derive some value from multiple
//! inputs. This is done in a systematic way with
//! [`ro::RandomOracle`].
//!
//! This type takes named inputs of various types (scalars, points,
//! bytestrings, and small integers), along with a domain separator, and
//! hashes them using XMD to produce outputs which can be scalars, points,
//! or bytestrings.
//!
//! ## Utility Functions: Testing
//!
//! File: `test_utils.rs`
//!
//! Contains a function for corrupting dealings which is used when testing
//! malicious behavior.

#![forbid(unsafe_code)]

use ic_crypto_internal_seed::XmdError;
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterPublicKey};
use ic_types::crypto::AlgorithmId;
use ic_types::{NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strum::EnumIter;

pub use ic_crypto_internal_seed::Seed;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError,
    IDkgVerifyTranscriptError,
};
pub use ic_types::crypto::canister_threshold_sig::PublicKey;
pub use ic_types::NodeIndex;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CanisterThresholdError {
    CurveMismatch,
    InconsistentCiphertext,
    InconsistentOpeningAndCommitment,
    InsufficientDealings,
    InsufficientOpenings(usize, usize),
    InterpolationError,
    InvalidArguments(String),
    InvalidCommitment,
    InvalidComplaint,
    InvalidFieldElement,
    InvalidPoint,
    InvalidProof,
    InvalidRandomOracleInput,
    InvalidRecipients,
    InvalidScalar,
    InvalidSecretShare,
    InvalidSignature,
    InvalidSignatureShare,
    InvalidThreshold(usize, usize),
    UnexpectedCommitmentType,
}

pub type CanisterThresholdResult<T> = std::result::Result<T, CanisterThresholdError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanisterThresholdSerializationError(pub String);

pub type CanisterThresholdSerializationResult<T> =
    std::result::Result<T, CanisterThresholdSerializationError>;

/// Identifies an IDKG protocol purposes
///
/// The IDKG is flexible, and usable for many different purposes.
/// This enumeration identifies what the intended use of an IDKG
/// instance is.
///
#[derive(Copy, Clone, Debug, EnumIter, Eq, PartialEq)]
pub enum IdkgProtocolAlgorithm {
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    Bip340,
    Ed25519,
}

impl IdkgProtocolAlgorithm {
    pub fn from_algorithm(alg_id: ic_types::crypto::AlgorithmId) -> Option<Self> {
        match alg_id {
            AlgorithmId::ThresholdEcdsaSecp256k1 => Some(Self::EcdsaSecp256k1),
            AlgorithmId::ThresholdEcdsaSecp256r1 => Some(Self::EcdsaSecp256r1),
            AlgorithmId::ThresholdSchnorrBip340 => Some(Self::Bip340),
            AlgorithmId::ThresholdEd25519 => Some(Self::Ed25519),
            _ => None,
        }
    }

    pub fn to_algorithm_id(&self) -> AlgorithmId {
        match self {
            Self::EcdsaSecp256k1 => AlgorithmId::ThresholdEcdsaSecp256k1,
            Self::EcdsaSecp256r1 => AlgorithmId::ThresholdEcdsaSecp256r1,
            Self::Bip340 => AlgorithmId::ThresholdSchnorrBip340,
            Self::Ed25519 => AlgorithmId::ThresholdEd25519,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1 => "ecdsa-secp256k1",
            Self::EcdsaSecp256r1 => "ecdsa-secp256r1",
            Self::Bip340 => "bip340",
            Self::Ed25519 => "ed25519",
        }
    }

    pub fn curve(&self) -> EccCurveType {
        match self {
            Self::EcdsaSecp256k1 => EccCurveType::K256,
            Self::EcdsaSecp256r1 => EccCurveType::P256,
            Self::Bip340 => EccCurveType::K256,
            Self::Ed25519 => EccCurveType::Ed25519,
        }
    }
}

pub mod test_utils;

mod domain_sep;
mod idkg;
mod signing;
mod utils;

use domain_sep::DomainSep;

pub use crate::idkg::mega::*;

pub use crate::idkg::complaints::*;
pub use crate::idkg::dealings::*;
pub use crate::idkg::transcript::*;
pub use crate::idkg::zk;

pub use crate::utils::group::*;
pub use crate::utils::poly::*;

pub use crate::utils::ro::*;

pub use crate::signing::bip340::{
    ThresholdBip340CombinedSignatureInternal, ThresholdBip340SignatureShareInternal,
};
pub use crate::signing::ecdsa::{
    ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaSigShareInternal,
};
pub use crate::signing::eddsa::{
    ThresholdEd25519CombinedSignatureInternal, ThresholdEd25519SignatureShareInternal,
};
pub use crate::signing::key_derivation::{DerivationIndex, DerivationPath};

/// Create MEGa encryption keypair
pub fn gen_keypair(curve_type: EccCurveType, seed: Seed) -> (MEGaPublicKey, MEGaPrivateKey) {
    let rng = &mut seed.into_rng();
    let private_key = MEGaPrivateKey::generate(curve_type, rng);

    let public_key = private_key.public_key();

    (public_key, private_key)
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

impl From<CanisterThresholdError> for IdkgCreateDealingInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InvalidRecipients => Self::InvalidRecipients,
            CanisterThresholdError::InvalidSecretShare => Self::InvalidSecretShare,
            CanisterThresholdError::InvalidThreshold(t, r) => Self::InvalidThreshold(t, r),
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create an IDKG dealing
pub fn create_dealing(
    algorithm_id: AlgorithmId,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    threshold: NumberOfNodes,
    recipients: &[MEGaPublicKey],
    shares: &SecretShares,
    seed: Seed,
) -> Result<IDkgDealingInternal, IdkgCreateDealingInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IdkgCreateDealingInternalError::UnsupportedAlgorithm)?;

    IDkgDealingInternal::new(
        shares,
        alg,
        seed,
        threshold.get() as usize,
        recipients,
        dealer_index,
        associated_data,
    )
    .map_err(IdkgCreateDealingInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgCreateTranscriptInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientDealings,
    InternalError(String),
}

impl From<CanisterThresholdError> for IDkgCreateTranscriptInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InsufficientDealings => Self::InsufficientDealings,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

impl From<XmdError> for CanisterThresholdError {
    fn from(e: XmdError) -> Self {
        match e {
            XmdError::InvalidOutputLength(x) => Self::InvalidArguments(format!("{:?}", x)),
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
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgCreateTranscriptInternalError::UnsupportedAlgorithm)?;

    IDkgTranscriptInternal::new(
        alg.curve(),
        reconstruction_threshold.get() as usize,
        verified_dealings,
        operation_mode,
    )
    .map_err(IDkgCreateTranscriptInternalError::from)
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
    ComplaintShouldBeIssued,
    InvalidCiphertext(String),
    UnableToCombineOpenings(String),
    UnableToReconstruct(String),
    UnsupportedAlgorithm,
}

/// Computes secret shares (in the form of commitment openings) from
/// the given dealings.
///
/// # Arguments:
/// * `algorithm_id`: the algorithm being executed by this IDKG
/// * `verified_dealings`: dealings to be decrypted,
/// * `transcript`: the combined commitment to the coefficients of the shared polynomial,
/// * `context_data`: associated data used in encryption and the zero-knowledge proofs,
/// * `receiver_index`: index of the receiver in this specific IDKG instance,
/// * `secret_key`: MEGa secret decryption key of the receiver,
/// * `public_key`: MEGa public encryption key associated to `secret_key`,
///
/// # Errors:
/// * `ComplaintShouldBeIssued`: if a ciphertext decrypts to a share that does not match with the commitment.
/// * `InvalidCiphertext`: if a ciphertext cannot be decrypted.
/// * `UnableToCombineOpenings`: internal error denoting that the decrypted share cannot be combined.
pub fn compute_secret_shares(
    algorithm_id: AlgorithmId,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    transcript: &IDkgTranscriptInternal,
    context_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, IDkgComputeSecretSharesInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgComputeSecretSharesInternalError::UnsupportedAlgorithm)?;

    CommitmentOpening::from_dealings(
        alg,
        verified_dealings,
        &transcript.combined_commitment,
        context_data,
        receiver_index,
        secret_key,
        public_key,
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgComputeSecretSharesWithOpeningsInternalError {
    ComplaintShouldBeIssued,
    InsufficientOpenings(usize, usize),
    InvalidCiphertext(String),
    UnsupportedAlgorithm,
    UnableToReconstruct(String),
    UnableToCombineOpenings(String),
}

/// Computes secret shares (in the form of commitment openings) from
/// the given dealings and openings.
///
/// # Preconditions
/// * The openings have all been verified to be valid.
/// * There are sufficient valid openings (at least `reconstruction_threshold`
///   many) for each corrupted dealing.
///
/// # Arguments:
/// * `algorithm_id`: the algorithm being executed by this IDKG
/// * `verified_dealings`: dealings to be decrypted,
/// * `openings`: openings answering complaints against dealing that could not be decrypted correctly,
/// * `transcript`: the combined commitment to the coefficients of the shared polynomial,
/// * `context_data`: associated data used in encryption and the zero-knowledge proofs,
/// * `receiver_index`: index of the receiver in this specific IDKG instance,
/// * `secret_key`: MEGa secret decryption key of the receiver,
/// * `public_key`: MEGa public encryption key associated to `secret_key`,
///
/// # Errors:
/// * `ComplaintShouldBeIssued`: if a ciphertext decrypts to a share that does not match with the commitment.
/// * `InsufficientOpenings`: if the number of openings answering a complaint is insufficient.
/// * `InvalidCiphertext`: if a ciphertext cannot be decrypted.
/// * `UnableToCombineOpenings`: internal error denoting that the decrypted share cannot be combined.
/// * `UnableToReconstruct`: internal error denoting that the received openings cannot be used to recompute a share.
pub fn compute_secret_shares_with_openings(
    algorithm_id: AlgorithmId,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
    transcript: &IDkgTranscriptInternal,
    context_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, IDkgComputeSecretSharesWithOpeningsInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgComputeSecretSharesWithOpeningsInternalError::UnsupportedAlgorithm)?;

    CommitmentOpening::from_dealings_and_openings(
        alg,
        verified_dealings,
        openings,
        &transcript.combined_commitment,
        context_data,
        receiver_index,
        secret_key,
        public_key,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IDkgVerifyDealingInternalError {
    UnsupportedAlgorithm,
    InvalidCommitment,
    InvalidProof,
    InvalidRecipients,
    InternalError(String),
}

impl From<CanisterThresholdError> for IDkgVerifyDealingInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InvalidProof => Self::InvalidProof,
            CanisterThresholdError::InvalidCommitment => Self::InvalidCommitment,
            CanisterThresholdError::InvalidRecipients => Self::InvalidRecipients,
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
    let key_curve = EccCurveType::K256;

    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgVerifyDealingInternalError::UnsupportedAlgorithm)?;

    dealing
        .publicly_verify(
            key_curve,
            alg,
            transcript_type,
            reconstruction_threshold,
            dealer_index,
            number_of_receivers,
            associated_data,
        )
        .map_err(IDkgVerifyDealingInternalError::from)
}

/// Verify a dealing using private information
///
/// This private verification must be done after the dealing has been publicly
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
    let signature_alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgVerifyDealingInternalError::UnsupportedAlgorithm)?;

    let key_curve = private_key.curve_type();

    dealing
        .privately_verify(
            key_curve,
            signature_alg,
            private_key,
            public_key,
            associated_data,
            dealer_index,
            recipient_index,
        )
        .map_err(IDkgVerifyDealingInternalError::from)
}

impl From<&ExtendedDerivationPath> for DerivationPath {
    fn from(extended_derivation_path: &ExtendedDerivationPath) -> Self {
        // We use generalized derivation for all path bytestrings after prepending
        // the caller's principal. It means only big-endian encoded 4-byte values
        // less than 2^31 are compatible with BIP-32 non-hardened derivation path.
        Self::new(
            std::iter::once(extended_derivation_path.caller.to_vec())
                .chain(extended_derivation_path.derivation_path.clone())
                .map(crate::signing::key_derivation::DerivationIndex)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaGenerateSigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEcdsaGenerateSigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create a new threshold ECDSA signature share
///
/// The derivation_path creates a new key relative to the master key
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
pub fn create_ecdsa_signature_share(
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
    let (curve_type, hash_len) = ecdsa_signature_parameters(algorithm_id).ok_or_else(|| {
        ThresholdEcdsaGenerateSigShareInternalError::InvalidArguments(format!(
            "unsupported algorithm: {algorithm_id:?}"
        ))
    })?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaGenerateSigShareInternalError::InvalidArguments(
            format!("length of hashed_message ({}) not matching expected length ({hash_len}) for algorithm_id ({algorithm_id:?})", hashed_message.len()))
        );
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
    .map_err(ThresholdEcdsaGenerateSigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifySigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InvalidSignatureShare,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEcdsaVerifySigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidSignatureShare => Self::InvalidSignatureShare,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a signature share
///
/// The values provided must be consistent with when the signature share
/// was created
#[allow(clippy::too_many_arguments)]
pub fn verify_ecdsa_signature_share(
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
    let (curve_type, hash_len) = ecdsa_signature_parameters(algorithm_id).ok_or_else(|| {
        ThresholdEcdsaVerifySigShareInternalError::InvalidArguments(format!(
            "unsupported algorithm: {algorithm_id:?}"
        ))
    })?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaVerifySigShareInternalError::InvalidArguments(
            format!("length of hashed_message ({}) not matching expected length ({hash_len}) for algorithm_id ({algorithm_id:?})", hashed_message.len()))
        );
    }

    sig_share
        .verify(
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
        )
        .map_err(ThresholdEcdsaVerifySigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaCombineSigSharesInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientShares,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEcdsaCombineSigSharesInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InsufficientDealings => Self::InsufficientShares,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Combine sufficient signature shares into an ECDSA signature
///
/// The signature shares must be verified prior to use, and there must
/// be at least reconstruction_threshold many of them.
///
/// All shares must have been created with respect to the same derivation path,
/// message, randomness, and transcripts.
#[allow(clippy::too_many_arguments)]
pub fn combine_ecdsa_signature_shares(
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    reconstruction_threshold: NumberOfNodes,
    sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    algorithm_id: AlgorithmId,
) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(ThresholdEcdsaCombineSigSharesInternalError::UnsupportedAlgorithm)?;

    crate::signing::ecdsa::ThresholdEcdsaCombinedSigInternal::new(
        derivation_path,
        hashed_message,
        randomness,
        key_transcript,
        presig_transcript,
        reconstruction_threshold,
        sig_shares,
        alg.curve(),
    )
    .map_err(ThresholdEcdsaCombineSigSharesInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEcdsaVerifySignatureInternalError {
    InvalidSignature,
    InvalidArguments(String),
    InconsistentCommitments,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEcdsaVerifySignatureInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidSignature => Self::InvalidSignature,
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
pub fn verify_ecdsa_threshold_signature(
    signature: &ThresholdEcdsaCombinedSigInternal,
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    presig_transcript: &IDkgTranscriptInternal,
    key_transcript: &IDkgTranscriptInternal,
    algorithm_id: AlgorithmId,
) -> Result<(), ThresholdEcdsaVerifySignatureInternalError> {
    let (curve_type, hash_len) = ecdsa_signature_parameters(algorithm_id).ok_or_else(|| {
        ThresholdEcdsaVerifySignatureInternalError::InvalidArguments(format!(
            "unsupported algorithm: {algorithm_id:?}"
        ))
    })?;

    if hashed_message.len() != hash_len {
        return Err(ThresholdEcdsaVerifySignatureInternalError::InvalidArguments(
            format!("length of hashed_message ({}) not matching expected length ({hash_len}) for algorithm_id ({algorithm_id:?})", hashed_message.len())
        ));
    }

    signature
        .verify(
            derivation_path,
            hashed_message,
            randomness,
            presig_transcript,
            key_transcript,
            curve_type,
        )
        .map_err(ThresholdEcdsaVerifySignatureInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdBip340GenerateSigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdBip340GenerateSigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create a new threshold BIP340 Schnorr signature share
///
/// The derivation_path creates a new key relative to the master key
///
/// The nonce should be random and shared by all nodes, for instance
/// by deriving a value from the random tape.
///
/// The presig_transcript is the transcript of the pre-signature (kappa)
///
/// The message can be of any length
pub fn create_bip340_signature_share(
    derivation_path: &DerivationPath,
    message: &[u8],
    nonce: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    key_opening: &CommitmentOpening,
    presig_opening: &CommitmentOpening,
) -> Result<ThresholdBip340SignatureShareInternal, ThresholdBip340GenerateSigShareInternalError> {
    ThresholdBip340SignatureShareInternal::new(
        derivation_path,
        message,
        nonce,
        key_transcript,
        key_opening,
        presig_transcript,
        presig_opening,
    )
    .map_err(ThresholdBip340GenerateSigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdBip340VerifySigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InvalidSignatureShare,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdBip340VerifySigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidSignatureShare => Self::InvalidSignatureShare,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a signature share
///
/// The values provided must be consistent with when the signature share
/// was created
pub fn verify_bip340_signature_share(
    sig_share: &ThresholdBip340SignatureShareInternal,
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    signer_index: NodeIndex,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
) -> Result<(), ThresholdBip340VerifySigShareInternalError> {
    sig_share
        .verify(
            derivation_path,
            hashed_message,
            randomness,
            signer_index,
            key_transcript,
            presig_transcript,
        )
        .map_err(ThresholdBip340VerifySigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdBip340CombineSigSharesInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientShares,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdBip340CombineSigSharesInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InsufficientDealings => Self::InsufficientShares,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Combine sufficient signature shares into an BIP340 signature
///
/// The signature shares must be verified prior to use, and there must
/// be at least reconstruction_threshold many of them.
///
/// All shares must have been created with respect to the same derivation path,
/// message, randomness, and transcripts.
pub fn combine_bip340_signature_shares(
    derivation_path: &DerivationPath,
    message: &[u8],
    randomness: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    reconstruction_threshold: NumberOfNodes,
    sig_shares: &BTreeMap<NodeIndex, ThresholdBip340SignatureShareInternal>,
) -> Result<ThresholdBip340CombinedSignatureInternal, ThresholdBip340CombineSigSharesInternalError>
{
    ThresholdBip340CombinedSignatureInternal::new(
        derivation_path,
        message,
        randomness,
        key_transcript,
        presig_transcript,
        reconstruction_threshold,
        sig_shares,
    )
    .map_err(ThresholdBip340CombineSigSharesInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdBip340VerifySignatureInternalError {
    InvalidSignature,
    UnexpectedCommitmentType,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdBip340VerifySignatureInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::UnexpectedCommitmentType => Self::UnexpectedCommitmentType,
            CanisterThresholdError::InvalidSignature => Self::InvalidSignature,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a threshold BIP340 Schnorr signature
///
/// In addition to checking that the signature itself is consistent
/// with the provided message and the public key associated with
/// `derivation_path`, this function also verifies that the signature
/// was generated correctly with regards to the provided presignature
/// transcript and randomness.
pub fn verify_threshold_bip340_signature(
    signature: &ThresholdBip340CombinedSignatureInternal,
    derivation_path: &DerivationPath,
    message: &[u8],
    randomness: Randomness,
    presig_transcript: &IDkgTranscriptInternal,
    key_transcript: &IDkgTranscriptInternal,
) -> Result<(), ThresholdBip340VerifySignatureInternalError> {
    signature
        .verify(
            derivation_path,
            message,
            randomness,
            presig_transcript,
            key_transcript,
        )
        .map_err(ThresholdBip340VerifySignatureInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEd25519GenerateSigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEd25519GenerateSigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Create a new threshold Ed25519 Schnorr signature share
///
/// The derivation_path creates a new key relative to the master key
///
/// The nonce should be random and shared by all nodes, for instance
/// by deriving a value from the random tape.
///
/// The presig_transcript is the transcript of the pre-signature (kappa)
///
/// The message can be of any length
pub fn create_ed25519_signature_share(
    derivation_path: &DerivationPath,
    message: &[u8],
    nonce: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    key_opening: &CommitmentOpening,
    presig_opening: &CommitmentOpening,
) -> Result<ThresholdEd25519SignatureShareInternal, ThresholdEd25519GenerateSigShareInternalError> {
    ThresholdEd25519SignatureShareInternal::new(
        derivation_path,
        message,
        nonce,
        key_transcript,
        key_opening,
        presig_transcript,
        presig_opening,
    )
    .map_err(ThresholdEd25519GenerateSigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEd25519VerifySigShareInternalError {
    InvalidArguments(String),
    InconsistentCommitments,
    InvalidSignatureShare,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEd25519VerifySigShareInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidSignatureShare => Self::InvalidSignatureShare,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a signature share
///
/// The values provided must be consistent with when the signature share
/// was created
pub fn verify_ed25519_signature_share(
    sig_share: &ThresholdEd25519SignatureShareInternal,
    derivation_path: &DerivationPath,
    hashed_message: &[u8],
    randomness: Randomness,
    signer_index: NodeIndex,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
) -> Result<(), ThresholdEd25519VerifySigShareInternalError> {
    sig_share
        .verify(
            derivation_path,
            hashed_message,
            randomness,
            signer_index,
            key_transcript,
            presig_transcript,
        )
        .map_err(ThresholdEd25519VerifySigShareInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEd25519CombineSigSharesInternalError {
    UnsupportedAlgorithm,
    InconsistentCommitments,
    InsufficientShares,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEd25519CombineSigSharesInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::CurveMismatch => Self::InconsistentCommitments,
            CanisterThresholdError::InvalidCommitment => Self::InconsistentCommitments,
            CanisterThresholdError::InsufficientDealings => Self::InsufficientShares,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Combine sufficient signature shares into an Ed25519 signature
///
/// The signature shares must be verified prior to use, and there must
/// be at least reconstruction_threshold many of them.
///
/// All shares must have been created with respect to the same derivation path,
/// message, randomness, and transcripts.
pub fn combine_ed25519_signature_shares(
    derivation_path: &DerivationPath,
    message: &[u8],
    randomness: Randomness,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
    reconstruction_threshold: NumberOfNodes,
    sig_shares: &BTreeMap<NodeIndex, ThresholdEd25519SignatureShareInternal>,
) -> Result<ThresholdEd25519CombinedSignatureInternal, ThresholdEd25519CombineSigSharesInternalError>
{
    ThresholdEd25519CombinedSignatureInternal::new(
        derivation_path,
        message,
        randomness,
        key_transcript,
        presig_transcript,
        reconstruction_threshold,
        sig_shares,
    )
    .map_err(ThresholdEd25519CombineSigSharesInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdEd25519VerifySignatureInternalError {
    InvalidSignature,
    UnexpectedCommitmentType,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdEd25519VerifySignatureInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::UnexpectedCommitmentType => Self::UnexpectedCommitmentType,
            CanisterThresholdError::InvalidSignature => Self::InvalidSignature,
            x => Self::InternalError(format!("{:?}", x)),
        }
    }
}

/// Verify a threshold Ed25519 Schnorr signature
///
/// In addition to checking that the signature itself is consistent
/// with the provided message and the public key associated with
/// `derivation_path`, this function also verifies that the signature
/// was generated correctly with regards to the provided presignature
/// transcript and randomness.
pub fn verify_threshold_ed25519_signature(
    signature: &ThresholdEd25519CombinedSignatureInternal,
    derivation_path: &DerivationPath,
    message: &[u8],
    randomness: Randomness,
    presig_transcript: &IDkgTranscriptInternal,
    key_transcript: &IDkgTranscriptInternal,
) -> Result<(), ThresholdEd25519VerifySignatureInternalError> {
    signature
        .verify(
            derivation_path,
            message,
            randomness,
            presig_transcript,
            key_transcript,
        )
        .map_err(ThresholdEd25519VerifySignatureInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeriveThresholdPublicKeyError {
    InvalidArgument(String),
    InternalError(CanisterThresholdError),
}

impl From<CanisterThresholdError> for DeriveThresholdPublicKeyError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InvalidArguments(s) => Self::InvalidArgument(s),
            CanisterThresholdError::CurveMismatch
            | CanisterThresholdError::InconsistentCiphertext
            | CanisterThresholdError::InconsistentOpeningAndCommitment
            | CanisterThresholdError::InsufficientDealings
            | CanisterThresholdError::InsufficientOpenings(_, _)
            | CanisterThresholdError::InterpolationError
            | CanisterThresholdError::InvalidCommitment
            | CanisterThresholdError::InvalidComplaint
            | CanisterThresholdError::InvalidFieldElement
            | CanisterThresholdError::InvalidPoint
            | CanisterThresholdError::InvalidProof
            | CanisterThresholdError::InvalidRandomOracleInput
            | CanisterThresholdError::InvalidRecipients
            | CanisterThresholdError::InvalidScalar
            | CanisterThresholdError::InvalidSecretShare
            | CanisterThresholdError::InvalidSignature
            | CanisterThresholdError::InvalidSignatureShare
            | CanisterThresholdError::InvalidThreshold(_, _)
            | CanisterThresholdError::UnexpectedCommitmentType => Self::InternalError(e),
        }
    }
}

/// Returns a public key derived from `master_public_key` according to the
/// `derivation_path`.  The algorithm id of the derived key is the same
/// as the algorithm id of `master_public_key`.
pub fn derive_threshold_public_key(
    master_public_key: &MasterPublicKey,
    derivation_path: &DerivationPath,
) -> Result<PublicKey, DeriveThresholdPublicKeyError> {
    let expected_curve = match master_public_key.algorithm_id {
        AlgorithmId::EcdsaSecp256k1 => EccCurveType::K256,
        AlgorithmId::ThresholdEcdsaSecp256k1 => EccCurveType::K256,

        AlgorithmId::EcdsaP256 => EccCurveType::P256,
        AlgorithmId::ThresholdEcdsaSecp256r1 => EccCurveType::P256,

        AlgorithmId::SchnorrSecp256k1 => EccCurveType::K256,
        AlgorithmId::ThresholdSchnorrBip340 => EccCurveType::K256,

        AlgorithmId::Ed25519 => EccCurveType::Ed25519,
        AlgorithmId::ThresholdEd25519 => EccCurveType::Ed25519,

        x => {
            return Err(DeriveThresholdPublicKeyError::InvalidArgument(format!(
                "Not a known signature algo related to threshold signatures {:?}",
                x
            )))
        }
    };

    let raw_master_pk = EccPoint::deserialize(expected_curve, &master_public_key.public_key)?;

    let (key_tweak, chain_key) = derivation_path.derive_tweak(&raw_master_pk)?;
    let tweak_g = EccPoint::mul_by_g(&key_tweak);
    let public_key_point = tweak_g.add_points(&raw_master_pk)?;

    Ok(PublicKey {
        algorithm_id: master_public_key.algorithm_id,
        public_key: public_key_point.serialize(),
        chain_key,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IDkgGenerateComplaintsInternalError {
    UnsupportedAlgorithm,
    InvalidArguments(String),
    InternalError(String),
}

impl From<IDkgGenerateComplaintsInternalError> for IDkgLoadTranscriptError {
    fn from(e: IDkgGenerateComplaintsInternalError) -> Self {
        type Igcie = IDkgGenerateComplaintsInternalError;
        type Ilte = IDkgLoadTranscriptError;
        match e {
            Igcie::UnsupportedAlgorithm => Ilte::InvalidArguments {
                internal_error: format!("{:?}", e),
            },
            Igcie::InvalidArguments(internal_error) => Ilte::InvalidArguments { internal_error },
            Igcie::InternalError(internal_error) => Ilte::InternalError { internal_error },
        }
    }
}

impl From<CanisterThresholdError> for IDkgGenerateComplaintsInternalError {
    fn from(threshold_ecdsa_error: CanisterThresholdError) -> Self {
        type Tee = CanisterThresholdError;
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
    algorithm_id: AlgorithmId,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
    associated_data: &[u8],
    receiver_index: NodeIndex,
    secret_key: &MEGaPrivateKey,
    public_key: &MEGaPublicKey,
    seed: Seed,
) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgGenerateComplaintsInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgGenerateComplaintsInternalError::UnsupportedAlgorithm)?;

    Ok(idkg::complaints::generate_complaints(
        alg,
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
    UnsupportedAlgorithm,
    InvalidComplaint,
    InvalidArgument(String),
    InternalError(String),
}

impl From<CanisterThresholdError> for IDkgVerifyComplaintInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InvalidProof => Self::InvalidComplaint,
            CanisterThresholdError::InvalidComplaint => Self::InvalidComplaint,
            CanisterThresholdError::CurveMismatch => Self::InvalidComplaint,
            CanisterThresholdError::InvalidArguments(e) => Self::InvalidArgument(e),
            other => Self::InternalError(format!("{:?}", other)),
        }
    }
}

impl From<IDkgVerifyComplaintInternalError> for IDkgVerifyComplaintError {
    fn from(verify_complaint_internal_error: IDkgVerifyComplaintInternalError) -> Self {
        type Vcie = IDkgVerifyComplaintInternalError;
        type Vce = IDkgVerifyComplaintError;
        match verify_complaint_internal_error {
            Vcie::UnsupportedAlgorithm => Vce::InvalidArgument {
                internal_error: "Unsupported algorithm".to_string(),
            },
            Vcie::InvalidComplaint => Vce::InvalidComplaint,
            Vcie::InternalError(internal_error) => Vce::InternalError { internal_error },
            Vcie::InvalidArgument(internal_error) => Vce::InvalidArgument { internal_error },
        }
    }
}

/// Verifies a complaint against a dealing.
pub fn verify_complaint(
    algorithm_id: AlgorithmId,
    complaint: &IDkgComplaintInternal,
    complainer_index: NodeIndex,
    complainer_key: &MEGaPublicKey,
    dealing: &IDkgDealingInternal,
    dealer_index: NodeIndex,
    associated_data: &[u8],
) -> Result<(), IDkgVerifyComplaintInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(IDkgVerifyComplaintInternalError::UnsupportedAlgorithm)?;

    Ok(complaint.verify(
        alg,
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
    UnsupportedAlgorithm,
}

impl From<CanisterThresholdError> for ThresholdOpenDealingInternalError {
    fn from(e: CanisterThresholdError) -> Self {
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
/// * The dealing has already been publicly verified
/// * The complaint which caused us to provide an opening for this dealing has
///   already been verified to be valid.
pub fn open_dealing(
    algorithm_id: AlgorithmId,
    verified_dealing: &IDkgDealingInternal,
    associated_data: &[u8],
    dealer_index: NodeIndex,
    opener_index: NodeIndex,
    opener_secret_key: &MEGaPrivateKey,
    opener_public_key: &MEGaPublicKey,
) -> Result<CommitmentOpening, ThresholdOpenDealingInternalError> {
    let alg = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
        .ok_or(ThresholdOpenDealingInternalError::UnsupportedAlgorithm)?;

    CommitmentOpening::open_dealing(
        alg,
        verified_dealing,
        associated_data,
        dealer_index,
        opener_index,
        opener_secret_key,
        opener_public_key,
    )
    .map_err(ThresholdOpenDealingInternalError::from)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ThresholdVerifyOpeningInternalError {
    InvalidOpening,
    MismatchingType,
    InternalError(String),
}

impl From<CanisterThresholdError> for ThresholdVerifyOpeningInternalError {
    fn from(e: CanisterThresholdError) -> Self {
        match e {
            CanisterThresholdError::InconsistentOpeningAndCommitment => Self::MismatchingType,
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
/// * The dealing has already been publicly verified
/// # Errors
/// * `ThresholdVerifyOpeningInternalError::InvalidOpening` if the opening does
///   not match with the polynomial commitment.
/// * `ThresholdVerifyOpeningInternalError::MismatchingType` if the opening
///   has a type that is inconsistent with the polynomial commitment.
/// * `ThresholdVerifyOpeningInternalError::InternalError` if there is an
///   unexpected internal error.
pub fn verify_dealing_opening(
    verified_dealing: &IDkgDealingInternal,
    opener_index: NodeIndex,
    opening: &CommitmentOpening,
) -> Result<(), ThresholdVerifyOpeningInternalError> {
    let is_invalid = verified_dealing
        .commitment
        .check_opening(opener_index, opening)
        .is_err();
    if is_invalid {
        return Err(ThresholdVerifyOpeningInternalError::InvalidOpening);
    }
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

// Returns None if the AlgorithmId does not map to threshold ECDSA
fn ecdsa_signature_parameters(algorithm_id: AlgorithmId) -> Option<(EccCurveType, usize)> {
    if algorithm_id.is_threshold_ecdsa() {
        IdkgProtocolAlgorithm::from_algorithm(algorithm_id).map(|alg| {
            let curve = alg.curve();
            (curve, curve.scalar_bytes())
        })
    } else {
        None
    }
}
