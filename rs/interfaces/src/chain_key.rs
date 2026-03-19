use ic_error_types::UserError;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_types::{
    Height,
    batch::ChainKeyAgreement,
    consensus::idkg::common::BuildSignatureInputsError,
    crypto::{
        canister_threshold_sig::error::{
            ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaVerifyCombinedSignatureError,
            ThresholdSchnorrCombineSigSharesError, ThresholdSchnorrVerifyCombinedSigError,
        },
        vetkd::{VetKdKeyShareCombinationError, VetKdKeyVerificationError},
    },
    messages::CallbackId,
    registry::RegistryClientError,
    state_manager::StateManagerError,
};

#[derive(Clone, Debug)]
pub enum CombineSharesError {
    Ecdsa(ThresholdEcdsaCombineSigSharesError),
    Schnorr(ThresholdSchnorrCombineSigSharesError),
    VetKd(VetKdKeyShareCombinationError),
    NoSharesFound,
}

impl CombineSharesError {
    pub fn is_unsatisfied_reconstruction_threshold(&self) -> bool {
        matches!(
            self,
            CombineSharesError::NoSharesFound
                | CombineSharesError::Ecdsa(
                    ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold { .. }
                )
                | CombineSharesError::Schnorr(
                    ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold { .. }
                )
                | CombineSharesError::VetKd(
                    VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold { .. }
                )
        )
    }
}

#[derive(Debug)]
pub enum ChainKeyAgreementValidationError {
    DecodingError(String),
    BuildSignatureInputsError(BuildSignatureInputsError),
    VetKd(VetKdKeyVerificationError),
    Ecdsa(ThresholdEcdsaVerifyCombinedSignatureError),
    Schnorr(ThresholdSchnorrVerifyCombinedSigError),
}

impl ChainKeyAgreementValidationError {
    pub fn is_nidkg_transcript_not_loaded(&self) -> bool {
        matches!(
            self,
            ChainKeyAgreementValidationError::VetKd(
                VetKdKeyVerificationError::ThresholdSigDataNotFound(_)
            )
        )
    }
}

impl From<UserError> for ChainKeyAgreementValidationError {
    fn from(err: UserError) -> Self {
        ChainKeyAgreementValidationError::DecodingError(err.to_string())
    }
}

impl From<BuildSignatureInputsError> for ChainKeyAgreementValidationError {
    fn from(err: BuildSignatureInputsError) -> Self {
        ChainKeyAgreementValidationError::BuildSignatureInputsError(err)
    }
}

#[derive(Debug)]
pub enum InvalidChainKeyPayloadReason {
    /// The feature is not enabled
    Disabled,
    /// The payload could not be deserialized
    DeserializationFailed(ProxyDecodeError),
    /// The payload contained a response that was already delivered
    DuplicateResponse(CallbackId),
    /// The payload contained a response that wasn't requested
    MissingContext(CallbackId),
    /// The payload proposes the wrong type of agreement for a request context. For instance, the
    /// payload rejected a request that should have been accepted or vice versa.
    MismatchedAgreement {
        expected: Option<ChainKeyAgreement>,
        received: Option<ChainKeyAgreement>,
    },
    /// A success response was cryptographically invalid
    InvalidChainKeyAgreement(ChainKeyAgreementValidationError),
}

#[derive(Debug)]
pub enum ChainKeyPayloadValidationFailure {
    /// The state was not available for a height
    StateUnavailable(StateManagerError),
    /// The DKG summary was not available for a height
    DkgSummaryUnavailable(Height),
    /// The registry client returned an error
    RegistryClientError(RegistryClientError),
    /// Crypto failed to determine the validity of the key
    InvalidChainKeyAgreement(ChainKeyAgreementValidationError),
}
