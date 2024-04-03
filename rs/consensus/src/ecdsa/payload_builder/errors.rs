use ic_crypto::MegaKeyFromRegistryError;
use ic_interfaces_state_manager::StateManagerError;
use ic_types::{
    consensus::ecdsa,
    crypto::canister_threshold_sig::{
        error::{
            EcdsaPresignatureQuadrupleCreationError, IDkgParamsValidationError,
            IDkgTranscriptIdError, ThresholdEcdsaSigInputsCreationError,
        },
        idkg::InitialIDkgDealings,
    },
    registry::RegistryClientError,
    Height, RegistryVersion, SubnetId,
};

use super::InvalidChainCacheError;

#[derive(Clone, Debug, PartialEq)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
// #[allow(dead_code)]
pub(crate) enum EcdsaPayloadError {
    RegistryClientError(RegistryClientError),
    MegaKeyFromRegistryError(MegaKeyFromRegistryError),
    ConsensusSummaryBlockNotFound(Height),
    StateManagerError(StateManagerError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    PreSignatureError(EcdsaPresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    IDkgTranscriptIdError(IDkgTranscriptIdError),
    ThresholdEcdsaSigInputsCreationError(ThresholdEcdsaSigInputsCreationError),
    TranscriptLookupError(ecdsa::TranscriptLookupError),
    TranscriptCastError(ecdsa::TranscriptCastError),
    InvalidChainCacheError(InvalidChainCacheError),
    InitialIDkgDealingsNotUnmaskedParams(Box<InitialIDkgDealings>),
}

impl From<ecdsa::TranscriptLookupError> for EcdsaPayloadError {
    fn from(err: ecdsa::TranscriptLookupError) -> Self {
        EcdsaPayloadError::TranscriptLookupError(err)
    }
}

impl From<RegistryClientError> for EcdsaPayloadError {
    fn from(err: RegistryClientError) -> Self {
        EcdsaPayloadError::RegistryClientError(err)
    }
}

impl From<StateManagerError> for EcdsaPayloadError {
    fn from(err: StateManagerError) -> Self {
        EcdsaPayloadError::StateManagerError(err)
    }
}

impl From<EcdsaPresignatureQuadrupleCreationError> for EcdsaPayloadError {
    fn from(err: EcdsaPresignatureQuadrupleCreationError) -> Self {
        EcdsaPayloadError::PreSignatureError(err)
    }
}

impl From<IDkgParamsValidationError> for EcdsaPayloadError {
    fn from(err: IDkgParamsValidationError) -> Self {
        EcdsaPayloadError::IDkgParamsValidationError(err)
    }
}

impl From<IDkgTranscriptIdError> for EcdsaPayloadError {
    fn from(err: IDkgTranscriptIdError) -> Self {
        EcdsaPayloadError::IDkgTranscriptIdError(err)
    }
}

impl From<ThresholdEcdsaSigInputsCreationError> for EcdsaPayloadError {
    fn from(err: ThresholdEcdsaSigInputsCreationError) -> Self {
        EcdsaPayloadError::ThresholdEcdsaSigInputsCreationError(err)
    }
}

impl From<ecdsa::TranscriptCastError> for EcdsaPayloadError {
    fn from(err: ecdsa::TranscriptCastError) -> Self {
        EcdsaPayloadError::TranscriptCastError(err)
    }
}

impl From<InvalidChainCacheError> for EcdsaPayloadError {
    fn from(err: InvalidChainCacheError) -> Self {
        EcdsaPayloadError::InvalidChainCacheError(err)
    }
}

#[derive(Debug)]
pub(super) enum MembershipError {
    RegistryClientError(RegistryClientError),
    MegaKeyFromRegistryError(MegaKeyFromRegistryError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
}

impl From<MembershipError> for EcdsaPayloadError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::RegistryClientError(err) => {
                EcdsaPayloadError::RegistryClientError(err)
            }
            MembershipError::MegaKeyFromRegistryError(err) => {
                EcdsaPayloadError::MegaKeyFromRegistryError(err)
            }
            MembershipError::SubnetWithNoNodes(subnet_id, err) => {
                EcdsaPayloadError::SubnetWithNoNodes(subnet_id, err)
            }
        }
    }
}
