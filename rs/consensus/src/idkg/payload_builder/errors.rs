use ic_crypto::MegaKeyFromRegistryError;
use ic_interfaces_state_manager::StateManagerError;
use ic_types::{
    consensus::idkg,
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
pub(crate) enum IDkgPayloadError {
    RegistryClientError(RegistryClientError),
    MegaKeyFromRegistryError(MegaKeyFromRegistryError),
    ConsensusSummaryBlockNotFound(Height),
    StateManagerError(StateManagerError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    PreSignatureError(EcdsaPresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    IDkgTranscriptIdError(IDkgTranscriptIdError),
    ThresholdEcdsaSigInputsCreationError(ThresholdEcdsaSigInputsCreationError),
    TranscriptLookupError(idkg::TranscriptLookupError),
    TranscriptCastError(Box<idkg::TranscriptCastError>),
    InvalidChainCacheError(InvalidChainCacheError),
    InitialIDkgDealingsNotUnmaskedParams(Box<InitialIDkgDealings>),
}

impl From<idkg::TranscriptLookupError> for IDkgPayloadError {
    fn from(err: idkg::TranscriptLookupError) -> Self {
        IDkgPayloadError::TranscriptLookupError(err)
    }
}

impl From<RegistryClientError> for IDkgPayloadError {
    fn from(err: RegistryClientError) -> Self {
        IDkgPayloadError::RegistryClientError(err)
    }
}

impl From<StateManagerError> for IDkgPayloadError {
    fn from(err: StateManagerError) -> Self {
        IDkgPayloadError::StateManagerError(err)
    }
}

impl From<EcdsaPresignatureQuadrupleCreationError> for IDkgPayloadError {
    fn from(err: EcdsaPresignatureQuadrupleCreationError) -> Self {
        IDkgPayloadError::PreSignatureError(err)
    }
}

impl From<IDkgParamsValidationError> for IDkgPayloadError {
    fn from(err: IDkgParamsValidationError) -> Self {
        IDkgPayloadError::IDkgParamsValidationError(err)
    }
}

impl From<IDkgTranscriptIdError> for IDkgPayloadError {
    fn from(err: IDkgTranscriptIdError) -> Self {
        IDkgPayloadError::IDkgTranscriptIdError(err)
    }
}

impl From<ThresholdEcdsaSigInputsCreationError> for IDkgPayloadError {
    fn from(err: ThresholdEcdsaSigInputsCreationError) -> Self {
        IDkgPayloadError::ThresholdEcdsaSigInputsCreationError(err)
    }
}

impl From<idkg::TranscriptCastError> for IDkgPayloadError {
    fn from(err: idkg::TranscriptCastError) -> Self {
        IDkgPayloadError::TranscriptCastError(Box::new(err))
    }
}

impl From<InvalidChainCacheError> for IDkgPayloadError {
    fn from(err: InvalidChainCacheError) -> Self {
        IDkgPayloadError::InvalidChainCacheError(err)
    }
}

#[derive(Debug)]
pub(super) enum MembershipError {
    RegistryClientError(RegistryClientError),
    MegaKeyFromRegistryError(MegaKeyFromRegistryError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
}

impl From<MembershipError> for IDkgPayloadError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::RegistryClientError(err) => IDkgPayloadError::RegistryClientError(err),
            MembershipError::MegaKeyFromRegistryError(err) => {
                IDkgPayloadError::MegaKeyFromRegistryError(err)
            }
            MembershipError::SubnetWithNoNodes(subnet_id, err) => {
                IDkgPayloadError::SubnetWithNoNodes(subnet_id, err)
            }
        }
    }
}
