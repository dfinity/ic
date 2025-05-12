//! The DKG public interface.
use crate::validation::ValidationError;
use ic_types::{
    consensus::dkg,
    crypto::{
        threshold_sig::ni_dkg::errors::{
            create_transcript_error::DkgCreateTranscriptError,
            verify_dealing_error::DkgVerifyDealingError,
        },
        CryptoError,
    },
    registry::RegistryClientError,
    state_manager::StateManagerError,
    Height, NodeId,
};

/// Errors which could occur when creating a Dkg payload.
#[derive(PartialEq, Debug)]
pub enum DkgPayloadCreationError {
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    FailedToGetDkgIntervalSettingFromRegistry(RegistryClientError),
    FailedToGetSubnetMemberListFromRegistry(RegistryClientError),
    FailedToGetVetKdKeyList(RegistryClientError),
    MissingDkgStartBlock,
}

/// Reasons for why a dkg payload might be invalid.
#[derive(PartialEq, Debug)]
pub enum InvalidDkgPayloadReason {
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(dkg::Summary, dkg::Summary),
    MissingDkgConfigForDealing,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
    /// There are multiple dealings from the same dealer in the payload.
    DuplicateDealers,
    /// The number of dealings in the payload exceeds the maximum allowed number of dealings.
    TooManyDealings {
        limit: usize,
        actual: usize,
    },
}

/// Possible failures which could occur while validating a dkg payload. They don't imply that the
/// payload is invalid.
#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub enum DkgPayloadValidationFailure {
    PayloadCreationFailed(DkgPayloadCreationError),
    /// Crypto related errors.
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    FailedToGetMaxDealingsPerBlock(RegistryClientError),
    FailedToGetRegistryVersion,
}

/// Dkg errors.
pub type PayloadValidationError =
    ValidationError<InvalidDkgPayloadReason, DkgPayloadValidationFailure>;

impl From<DkgVerifyDealingError> for InvalidDkgPayloadReason {
    fn from(err: DkgVerifyDealingError) -> Self {
        InvalidDkgPayloadReason::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for DkgPayloadValidationFailure {
    fn from(err: DkgVerifyDealingError) -> Self {
        DkgPayloadValidationFailure::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for InvalidDkgPayloadReason {
    fn from(err: CryptoError) -> Self {
        InvalidDkgPayloadReason::CryptoError(err)
    }
}

impl From<CryptoError> for DkgPayloadValidationFailure {
    fn from(err: CryptoError) -> Self {
        DkgPayloadValidationFailure::CryptoError(err)
    }
}

impl From<InvalidDkgPayloadReason> for PayloadValidationError {
    fn from(err: InvalidDkgPayloadReason) -> Self {
        PayloadValidationError::InvalidArtifact(err)
    }
}

impl From<DkgPayloadValidationFailure> for PayloadValidationError {
    fn from(err: DkgPayloadValidationFailure) -> Self {
        PayloadValidationError::ValidationFailed(err)
    }
}

impl From<DkgPayloadCreationError> for PayloadValidationError {
    fn from(err: DkgPayloadCreationError) -> Self {
        PayloadValidationError::ValidationFailed(
            DkgPayloadValidationFailure::PayloadCreationFailed(err),
        )
    }
}

/// The DkgPool is used to store messages that are exchanged between nodes in
/// the process of executing dkg.
pub trait DkgPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// The start height of the currently _computed_ DKG interval; the invariant
    /// we want to maintain for all messages in validated and unvalidated
    /// sections is that they correspond to a DKG Id with the start height
    /// equal to current_start_height.
    fn get_current_start_height(&self) -> Height;
    /// Checks if the message is present in the validated section.
    fn validated_contains(&self, msg: &dkg::Message) -> bool;
}

/// Various actions that can be performed in DKG.
#[derive(Debug)]
pub enum ChangeAction {
    AddToValidated(dkg::Message),
    MoveToValidated(dkg::Message),
    RemoveFromUnvalidated(dkg::Message),
    HandleInvalid(dkg::DkgMessageId, String),
    Purge(Height),
}

pub type Mutations = Vec<ChangeAction>;

impl From<ChangeAction> for Mutations {
    fn from(change_action: ChangeAction) -> Self {
        vec![change_action]
    }
}
