//! The DKG public interface.
use ic_base_types::NodeId;
use ic_interfaces_state_manager::StateManagerError;
use ic_types::{
    consensus::dkg,
    crypto::{
        threshold_sig::ni_dkg::{
            config::errors::NiDkgConfigValidationError,
            errors::{
                create_transcript_error::DkgCreateTranscriptError,
                verify_dealing_error::DkgVerifyDealingError,
            },
        },
        CryptoError, CryptoHashOf,
    },
    registry::RegistryClientError,
    Height,
};
use std::time::Duration;

use crate::validation::ValidationError;

/// The DkgPool is used to store messages that are exchanged between nodes in
/// the process of executing dkg.
pub trait DkgPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// Returns the validated entries older than the age threshold
    fn get_validated_older_than(
        &self,
        age_threshold: Duration,
    ) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
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
    HandleInvalid(CryptoHashOf<dkg::Message>, String),
    Purge(Height),
}

pub type ChangeSet = Vec<ChangeAction>;

impl From<ChangeAction> for ChangeSet {
    fn from(change_action: ChangeAction) -> Self {
        vec![change_action]
    }
}

/// Transient Dkg message validation errors.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum PermanentError {
    CryptoError(CryptoError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(dkg::Summary, dkg::Summary),
    MissingDkgConfigForDealing,
    LastSummaryHasMultipleConfigsForSameTag,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    MissingRegistryVersion(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
    FailedToCreateDkgConfig(NiDkgConfigValidationError),
}

/// Permanent Dkg message validation errors.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum TransientError {
    /// Crypto related errors.
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    FailedToGetDkgIntervalSettingFromRegistry(RegistryClientError),
    FailedToGetSubnetMemberListFromRegistry(RegistryClientError),
    MissingDkgStartBlock,
}

/// Dkg errors.
pub type DkgMessageValidationError = ValidationError<PermanentError, TransientError>;

impl From<DkgCreateTranscriptError> for PermanentError {
    fn from(err: DkgCreateTranscriptError) -> Self {
        PermanentError::DkgCreateTranscriptError(err)
    }
}

impl From<DkgCreateTranscriptError> for TransientError {
    fn from(err: DkgCreateTranscriptError) -> Self {
        TransientError::DkgCreateTranscriptError(err)
    }
}

impl From<DkgVerifyDealingError> for PermanentError {
    fn from(err: DkgVerifyDealingError) -> Self {
        PermanentError::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for TransientError {
    fn from(err: DkgVerifyDealingError) -> Self {
        TransientError::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for PermanentError {
    fn from(err: CryptoError) -> Self {
        PermanentError::CryptoError(err)
    }
}

impl From<CryptoError> for TransientError {
    fn from(err: CryptoError) -> Self {
        TransientError::CryptoError(err)
    }
}

impl From<PermanentError> for DkgMessageValidationError {
    fn from(err: PermanentError) -> Self {
        ValidationError::Permanent(err)
    }
}

impl From<TransientError> for DkgMessageValidationError {
    fn from(err: TransientError) -> Self {
        ValidationError::Transient(err)
    }
}
