//! Errors that may occur in the context of validating non-interactive DKG
//! configurations.
use super::*;
use std::fmt;

#[cfg(test)]
mod tests;

/// Occurs if the threshold is zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NiDkgThresholdZeroError {}

/// Occurs if a non-interactive DKG configuration is invalid.
#[derive(Clone, PartialEq, Eq)]
pub enum NiDkgConfigValidationError {
    ThresholdZero,
    DealersEmpty,
    ReceiversEmpty,
    TooManyReceivers {
        receivers_count: usize,
    },
    TooManyDealers {
        dealers_count: usize,
    },
    InsufficientThreshold {
        threshold: NiDkgThreshold,
        max_corrupt_receivers: NumberOfNodes,
    },
    InsufficientDealers {
        dealer_count: NumberOfNodes,
        max_corrupt_dealers: NumberOfNodes,
    },
    InsufficientReceivers {
        receiver_count: NumberOfNodes,
        max_corrupt_receivers: NumberOfNodes,
        threshold: NiDkgThreshold,
    },
    DealersNotInResharingCommittee {
        dealers_missing: BTreeSet<NodeId>,
        dealers_existing: BTreeSet<NodeId>,
        resharing_committee: BTreeSet<NodeId>,
    },
    InsufficientDealersForResharingThreshold {
        dealer_count: NumberOfNodes,
        resharing_threshold: NiDkgThreshold,
    },
}

impl From<NiDkgThresholdZeroError> for NiDkgConfigValidationError {
    fn from(_error: NiDkgThresholdZeroError) -> Self {
        NiDkgConfigValidationError::ThresholdZero
    }
}

impl fmt::Display for NiDkgConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NiDkgConfigValidationError::ThresholdZero =>
                write!(f, "The threshold must not be zero."),
            NiDkgConfigValidationError::DealersEmpty =>
                write!(f, "The dealers must not be empty."),
            NiDkgConfigValidationError::ReceiversEmpty =>
                write!(f, "The receivers must not be empty."),
            NiDkgConfigValidationError::TooManyReceivers {receivers_count} =>
                write!(f, "The number of receivers does not fit into NumberOfNodes. Number of receivers: {}", receivers_count),
            NiDkgConfigValidationError::TooManyDealers {dealers_count} =>
                write!(f, "The number of dealers does not fit into NumberOfNodes. Number of dealers: {}", dealers_count),
            NiDkgConfigValidationError::InsufficientThreshold { threshold, max_corrupt_receivers } =>
                write!(f, "The threshold (value: {}) must be greater than max_corrupt_receivers (value: {}).", threshold.get(), max_corrupt_receivers),
            NiDkgConfigValidationError::InsufficientDealers { dealer_count: dealers_count, max_corrupt_dealers } =>
                write!(f, "The number of dealers (value: {}) must be greater than max_corrupt_dealers (value: {}).", dealers_count, max_corrupt_dealers),
            NiDkgConfigValidationError::InsufficientReceivers { receiver_count: receivers_count, max_corrupt_receivers, threshold } =>
                write!(f, "The number of receivers (value: {}) must be greater than or equal to max_corrupt_receivers (value: {}) + threshold (value: {}).", receivers_count, max_corrupt_receivers, threshold.get()),
            NiDkgConfigValidationError::DealersNotInResharingCommittee {dealers_missing, dealers_existing, resharing_committee} =>
                write!(f, "The dealers must all be contained in the resharing committee. Dealers missing in committee: {:?}, dealers in committee: {:?}, resharing committee: {:?}", dealers_missing, dealers_existing, resharing_committee),
            NiDkgConfigValidationError::InsufficientDealersForResharingThreshold {dealer_count, resharing_threshold} =>
                write!(f, "The number of dealers (value: {}) must be greater than or equal to the resharing threshold (value: {})", dealer_count, resharing_threshold.threshold.get()),
        }
    }
}

impl fmt::Debug for NiDkgConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
