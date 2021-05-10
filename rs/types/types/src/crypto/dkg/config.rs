use super::*;
use crate::consensus::Threshold;

use crate::{NodeIndex, NumberOfNodes};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::slice::Iter;

#[cfg(test)]
mod tests;

/// Configures interactive DKG.
// TODO (CRP-311): replace Config by DkgConfig in two steps:
// 1. internally in crypto: convert Config to DkgConfig in each method and use
// DkgConfig
// 2. externally: change api, remove 1, adapt caller (consensus) code
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Config {
    pub dkg_id: IDkgId,
    pub dealers: Vec<NodeId>,
    // The ordering of receivers defines the node indices for threshold.
    pub receivers: Vec<NodeId>,
    pub threshold: Threshold,
    // If the transcript of the previous DKG phase is present, resharing DKG is performed.
    pub resharing_transcript: Option<Transcript>,
}

/// A validated configuration for interactive DKG. This configuration can only
/// exist if all configuration invariants are satisfied. See `DkgConfig::new`
/// for a description of the invariants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgConfig {
    dkg_id: IDkgId,
    dealers: Dealers,
    receivers: Receivers,
    threshold: DkgThreshold,
    // If the transcript of the previous DKG phase is present, resharing DKG is performed.
    resharing_transcript: Option<Transcript>,
}

/// The non-validated config parameter object to be passed to the `DkgConfig`
/// constructor.
pub struct DkgConfigData {
    pub dkg_id: IDkgId,
    pub dealers: Vec<NodeId>,
    // The ordering of receivers defines the node indices for threshold.
    pub receivers: Vec<NodeId>,
    pub threshold: Threshold,
    // If the transcript of the previous DKG phase is present, resharing DKG is performed.
    pub resharing_transcript: Option<Transcript>,
}

/// Configures interactive DKG.
impl DkgConfig {
    /// A `DkgConfig` can only be created if the following invariants hold:
    /// * The threshold is at least 1 (error: `ThresholdIsZero`)
    /// * The threshold fits into `NodeIndex` (error: `InvalidThreshold`)
    /// * Receivers and dealers do not contain duplicates (errors:
    ///   `DuplicateReceivers`, `DuplicateDealers`)
    /// * There are at least threshold many dealers (error:
    ///   `InsufficientDealersForThreshold`)
    /// * The number of receivers and dealers fits into `NodeIndex` (errors:
    ///   `TooManyReceivers`, `TooManyDealers`)
    /// * \#receivers >= 2\*threshold-1, as DKG requires at least 2\*threshold-1
    ///   valid responses (error: `InsufficientReceiversForThreshold`)
    /// * If a resharing transcript is present, the dealers must be contained in
    ///   the committee of the resharing transcript. (error:
    ///   `MissingDealerInResharingCommittee`)
    ///
    /// If an invariant is not satisfied, the `Err` as indicated above is
    /// returned.
    pub fn new(data: DkgConfigData) -> Result<Self, DkgConfigValidationError> {
        let dealers = Dealers::new(data.dealers)?;
        let receivers = Receivers::new(data.receivers)?;
        let threshold = DkgThreshold::new(data.threshold)?;
        Self::ensure_num_of_dealers_sufficient_for_threshold(threshold.get(), &dealers)?;
        Self::ensure_num_of_receivers_sufficient_for_threshold(threshold.get(), &receivers)?;
        Self::ensure_resharing_committee_contains_dealers(&dealers, &data.resharing_transcript)?;
        Ok(Self {
            dkg_id: data.dkg_id,
            dealers,
            receivers,
            threshold,
            resharing_transcript: data.resharing_transcript,
        })
    }

    pub fn dkg_id(&self) -> IDkgId {
        self.dkg_id
    }

    pub fn dealers(&self) -> &Dealers {
        &self.dealers
    }

    pub fn receivers(&self) -> &Receivers {
        &self.receivers
    }

    pub fn threshold(&self) -> &DkgThreshold {
        &self.threshold
    }

    pub fn resharing_transcript(&self) -> &Option<Transcript> {
        &self.resharing_transcript
    }

    fn ensure_num_of_dealers_sufficient_for_threshold(
        threshold: NumberOfNodes,
        dealers: &Dealers,
    ) -> Result<(), DkgConfigValidationError> {
        let threshold = threshold.get();
        let num_dealers = dealers.count().get();
        if num_dealers < threshold {
            return Err(DkgConfigValidationError::InsufficientDealersForThreshold);
        }
        Ok(())
    }

    /// ensures that #receivers >= 2*threshold - 1
    fn ensure_num_of_receivers_sufficient_for_threshold(
        threshold: NumberOfNodes,
        receivers: &Receivers,
    ) -> Result<(), DkgConfigValidationError> {
        let threshold = threshold.get();
        let num_receivers = receivers.count().get();
        // the inequality is rearranged to avoid u32 overflows
        if threshold > (num_receivers - 1) / 2 + 1 {
            return Err(DkgConfigValidationError::InsufficientReceiversForThreshold);
        }
        Ok(())
    }

    fn ensure_resharing_committee_contains_dealers(
        dealers: &Dealers,
        resharing_transcript: &Option<Transcript>,
    ) -> Result<(), DkgConfigValidationError> {
        if let Some(transcript) = resharing_transcript {
            let resharing_committee_contains_dealers = dealers
                .iter()
                .all(|dealer| transcript.committee.contains(&Some(*dealer)));
            if !resharing_committee_contains_dealers {
                return Err(DkgConfigValidationError::MissingDealerInResharingCommittee);
            }
        }
        Ok(())
    }
}

/// A set of dealers for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dealers {
    dealers: Vec<NodeId>,
    count: NumberOfNodes,
}

impl Dealers {
    /// `Dealers` can only be created if the following invariants hold:
    /// * Dealers do not contain duplicates (error: `DuplicateDealers`)
    /// * Dealers are not empty (error: `InsufficientDealersForThreshold`)
    /// * The number of dealers fits into `NodeIndex` (error: `TooManyDealers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(dealers: Vec<NodeId>) -> Result<Self, DkgConfigValidationError> {
        Self::ensure_dealers_not_empty(&dealers)?;
        Self::ensure_no_duplicate_dealers(&dealers)?;
        let count = Self::number_of_dealers(dealers.len())?;
        Ok(Dealers { dealers, count })
    }

    fn number_of_dealers(dealers_len: usize) -> Result<NumberOfNodes, DkgConfigValidationError> {
        number_of_nodes_from_usize(dealers_len)
            .map_err(|_| DkgConfigValidationError::TooManyDealers)
    }

    fn ensure_dealers_not_empty(dealers: &[NodeId]) -> Result<(), DkgConfigValidationError> {
        if dealers.is_empty() {
            return Err(DkgConfigValidationError::InsufficientDealersForThreshold);
        }
        Ok(())
    }

    fn ensure_no_duplicate_dealers(dealers: &[NodeId]) -> Result<(), DkgConfigValidationError> {
        if has_duplicates(dealers) {
            return Err(DkgConfigValidationError::DuplicateDealers);
        }
        Ok(())
    }

    pub fn get(&self) -> &Vec<NodeId> {
        &self.dealers
    }

    pub fn iter(&self) -> Iter<'_, NodeId> {
        self.dealers.iter()
    }

    /// The count equals `dealers.len()`.
    ///
    /// This information is redundant since in several places we need the number
    /// of dealers as NumberOfNodes. For that, the vec length (`usize`) must
    /// be converted to `NodeIndex`, which may fail. To avoid doing this in
    /// several places this is done here on initialization.
    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}

/// A set of receivers for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Receivers {
    // The ordering of receivers defines the node indices for threshold.
    receivers: Vec<NodeId>,
    count: NumberOfNodes,
}

impl Receivers {
    /// `Receivers` can only be created if the following invariants hold:
    /// * Receivers do not contain duplicates (error: `DuplicateReceivers`)
    /// * Receivers are not empty (error: `InsufficientReceiversForThreshold`)
    /// * The number of receivers fits into `NodeIndex` (error:
    ///   `TooManyReceivers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(receivers: Vec<NodeId>) -> Result<Self, DkgConfigValidationError> {
        Self::ensure_receivers_not_empty(&receivers)?;
        Self::ensure_no_duplicate_receivers(&receivers)?;
        let count = Self::number_of_receivers(receivers.len())?;
        Ok(Receivers { receivers, count })
    }

    fn number_of_receivers(
        receivers_len: usize,
    ) -> Result<NumberOfNodes, DkgConfigValidationError> {
        number_of_nodes_from_usize(receivers_len)
            .map_err(|_| DkgConfigValidationError::TooManyReceivers)
    }

    fn ensure_receivers_not_empty(receivers: &[NodeId]) -> Result<(), DkgConfigValidationError> {
        if receivers.is_empty() {
            return Err(DkgConfigValidationError::InsufficientReceiversForThreshold);
        }
        Ok(())
    }

    fn ensure_no_duplicate_receivers(receivers: &[NodeId]) -> Result<(), DkgConfigValidationError> {
        if has_duplicates(receivers) {
            return Err(DkgConfigValidationError::DuplicateReceivers);
        }
        Ok(())
    }

    pub fn get(&self) -> &[NodeId] {
        &self.receivers
    }

    pub fn iter(&self) -> Iter<'_, NodeId> {
        self.receivers.iter()
    }

    /// The count equals receivers.len().
    ///
    /// This information is redundant since in several places we need the number
    /// of receivers as NumberOfNodes. For that, the vec length (usize) must
    /// be converted to `NodeIndex`, which may fail. To avoid doing this in
    /// several places this is done here on initialization.
    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgThreshold {
    threshold: NumberOfNodes,
}

// TODO (CRP-311): Consider replacing `Threshold` with DkgThreshold.
impl DkgThreshold {
    /// A `DkgThreshold` can only be created if the following invariants hold:
    /// * The threshold is at least 1 (error: `ThresholdIsZero`)
    /// * The threshold fits into `NodeIndex` (error: `InvalidThreshold`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(threshold: Threshold) -> Result<Self, DkgConfigValidationError> {
        Self::ensure_threshold_is_not_zero(threshold)?;
        let threshold_as_node_index = NodeIndex::try_from(threshold)
            .map_err(|_| DkgConfigValidationError::InvalidThreshold)?;
        Ok(DkgThreshold {
            threshold: NumberOfNodes::from(threshold_as_node_index),
        })
    }

    pub fn get(&self) -> NumberOfNodes {
        self.threshold
    }

    fn ensure_threshold_is_not_zero(threshold: Threshold) -> Result<(), DkgConfigValidationError> {
        if threshold == 0 {
            return Err(DkgConfigValidationError::ThresholdIsZero);
        }
        Ok(())
    }
}

// TODO (CRP-311): get rid of nr_of_nodes_from_threshold
fn number_of_nodes_from_usize(number: usize) -> Result<NumberOfNodes, ()> {
    let count = NodeIndex::try_from(number).map_err(|_| ())?;
    Ok(NumberOfNodes::from(count))
}

fn has_duplicates(nodes: &[NodeId]) -> bool {
    let node_set: HashSet<_> = nodes.iter().collect();
    node_set.len() != nodes.len()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgConfigValidationError {
    TooManyReceivers,
    TooManyDealers,
    DuplicateReceivers,
    DuplicateDealers,
    InvalidThreshold,
    InsufficientDealersForThreshold,
    InsufficientReceiversForThreshold,
    MissingDealerInResharingCommittee,
    ThresholdIsZero,
}
