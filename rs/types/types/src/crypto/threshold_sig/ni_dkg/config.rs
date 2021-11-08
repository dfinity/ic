//! Types related to the non-interactive DKG configuration.
use crate::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTranscript};
use crate::{NodeId, NodeIndex, NumberOfNodes, RegistryVersion};
use core::fmt;
use dealers::NiDkgDealers;
use errors::{NiDkgConfigValidationError, NiDkgThresholdZeroError};
use ic_protobuf::types::v1 as pb;
use receivers::NiDkgReceivers;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

pub mod dealers;
pub mod errors;
pub mod receivers;

/// A validated configuration for non-interactive DKG. This configuration can
/// only exist if all configuration invariants are satisfied. See
/// `NiDkgConfig::new` for a description of the invariants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgConfig {
    pub(crate) dkg_id: NiDkgId,
    max_corrupt_dealers: NumberOfNodes,
    dealers: NiDkgDealers,
    max_corrupt_receivers: NumberOfNodes,
    receivers: NiDkgReceivers,
    threshold: NiDkgThreshold,
    registry_version: RegistryVersion,
    // If the transcript of the previous DKG phase is present, resharing DKG is performed.
    resharing_transcript: Option<NiDkgTranscript>,
}

impl From<&NiDkgConfig> for pb::NiDkgConfig {
    fn from(config: &NiDkgConfig) -> Self {
        Self {
            dkg_id: Some(pb::NiDkgId::from(config.dkg_id)),
            max_corrupt_dealers: config.max_corrupt_dealers.get(),
            dealers: config
                .dealers
                .get()
                .iter()
                .cloned()
                .map(crate::node_id_into_protobuf)
                .collect(),
            max_corrupt_receivers: config.max_corrupt_receivers.get(),
            receivers: config
                .receivers
                .get()
                .iter()
                .cloned()
                .map(crate::node_id_into_protobuf)
                .collect(),
            threshold: config.threshold.get().get(),
            registry_version: config.registry_version.get(),
            resharing_transcript: config
                .resharing_transcript
                .as_ref()
                .map(pb::NiDkgTranscript::from),
        }
    }
}

impl TryFrom<pb::NiDkgConfig> for NiDkgConfig {
    type Error = String;
    fn try_from(config: pb::NiDkgConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            dkg_id: NiDkgId::from_option_protobuf(config.dkg_id, "NiDkgConfig")?,
            max_corrupt_dealers: NumberOfNodes::from(config.max_corrupt_dealers),
            dealers: NiDkgDealers::new(
                config
                    .dealers
                    .into_iter()
                    .map(crate::node_id_try_from_protobuf)
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|err| format!("Problem loading dealers in NiDkgConfig: {:?}", err))?,
            )
            .map_err(|e| format!("{:?}", e))?,
            max_corrupt_receivers: NumberOfNodes::from(config.max_corrupt_receivers),
            receivers: NiDkgReceivers::new(
                config
                    .receivers
                    .into_iter()
                    .map(crate::node_id_try_from_protobuf)
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|err| {
                        format!("Problem loading receivers in NiDkgConfig: {:?}", err)
                    })?,
            )
            .map_err(|e| format!("{:?}", e))?,
            threshold: NiDkgThreshold::new(NumberOfNodes::from(config.threshold))
                .map_err(|e| format!("threshold error {:?}", e))?,
            registry_version: RegistryVersion::from(config.registry_version),
            resharing_transcript: config
                .resharing_transcript
                .map(|transcript| {
                    NiDkgTranscript::try_from(&transcript)
                        .map_err(|e| format!("Converting resharing transcript failed: {:?}", e))
                })
                .transpose()?,
        })
    }
}

/// The non-validated config parameter object to be passed to the `NiDkgConfig`
/// constructor.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgConfigData {
    pub dkg_id: NiDkgId,
    pub max_corrupt_dealers: NumberOfNodes,
    pub dealers: BTreeSet<NodeId>,
    pub max_corrupt_receivers: NumberOfNodes,
    pub receivers: BTreeSet<NodeId>,
    pub threshold: NumberOfNodes,
    pub registry_version: RegistryVersion,
    /// If the transcript of the previous DKG phase is present, resharing DKG is
    /// performed.
    pub resharing_transcript: Option<NiDkgTranscript>,
}

/// Configures non-interactive DKG.
impl NiDkgConfig {
    /// Creates a new non-interactive DKG config.
    ///
    /// A `NiDkgConfig` can only be created if the following invariants hold:
    /// * The threshold is not zero (error: `ThresholdZero`),
    /// * The threshold is greater than max_corrupt_receivers (error:
    ///   `InsufficientThreshold`)
    /// * The dealers and receivers are not empty (errors: `DealersEmpty`,
    ///   `ReceiversEmpty`)
    /// * The number of dealers and receivers fit into `NumberOfNodes` (errors:
    ///   `TooManyDealers`, `TooManyReceivers`)
    /// * The number of dealers is greater than max_corrupt_dealers (error:
    ///   `InsufficientDealers`)
    /// * The number of receivers is greater than or equal to
    ///   max_corrupt_receivers + threshold (error: `InsufficientReceivers`).
    /// * If a resharing transcript is present:
    ///   * The dealers are all contained in the transcript's committee. (error:
    ///     `DealersNotInResharingCommittee`)
    ///   * The number of dealers is greater than or equal to the transcript's
    ///     threshold. (error: `InsufficientDealersForResharingThreshold`)
    ///
    /// If an invariant is not satisfied, the `Err` as indicated above is
    /// returned.
    pub fn new(data: NiDkgConfigData) -> Result<Self, NiDkgConfigValidationError> {
        let threshold = NiDkgThreshold::new(data.threshold)?;
        let dealers = NiDkgDealers::new(data.dealers)?;
        let receivers = NiDkgReceivers::new(data.receivers)?;
        Self::ensure_sufficient_threshold(threshold, data.max_corrupt_receivers)?;
        Self::ensure_sufficient_dealers(&dealers, data.max_corrupt_dealers)?;
        Self::ensure_sufficient_receivers(&receivers, data.max_corrupt_receivers, threshold)?;
        if let Some(rs_transcript) = &data.resharing_transcript {
            Self::ensure_dealers_contained_in_resharing_committee(&dealers, rs_transcript)?;
            Self::ensure_sufficient_dealers_for_resharing_threshold(&dealers, rs_transcript)?;
        }
        Ok(Self {
            dkg_id: data.dkg_id,
            max_corrupt_dealers: data.max_corrupt_dealers,
            dealers,
            max_corrupt_receivers: data.max_corrupt_receivers,
            receivers,
            threshold,
            registry_version: data.registry_version,
            resharing_transcript: data.resharing_transcript,
        })
    }

    pub fn dkg_id(&self) -> NiDkgId {
        self.dkg_id
    }

    pub fn max_corrupt_dealers(&self) -> NumberOfNodes {
        self.max_corrupt_dealers
    }

    pub fn dealers(&self) -> &NiDkgDealers {
        &self.dealers
    }

    pub fn max_corrupt_receivers(&self) -> NumberOfNodes {
        self.max_corrupt_receivers
    }

    pub fn receivers(&self) -> &NiDkgReceivers {
        &self.receivers
    }

    pub fn threshold(&self) -> NiDkgThreshold {
        self.threshold
    }

    pub fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    pub fn resharing_transcript(&self) -> &Option<NiDkgTranscript> {
        &self.resharing_transcript
    }

    /// Ensures threshold > max_corrupt_receivers
    fn ensure_sufficient_threshold(
        threshold: NiDkgThreshold,
        max_corrupt_receivers: NumberOfNodes,
    ) -> Result<(), NiDkgConfigValidationError> {
        if threshold.get() <= max_corrupt_receivers {
            return Err(NiDkgConfigValidationError::InsufficientThreshold {
                threshold,
                max_corrupt_receivers,
            });
        }
        Ok(())
    }

    /// Ensures #dealers > max_corrupt_dealers
    fn ensure_sufficient_dealers(
        dealers: &NiDkgDealers,
        max_corrupt_dealers: NumberOfNodes,
    ) -> Result<(), NiDkgConfigValidationError> {
        if dealers.count() <= max_corrupt_dealers {
            return Err(NiDkgConfigValidationError::InsufficientDealers {
                dealer_count: dealers.count(),
                max_corrupt_dealers,
            });
        }
        Ok(())
    }

    /// Ensures #receivers >= (max_corrupt_receivers + threshold)
    fn ensure_sufficient_receivers(
        receivers: &NiDkgReceivers,
        max_corrupt_receivers: NumberOfNodes,
        threshold: NiDkgThreshold,
    ) -> Result<(), NiDkgConfigValidationError> {
        let insufficient_receivers_error = NiDkgConfigValidationError::InsufficientReceivers {
            receiver_count: receivers.count(),
            max_corrupt_receivers,
            threshold,
        };
        if receivers.count() < max_corrupt_receivers {
            return Err(insufficient_receivers_error);
        }
        // The previous if-statement ensures that calculating receivers.count() -
        // max_corrupt_receivers in the following line does not overflow.
        if receivers.count() - max_corrupt_receivers < threshold.get() {
            return Err(insufficient_receivers_error);
        }
        Ok(())
    }

    /// Ensures dealers are all contained in resharing committee
    fn ensure_dealers_contained_in_resharing_committee(
        dealers: &NiDkgDealers,
        resharing_transcript: &NiDkgTranscript,
    ) -> Result<(), NiDkgConfigValidationError> {
        if !dealers
            .get()
            .is_subset(resharing_transcript.committee.get())
        {
            let dealers = dealers.get();
            let committee = &resharing_transcript.committee;
            return Err(NiDkgConfigValidationError::DealersNotInResharingCommittee {
                dealers_missing: dealers.difference(committee.get()).cloned().collect(),
                dealers_existing: dealers.intersection(committee.get()).cloned().collect(),
                resharing_committee: committee.get().clone(),
            });
        }
        Ok(())
    }

    /// Ensures #dealers >= resharing threshold
    fn ensure_sufficient_dealers_for_resharing_threshold(
        dealers: &NiDkgDealers,
        resharing_transcript: &NiDkgTranscript,
    ) -> Result<(), NiDkgConfigValidationError> {
        if dealers.count() < resharing_transcript.threshold.get() {
            return Err(
                NiDkgConfigValidationError::InsufficientDealersForResharingThreshold {
                    dealer_count: dealers.count(),
                    resharing_threshold: resharing_transcript.threshold,
                },
            );
        }
        Ok(())
    }
}

impl fmt::Display for NiDkgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

/// The minimum number of nodes required to generate a valid threshold
/// signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgThreshold {
    threshold: NumberOfNodes,
}

impl NiDkgThreshold {
    /// A `DkgThreshold` can only be created if the following invariants hold:
    /// * The threshold is at least 1 (error: `ThresholdIsZero`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(threshold: NumberOfNodes) -> Result<Self, NiDkgThresholdZeroError> {
        Self::ensure_threshold_is_not_zero(threshold)?;
        Ok(NiDkgThreshold { threshold })
    }

    pub fn get(self) -> NumberOfNodes {
        self.threshold
    }

    fn ensure_threshold_is_not_zero(
        threshold: NumberOfNodes,
    ) -> Result<(), NiDkgThresholdZeroError> {
        if threshold.get() == 0 {
            return Err(NiDkgThresholdZeroError {});
        }
        Ok(())
    }
}

fn number_of_nodes_from_usize(count: usize) -> Result<NumberOfNodes, ()> {
    let count = NodeIndex::try_from(count).map_err(|_| ())?;
    Ok(NumberOfNodes::from(count))
}
