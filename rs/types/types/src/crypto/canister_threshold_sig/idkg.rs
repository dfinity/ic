//! Defines interactive distributed key generation (IDkg) types.
use crate::crypto::canister_threshold_sig::error::{
    IDkgComplaintParsingError, IDkgOpeningParsingError, IDkgParamsValidationError,
    IDkgTranscriptParsingError,
};
use crate::crypto::{AlgorithmId, CombinedMultiSigOf};
use crate::{NodeId, NumberOfNodes, RegistryVersion};
use ic_crypto_internal_types::sign::canister_threshold_sig::{
    CspIDkgComplaint, CspIDkgDealing, CspIDkgOpening,
};
use ic_crypto_internal_types::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

pub mod conversions;
pub use conversions::*;

/// Unique identifier for an IDkg transcript.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgTranscriptId(pub usize);

impl IDkgTranscriptId {
    /// Return the next value of this id.
    pub fn increment(self) -> IDkgTranscriptId {
        IDkgTranscriptId(self.0 + 1)
    }
}

/// A set of receivers for IDkg.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IDkgReceivers {
    receivers: BTreeSet<NodeId>,

    // The count equals receivers.len().
    // This information is redundant since in several places we need the number
    // of receivers as NumberOfNodes. For that, the set length (usize) must
    // be converted to `NodeIndex`, which may fail. To avoid doing this in
    // several places this is done here on initialization.
    count: NumberOfNodes,
}

impl IDkgReceivers {
    /// `IDkgReceivers` can only be created if the following invariants hold:
    /// * Receivers are not empty (error: `ReceiversEmpty`)
    /// * The number of receivers fits into `NodeIndex` (error`:
    ///   TooManyReceivers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(receivers: BTreeSet<NodeId>) -> Result<Self, IDkgParamsValidationError> {
        Self::ensure_receivers_not_empty(&receivers)?;
        let count = Self::number_of_receivers(receivers.len())?;
        Ok(IDkgReceivers { receivers, count })
    }

    fn number_of_receivers(
        receivers_count: usize,
    ) -> Result<NumberOfNodes, IDkgParamsValidationError> {
        number_of_nodes_from_usize(receivers_count)
            .map_err(|_| IDkgParamsValidationError::TooManyReceivers { receivers_count })
    }

    fn ensure_receivers_not_empty(
        receivers: &BTreeSet<NodeId>,
    ) -> Result<(), IDkgParamsValidationError> {
        if receivers.is_empty() {
            return Err(IDkgParamsValidationError::ReceiversEmpty);
        }
        Ok(())
    }

    /// Returns the position of the given `node_id` in the receivers. Returns
    /// `None` if the `node_id` is not a receiver.
    pub fn position(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.receivers
            .iter()
            .position(|receiver| node_id == *receiver)
            .map(|index| NodeIndex::try_from(index).expect("node index overflow"))
    }

    pub fn get(&self) -> &BTreeSet<NodeId> {
        &self.receivers
    }

    /// Returns nodes with the standard indexing.
    ///
    /// Sharing relies on a stable indexing of the nodes.  This iterator
    /// provides the canonical indexing.  That stable indexing is based on
    /// the natural ordering of NodeIds, also used by the BTreeSet, however
    /// that is an implementation detail and external code should not rely
    /// on this.
    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, NodeId)> + '_ {
        (0..).zip(self.receivers.iter().copied())
    }

    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}

/// A set of dealers for IDkg.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IDkgDealers {
    dealers: BTreeSet<NodeId>,

    // The count equals `dealers.len()`.
    // This information is redundant since in several places we need the number
    // of dealers as NumberOfNodes. For that, the set length (`usize`) must
    // be converted to `NodeIndex`, which may fail. To avoid doing this in
    // several places this is done here on initialization.
    count: NumberOfNodes,
}

impl IDkgDealers {
    /// `IDkgDealers` can only be created if the following invariants hold:
    /// * Dealers are not empty (error: `DealersEmpty`)
    /// * The number of dealers fits into `NodeIndex` (error: `TooManyDealers`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(dealers: BTreeSet<NodeId>) -> Result<Self, IDkgParamsValidationError> {
        Self::ensure_dealers_not_empty(&dealers)?;
        let count = Self::number_of_dealers(dealers.len())?;
        Ok(IDkgDealers { dealers, count })
    }

    fn number_of_dealers(dealers_count: usize) -> Result<NumberOfNodes, IDkgParamsValidationError> {
        number_of_nodes_from_usize(dealers_count)
            .map_err(|_| IDkgParamsValidationError::TooManyDealers { dealers_count })
    }

    fn ensure_dealers_not_empty(
        dealers: &BTreeSet<NodeId>,
    ) -> Result<(), IDkgParamsValidationError> {
        if dealers.is_empty() {
            return Err(IDkgParamsValidationError::DealersEmpty);
        }
        Ok(())
    }

    /// Returns the position of the given `node_id` in the dealers. Returns
    /// `None` if the `node_id` is not a dealer.
    pub fn position(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.iter().find_map(|(node_index, this_node_id)| {
            if node_id == this_node_id {
                Some(node_index)
            } else {
                None
            }
        })
    }

    pub fn get(&self) -> &BTreeSet<NodeId> {
        &self.dealers
    }

    /// Returns nodes with the standard indexing.
    ///
    /// Sharing relies on a stable indexing of the nodes.  This iterator
    /// provides the canonical indexing.  That stable indexing is based on
    /// the natural ordering of NodeIds, also used by the BTreeSet, however
    /// that is an implementation detail and external code should not rely
    /// on this.
    pub fn iter(&self) -> impl Iterator<Item = (NodeIndex, NodeId)> + '_ {
        (0..).zip(self.dealers.iter().copied())
    }

    pub fn count(&self) -> NumberOfNodes {
        self.count
    }
}

/// Parameters used in the creation of IDkg dealings and transcripts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgTranscriptParams {
    pub transcript_id: IDkgTranscriptId,
    pub max_corrupt_dealers: NumberOfNodes,
    pub dealers: IDkgDealers,
    pub max_corrupt_receivers: NumberOfNodes,
    pub receivers: IDkgReceivers,
    pub verification_threshold: NumberOfNodes,
    pub registry_version: RegistryVersion,
    pub algorithm_id: AlgorithmId,
    pub operation_type: IDkgTranscriptOperation,
}

impl IDkgTranscriptParams {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transcript_id: IDkgTranscriptId,
        max_corrupt_dealers: NumberOfNodes,
        dealers: IDkgDealers,
        max_corrupt_receivers: NumberOfNodes,
        receivers: IDkgReceivers,
        verification_threshold: NumberOfNodes,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        operation_type: IDkgTranscriptOperation,
    ) -> Self {
        // TODO. Check that
        // * |dealers| > max_corrupt_dealers
        // * |receivers| > max_corrupt_receivers
        // * threshold>max_corrupt_receivers
        // * AlgorithmId is supported.
        Self {
            transcript_id,
            max_corrupt_dealers,
            dealers,
            max_corrupt_receivers,
            receivers,
            verification_threshold,
            registry_version,
            algorithm_id,
            operation_type,
        }
    }
}

/// Origin identifier of a Masked IDkg transcript.
///
/// When the transcript derives from earlier transcripts, these are included
/// in this enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgMaskedTranscriptOrigin {
    Random,
    UnmaskedTimesMasked(IDkgTranscriptId, IDkgTranscriptId),
}

/// Origin identifier of an Unmasked IDkg transcript.
///
/// The earlier transcripts used to derive this transcript are included in this
/// enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgUnmaskedTranscriptOrigin {
    ReshareMasked(IDkgTranscriptId),
    ReshareUnmasked(IDkgTranscriptId),
}

/// Type and origin of an IDkg transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgTranscriptType {
    Masked(IDkgMaskedTranscriptOrigin),
    Unmasked(IDkgUnmaskedTranscriptOrigin),
}

/// Collection of verified IDkg dealings, together with metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgTranscript {
    pub transcript_id: IDkgTranscriptId,
    pub receivers: IDkgReceivers,
    pub registry_version: RegistryVersion,
    pub verified_dealings: BTreeMap<NodeId, IDkgMultiSignedDealing>,
    pub transcript_type: IDkgTranscriptType,
    pub algorithm_id: AlgorithmId,
}

/// Identifier for the way an IDkg transcript is created.
///
/// If earlier transcripts are used in the creation, these are included here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgTranscriptOperation {
    Random,
    ReshareOfMasked(IDkgTranscript),
    ReshareOfUnmasked(IDkgTranscript),
    UnmaskedTimesMasked(IDkgTranscript, IDkgTranscript),
}

impl IDkgTranscript {
    pub fn deserialize(_data: &[u8]) -> Result<Self, IDkgTranscriptParsingError> {
        unimplemented!("IDkgTranscript::deserialize");
    }

    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("IDkgTranscript::serialize");
    }

    pub fn get_type(&self) -> &IDkgTranscriptType {
        &self.transcript_type
    }
}

/// Dealing of an IDkg sharing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgDealing {
    pub internal_dealing: CspIDkgDealing,
}

impl IDkgDealing {
    pub fn dummy_for_tests() -> Self {
        Self {
            internal_dealing: CspIDkgDealing {},
        }
    }
}

/// Dealing of an IDkg sharing, along with a combined multisignature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgMultiSignedDealing {
    pub signature: CombinedMultiSigOf<IDkgDealing>,
    pub signers: BTreeSet<NodeId>,
    pub dealing: IDkgDealing,
}

/// Complaint against an individual IDkg dealing in a transcript.
#[derive(PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgComplaint {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub internal_complaint: CspIDkgComplaint,
}

impl IDkgComplaint {
    pub fn deserialize(_data: &[u8]) -> Result<Self, IDkgComplaintParsingError> {
        unimplemented!("IDkgComplaint::deserialize");
    }

    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("IDkgComplaint::serialize");
    }

    pub fn dummy_for_tests() -> Self {
        use crate::PrincipalId;

        Self {
            transcript_id: IDkgTranscriptId(1),
            dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
            internal_complaint: CspIDkgComplaint {},
        }
    }
}

/// Opening created in response to an IDkgComplaint.
pub struct IDkgOpening {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub internal_opening: CspIDkgOpening,
}

impl IDkgOpening {
    pub fn deserialize(_data: &[u8]) -> Result<Self, IDkgOpeningParsingError> {
        unimplemented!("IDkgOpening::deserialize");
    }

    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("IDkgOpening::serialize");
    }

    pub fn dummy_for_tests() -> Self {
        use crate::PrincipalId;

        Self {
            transcript_id: IDkgTranscriptId(1),
            dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
            internal_opening: CspIDkgOpening {},
        }
    }
}

fn number_of_nodes_from_usize(number: usize) -> Result<NumberOfNodes, ()> {
    let count = NodeIndex::try_from(number).map_err(|_| ())?;
    Ok(NumberOfNodes::from(count))
}
