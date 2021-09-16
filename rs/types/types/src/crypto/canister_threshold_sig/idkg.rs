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
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

//Note:
//* We may need an API for consensus to know which transcripts have been loaded.

// It should uniquely identify a transcript.
// Can be a string decided by Consensus, e.g. by hashing the fields below, or a
// u64. (CRP-1104)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IDkgTranscriptId(pub usize);

/// A set of receivers for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

/// A set of dealers for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug)]
pub struct IDkgTranscriptParams {
    pub transcript_id: IDkgTranscriptId,
    pub max_corrupt_dealers: NumberOfNodes,
    pub dealers: IDkgDealers,
    pub max_corrupt_receivers: NumberOfNodes,
    pub receivers: IDkgReceivers,
    pub verification_threshold: NumberOfNodes,
    pub registry_version: RegistryVersion,
    pub transcript_type: IDkgTranscriptType,
    pub algorithm_id: AlgorithmId,
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
        transcript_type: IDkgTranscriptType,
        algorithm_id: AlgorithmId,
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
            transcript_type,
            algorithm_id,
        }
    }
}

// Design consideration:
// We could use either full transcripts or IDkgTranscriptId in the Resharing and
// Multiplication variants.
#[derive(Clone, Debug)]
pub enum IDkgTranscriptType {
    RandomSkinny,
    RandomFat,
    Resharing(IDkgTranscript),
    Multiplication(IDkgTranscript, IDkgTranscript),
}

#[derive(Clone, Debug)]
pub struct IDkgTranscript {
    pub transcript_id: IDkgTranscriptId,
    pub receivers: IDkgReceivers,
    pub registry_version: RegistryVersion,
    pub verified_dealings: BTreeMap<NodeId, VerifiedIDkgDealing>,
}

impl IDkgTranscript {
    pub fn deserialize(_data: &[u8]) -> Result<Self, IDkgTranscriptParsingError> {
        unimplemented!("IDkgTranscript::deserialize");
    }

    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("IDkgTranscript::serialize");
    }
}

#[derive(Clone, Debug)]
pub struct IDkgDealing {
    // The identity of the dealer is usually part of the consensus types, and verified there.
    //pub dealer_id:  NodeId,
    pub internal_dealing: CspIDkgDealing,
}

#[derive(Clone, Debug)]
pub struct VerifiedIDkgDealing {
    pub signature: CombinedMultiSigOf<IDkgDealing>,
    pub signers: BTreeSet<NodeId>,
    pub dealing: IDkgDealing,
}

// IDkgComplaint against an indivdual dealing in a transcript.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
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
}

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
}

fn number_of_nodes_from_usize(number: usize) -> Result<NumberOfNodes, ()> {
    let count = NodeIndex::try_from(number).map_err(|_| ())?;
    Ok(NumberOfNodes::from(count))
}
