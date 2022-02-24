//! Defines interactive distributed key generation (IDkg) types.
use crate::consensus::ecdsa::EcdsaDealing;
use crate::consensus::get_faults_tolerated;
use crate::crypto::canister_threshold_sig::error::IDkgParamsValidationError;
use crate::crypto::{AlgorithmId, CombinedMultiSigOf};
use crate::{NodeId, NumberOfNodes, RegistryVersion};
use ic_base_types::SubnetId;
use ic_crypto_internal_types::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

pub mod conversions;
pub use conversions::*;

#[cfg(test)]
mod tests;

/// Unique identifier for an IDkg transcript.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgTranscriptId {
    id: usize,
    subnet: SubnetId,
}

impl IDkgTranscriptId {
    pub fn new(subnet: SubnetId, id: usize) -> Self {
        Self { id, subnet }
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn subnet(&self) -> &SubnetId {
        &self.subnet
    }

    /// Return the next value of this id.
    pub fn increment(self) -> Self {
        Self {
            id: self.id + 1,
            subnet: self.subnet,
        }
    }
}

/// A set of receivers for IDkg.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// * The number of receivers is large enough to gather sufficient honest
    ///   multisignature shares (i.e. |self| >= verification_threshold(|self|) +
    ///   faults_tolerated(|self|)) (error: `UnsatisfiedVerificationThreshold`)
    ///
    /// If an invariant is not satisifed, the `Err` as indicated above is
    /// returned.
    pub fn new(receivers: BTreeSet<NodeId>) -> Result<Self, IDkgParamsValidationError> {
        Self::ensure_receivers_not_empty(&receivers)?;
        let count = Self::number_of_receivers(receivers.len())?;

        let ret = IDkgReceivers { receivers, count };

        ret.ensure_verification_threshold_satisfied()?;

        Ok(ret)
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

    fn ensure_verification_threshold_satisfied(&self) -> Result<(), IDkgParamsValidationError> {
        let faulty = number_of_nodes_from_usize(get_faults_tolerated(self.count().get() as usize))
            .expect("by construction, this fits in a u32");
        let threshold = self.verification_threshold() + faulty;
        if self.count() < threshold {
            Err(
                IDkgParamsValidationError::UnsatisfiedVerificationThreshold {
                    threshold: threshold.get(),
                    receiver_count: self.count().get(),
                },
            )
        } else {
            Ok(())
        }
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

    /// Number of contributions needed to reconstruct a sharing.
    pub fn reconstruction_threshold(&self) -> NumberOfNodes {
        let faulty = get_faults_tolerated(self.count().get() as usize);
        let threshold = faulty + 1;
        number_of_nodes_from_usize(threshold).expect("by construction, this fits in a u32")
    }

    /// Number of multi-signature shares needed to include a dealing in a
    /// transcript.
    pub fn verification_threshold(&self) -> NumberOfNodes {
        let faulty = number_of_nodes_from_usize(get_faults_tolerated(self.count().get() as usize))
            .expect("by construction, this fits in a u32");
        self.reconstruction_threshold() + faulty
    }
}

impl PartialEq for IDkgReceivers {
    /// Equality is determined by comparison of the set of nodes
    /// *and* their indices.
    fn eq(&self, rhs: &Self) -> bool {
        self.iter().collect::<BTreeMap<_, _>>() == rhs.iter().collect()
    }
}

impl Eq for IDkgReceivers {}

impl Hash for IDkgReceivers {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.iter().collect::<BTreeMap<_, _>>().hash(state)
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
    transcript_id: IDkgTranscriptId,
    dealers: IDkgDealers,
    receivers: IDkgReceivers,
    registry_version: RegistryVersion,
    algorithm_id: AlgorithmId,
    operation_type: IDkgTranscriptOperation,
}

impl IDkgTranscriptParams {
    /// Checks the following invariants:
    /// * |dealers| > 0 and |receivers| > 0 (errors: `DealersEmpty`
    ///   and `ReceiversEmpty`)
    /// * |dealers| >= self.collection_threshold + faults_tolerated(|dealers|)
    ///   (error: `UnsatisfiedCollectionThreshold`)
    /// * algorithm_id is of type `ThresholdEcdsaSecp256k1` (error:
    ///   `UnsupportedAlgorithmId`)
    /// * If `operation_type` is:
    ///   - ReshareOfMasked(t):
    ///     - t is of type Masked(_)
    ///     - self.dealers is contained in t.receivers
    ///   - ReshareOfUnmasked(t):
    ///     - t is of type Unmasked(_)
    ///     - self.dealers is contained in t.receivers
    ///   - UnmaskedTimesMasked(s,t):
    ///     - s is of type Unmasked(_)
    ///     - t is of type Masked(_)
    ///     - s.receivers == t.receivers
    ///     - self.dealers is contained in t.receivers (errors:
    ///       `DealersNotContainedInPreviousReceivers` or
    /// `WrongTypeForOriginalTranscript`)
    pub fn new(
        transcript_id: IDkgTranscriptId,
        dealers: BTreeSet<NodeId>,
        receivers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
        algorithm_id: AlgorithmId,
        operation_type: IDkgTranscriptOperation,
    ) -> Result<Self, IDkgParamsValidationError> {
        let ret = Self {
            transcript_id,
            dealers: IDkgDealers::new(dealers)?,
            receivers: IDkgReceivers::new(receivers)?,
            registry_version,
            algorithm_id,
            operation_type,
        };

        ret.ensure_collection_threshold_satisfied()?;
        ret.ensure_algorithm_id_supported()?;
        ret.check_consistency_of_input_transcripts()?;

        Ok(ret)
    }

    pub fn transcript_id(&self) -> IDkgTranscriptId {
        self.transcript_id
    }

    pub fn dealers(&self) -> &IDkgDealers {
        &self.dealers
    }

    pub fn receivers(&self) -> &IDkgReceivers {
        &self.receivers
    }

    pub fn registry_version(&self) -> RegistryVersion {
        self.registry_version
    }

    pub fn algorithm_id(&self) -> AlgorithmId {
        self.algorithm_id
    }

    pub fn operation_type(&self) -> &IDkgTranscriptOperation {
        &self.operation_type
    }

    /// Number of contributions needed to reconstruct a sharing.
    pub fn reconstruction_threshold(&self) -> NumberOfNodes {
        self.receivers.reconstruction_threshold()
    }

    /// Returns the dealer index of a node, or `None` if the node is not included in the set of dealers.
    ///
    /// For a Random transcript, the index of a dealer correspond to the position of `node_id` in the dealer set.
    /// For all other transcript operations, the dealer index corresponds to its position of `node_id` in the previous set of receivers.
    pub fn dealer_index(&self, node_id: NodeId) -> Option<NodeIndex> {
        match self.dealers().position(node_id) {
            None => None,
            Some(index) => {
                match &self.operation_type {
                    IDkgTranscriptOperation::Random => Some(index),
                    IDkgTranscriptOperation::ReshareOfMasked(transcript) => {
                        transcript.receivers.position(node_id)
                    }
                    IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
                        transcript.receivers.position(node_id)
                    }
                    IDkgTranscriptOperation::UnmaskedTimesMasked(transcript_1, _transcript_2) => {
                        // transcript_1.receivers == transcript_2.receivers already checked by
                        // IDkgTranscriptParams::new
                        transcript_1.receivers.position(node_id)
                    }
                }
            }
        }
    }

    /// Number of multi-signature shares needed to include a dealing in a
    /// transcript.
    pub fn verification_threshold(&self) -> NumberOfNodes {
        self.receivers.verification_threshold()
    }

    /// Number of verified dealings needed for a transcript.
    pub fn collection_threshold(&self) -> NumberOfNodes {
        match &self.operation_type {
            IDkgTranscriptOperation::Random => {
                let faulty = get_faults_tolerated(self.dealers.count().get() as usize);
                number_of_nodes_from_usize(faulty + 1).expect("by construction, this fits in a u32")
            }
            IDkgTranscriptOperation::ReshareOfMasked(t) => t.reconstruction_threshold(),
            IDkgTranscriptOperation::ReshareOfUnmasked(t) => t.reconstruction_threshold(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(s, t) => {
                t.reconstruction_threshold() + s.reconstruction_threshold() - NumberOfNodes::from(1)
            }
        }
    }

    /// Contextual data needed for the creation of a dealing.
    pub fn context_data(&self) -> Vec<u8> {
        context_data(
            &self.transcript_id,
            self.registry_version,
            self.algorithm_id,
        )
    }

    fn ensure_collection_threshold_satisfied(&self) -> Result<(), IDkgParamsValidationError> {
        let faulty =
            number_of_nodes_from_usize(get_faults_tolerated(self.dealers.count().get() as usize))
                .expect("by construction, this fits in a u32");

        let threshold = faulty + self.collection_threshold();

        if self.dealers.count() < threshold {
            Err(IDkgParamsValidationError::UnsatisfiedCollectionThreshold {
                threshold: threshold.get(),
                dealer_count: self.dealers.count().get(),
            })
        } else {
            Ok(())
        }
    }

    fn ensure_algorithm_id_supported(&self) -> Result<(), IDkgParamsValidationError> {
        match self.algorithm_id {
            AlgorithmId::ThresholdEcdsaSecp256k1 => Ok(()),
            _ => Err(IDkgParamsValidationError::UnsupportedAlgorithmId {
                algorithm_id: self.algorithm_id,
            }),
        }
    }

    fn check_consistency_of_input_transcripts(&self) -> Result<(), IDkgParamsValidationError> {
        match &self.operation_type {
            IDkgTranscriptOperation::Random => Ok(()),
            IDkgTranscriptOperation::ReshareOfMasked(IDkgTranscript {
                receivers: original_receivers,
                transcript_type: IDkgTranscriptType::Masked(_),
                ..
            }) => {
                if self.dealers.get().is_subset(original_receivers.get()) {
                    Ok(())
                } else {
                    Err(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers)
                }
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(IDkgTranscript {
                receivers: original_receivers,
                transcript_type: IDkgTranscriptType::Unmasked(_),
                ..
            }) => {
                if self.dealers.get().is_subset(original_receivers.get()) {
                    Ok(())
                } else {
                    Err(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers)
                }
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                IDkgTranscript {
                    receivers: left_receivers,
                    transcript_type: IDkgTranscriptType::Unmasked(_),
                    ..
                },
                IDkgTranscript {
                    receivers: right_receivers,
                    transcript_type: IDkgTranscriptType::Masked(_),
                    ..
                },
            ) => {
                if left_receivers == right_receivers
                    && self.dealers.get().is_subset(right_receivers.get())
                {
                    Ok(())
                } else {
                    Err(IDkgParamsValidationError::DealersNotContainedInPreviousReceivers)
                }
            }
            _ => Err(IDkgParamsValidationError::WrongTypeForOriginalTranscript),
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
    pub verified_dealings: BTreeMap<NodeIndex, IDkgMultiSignedDealing>,
    pub transcript_type: IDkgTranscriptType,
    pub algorithm_id: AlgorithmId,
    pub internal_transcript_raw: Vec<u8>,
}

/// Identifier for the way an IDkg transcript is created.
///
/// If earlier transcripts are used in the creation, these are included here.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgTranscriptOperation {
    Random,
    ReshareOfMasked(IDkgTranscript),
    ReshareOfUnmasked(IDkgTranscript),
    UnmaskedTimesMasked(IDkgTranscript, IDkgTranscript),
}

impl IDkgTranscript {
    pub fn get_type(&self) -> &IDkgTranscriptType {
        &self.transcript_type
    }

    /// Number of contributions needed to reconstruct a sharing.
    pub fn reconstruction_threshold(&self) -> NumberOfNodes {
        self.receivers.reconstruction_threshold()
    }

    /// Number of multi-signature shares needed to include a dealing in a
    /// transcript.
    pub fn verification_threshold(&self) -> NumberOfNodes {
        self.receivers.verification_threshold()
    }

    /// Contextual data needed for the creation of a dealing.
    pub fn context_data(&self) -> Vec<u8> {
        context_data(
            &self.transcript_id,
            self.registry_version,
            self.algorithm_id,
        )
    }

    /// Returns the dealer ID for the given node index, or `None` if there is no such dealer.
    pub fn dealer_id_for_index(&self, index: NodeIndex) -> Option<NodeId> {
        self.verified_dealings
            .get(&index)
            .map(|signed_dealing| signed_dealing.dealing.idkg_dealing.dealer_id)
    }

    /// Returns the index of the dealer with the given ID, or `None` if there is no such index.
    pub fn index_for_dealer_id(&self, dealer_id: NodeId) -> Option<NodeIndex> {
        self.verified_dealings
            .iter()
            .find(|(_index, signed_dealing)| {
                signed_dealing.dealing.idkg_dealing.dealer_id == dealer_id
            })
            .map(|(index, _signed_dealing)| *index)
    }
}

/// Dealing of an IDkg sharing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgDealing {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub internal_dealing_raw: Vec<u8>,
}

/// Dealing of an IDkg sharing, along with a combined multisignature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgMultiSignedDealing {
    pub signature: CombinedMultiSigOf<EcdsaDealing>,
    pub signers: BTreeSet<NodeId>,
    pub dealing: EcdsaDealing,
}

/// Complaint against an individual IDkg dealing in a transcript.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgComplaint {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub internal_complaint_raw: Vec<u8>,
}

/// Opening created in response to an IDkgComplaint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgOpening {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub internal_opening_raw: Vec<u8>,
}

fn number_of_nodes_from_usize(number: usize) -> Result<NumberOfNodes, ()> {
    let count = NodeIndex::try_from(number).map_err(|_| ())?;
    Ok(NumberOfNodes::from(count))
}

/// Contextual data needed for the creation of a dealing.
///
/// Returns a byte vector consisting of:
/// - IDkgTranscriptId::SubnetId, as a byte-string (prefixed with its
///   64-bit-big-endian-integer length)
/// - IDkgTranscriptId::id, as a big-endian 64-bit integer
/// - RegistryVersion, as a big-endian 64-bit integer
/// - AlgorithmId, as an 8-bit integer value
fn context_data(
    transcript_id: &IDkgTranscriptId,
    registry_version: RegistryVersion,
    algorithm_id: AlgorithmId,
) -> Vec<u8> {
    let mut ret = Vec::with_capacity(8 + transcript_id.subnet().get().as_slice().len() + 8 + 8 + 1);

    ret.extend_from_slice(&(transcript_id.subnet().get().as_slice().len() as u64).to_be_bytes());
    ret.extend_from_slice(transcript_id.subnet().get().as_slice());
    ret.extend_from_slice(&(transcript_id.id() as u64).to_be_bytes());
    ret.extend_from_slice(&(registry_version.get() as u64).to_be_bytes());
    ret.push(algorithm_id as u8);

    ret
}
