//! Defines interactive distributed key generation (IDkg) types.
use crate::consensus::get_faults_tolerated;
use crate::crypto::canister_threshold_sig::error::impl_display_using_debug;
use crate::crypto::canister_threshold_sig::error::{
    IDkgParamsValidationError, IDkgTranscriptIdError, InitialIDkgDealingsValidationError,
};
use crate::crypto::{AlgorithmId, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator};
use crate::signature::{BasicSignature, BasicSignatureBatch};
use crate::{Height, NodeId, NumberOfNodes, RegistryVersion};
use ic_base_types::SubnetId;
use ic_crypto_internal_types::NodeIndex;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::num::TryFromIntError;

pub mod conversions;
pub mod proto_conversions;

#[cfg(test)]
mod tests;

/// Globally unique identifier of an IDKG transcript.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgTranscriptId {
    /// Identifier incremented by consensus.
    id: u64,
    /// Specifies which subnet generates the dealings for this instance of the IDKG protocol.
    source_subnet: SubnetId,
    /// Finalized block height in the `source_subnet` which specifies
    /// the beginning of this instance of the IDKG protocol.
    source_height: Height,
}

impl IDkgTranscriptId {
    pub fn new(subnet: SubnetId, id: u64, height: Height) -> Self {
        Self {
            id,
            source_subnet: subnet,
            source_height: height,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn source_subnet(&self) -> &SubnetId {
        &self.source_subnet
    }

    pub fn source_height(&self) -> Height {
        self.source_height
    }

    /// Returns the next Transcript ID.
    pub fn increment(self) -> Self {
        Self {
            id: self.id + 1,
            source_subnet: self.source_subnet,
            source_height: self.source_height,
        }
    }

    /// Updates the `height` of the Transcript ID.
    ///
    /// # Errors:
    /// * If the `height` is smaller than `self.source_height` the error `DecreasedBlockHeight` is returned.
    pub(crate) fn update_height(self, height: Height) -> Result<Self, IDkgTranscriptIdError> {
        if height < self.source_height {
            return Err(IDkgTranscriptIdError::DecreasedBlockHeight {
                existing_height: self.source_height,
                updated_height: height,
            });
        }
        Ok(Self {
            id: self.id,
            source_subnet: self.source_subnet,
            source_height: height,
        })
    }
}

impl_display_using_debug!(IDkgTranscriptId);

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

impl AsRef<IDkgReceivers> for IDkgReceivers {
    fn as_ref(&self) -> &IDkgReceivers {
        self
    }
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
    /// If an invariant is not satisfied, the `Err` as indicated above is
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
    ///
    /// This method is intended to be PRIVATE. For public methods for obtaining
    /// a receiver's index, the methods of the objects like [`IDkgTranscript`],
    /// [`IDkgTranscriptParams`], or [`ThresholdEcdsaSigInputs`] should be used.
    fn position(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.receivers
            .iter()
            .position(|receiver| node_id == *receiver)
            .map(|index| NodeIndex::try_from(index).expect("node index overflow"))
    }

    pub fn contains(&self, node_id: NodeId) -> bool {
        self.receivers.contains(&node_id)
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
    /// If an invariant is not satisfied, the `Err` as indicated above is
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

    pub fn contains(&self, node_id: NodeId) -> bool {
        self.dealers.contains(&node_id)
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

/// Parameters used throughout the IDKG protocol.
/// Note that the same parameters *must* be used throughout an execution of the IDKG protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgTranscriptParams {
    transcript_id: IDkgTranscriptId,
    dealers: IDkgDealers,
    receivers: IDkgReceivers,
    registry_version: RegistryVersion,
    /// Identifies the cryptographic signature scheme used in the
    /// protocol.  Currently only
    /// [`AlgorithmId::ThresholdEcdsaSecp256k1`] and
    /// [`AlgorithmId::ThresholdEcdsaSecp256r1`] are supported.
    algorithm_id: AlgorithmId,
    /// Mode of operation for this current execution of the protocol.
    operation_type: IDkgTranscriptOperation,
}

impl AsRef<IDkgReceivers> for IDkgTranscriptParams {
    fn as_ref(&self) -> &IDkgReceivers {
        self.receivers()
    }
}

impl AsRef<IDkgDealers> for IDkgTranscriptParams {
    fn as_ref(&self) -> &IDkgDealers {
        self.dealers()
    }
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
    ///       `WrongTypeForOriginalTranscript`)
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
    /// For a Random or RandomUnmasked transcript, the index of a dealer correspond to the position of `node_id` in the dealer set.
    /// For all other transcript operations, the dealer index corresponds to its position of `node_id` in the previous set of receivers.
    pub fn dealer_index(&self, node_id: NodeId) -> Option<NodeIndex> {
        let index = self
            .dealers()
            .iter()
            .find_map(|(node_index, this_node_id)| {
                if node_id == this_node_id {
                    Some(node_index)
                } else {
                    None
                }
            })?;
        match &self.operation_type {
            IDkgTranscriptOperation::Random => Some(index),
            IDkgTranscriptOperation::RandomUnmasked => Some(index),
            IDkgTranscriptOperation::ReshareOfMasked(transcript) => {
                transcript.index_for_signer_id(node_id)
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
                transcript.index_for_signer_id(node_id)
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(transcript_1, _transcript_2) => {
                // transcript_1.receivers == transcript_2.receivers already checked by
                // IDkgTranscriptParams::new
                transcript_1.index_for_signer_id(node_id)
            }
        }
    }

    /// Returns the dealer index of a node, or `None` if the node is not included in the set of receivers.
    pub fn receiver_index(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.receivers.position(node_id)
    }

    /// Number of multi-signature shares needed to include a dealing in a
    /// transcript.
    pub fn verification_threshold(&self) -> NumberOfNodes {
        self.receivers.verification_threshold()
    }

    /// Number of verified dealings needed to create a transcript.
    pub fn collection_threshold(&self) -> NumberOfNodes {
        match &self.operation_type {
            IDkgTranscriptOperation::Random | IDkgTranscriptOperation::RandomUnmasked => {
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

    /// Returns the number of unverified dealings needed to reshare an unmasked transcript to a different subnet.
    /// For params used in transcript operations other than `ReshareOfUnmasked` this method returns `None`.
    ///
    /// This threshold guarantees that the receiving subnet will receive a sufficient number of honest dealings to be able to finalize the transcript.
    pub fn unverified_dealings_collection_threshold(&self) -> Option<NumberOfNodes> {
        match &self.operation_type {
            // Random operation not currently supported for distinct dealer and receiver subnets.
            IDkgTranscriptOperation::Random => None,
            IDkgTranscriptOperation::RandomUnmasked => None,
            // Reshare of masked transcript not currently supported for distinct dealer and receiver subnets.
            IDkgTranscriptOperation::ReshareOfMasked(_) => None,
            IDkgTranscriptOperation::ReshareOfUnmasked(_) => {
                let faulty = get_faults_tolerated(self.dealers.count.get() as usize);
                let collection_threshold = number_of_nodes_from_usize(2 * faulty + 1)
                    .expect("by construction, this fits in a u32");
                Some(collection_threshold)
            }
            // Assuming fault tolerance of `f` nodes out of `3*f+1`, it cannot be guaranteed that the receiving subnet will be able to finalize a transcript for UnmaskedTimesMasked operation.
            IDkgTranscriptOperation::UnmaskedTimesMasked(_, _) => None,
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
        if self.algorithm_id.is_threshold_ecdsa() || self.algorithm_id.is_threshold_schnorr() {
            Ok(())
        } else {
            Err(IDkgParamsValidationError::UnsupportedAlgorithmId {
                algorithm_id: self.algorithm_id,
            })
        }
    }

    fn check_consistency_of_input_transcripts(&self) -> Result<(), IDkgParamsValidationError> {
        match &self.operation_type {
            IDkgTranscriptOperation::Random => Ok(()),
            IDkgTranscriptOperation::RandomUnmasked => Ok(()),
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

impl_display_using_debug!(IDkgTranscriptParams);

/// Initial params and dealings for a set of receivers assigned to a different subnet.
/// Only dealings intended for resharing an unmasked transcript can be included in InitialIDkgDealings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Hash)]
pub struct InitialIDkgDealings {
    params: IDkgTranscriptParams,
    dealings: Vec<SignedIDkgDealing>,
}

impl InitialIDkgDealings {
    /// Creates an initial set of dealings for receivers on a different subnet with exactly
    /// `params.unverified_dealings_collection_threshold()` dealings, which is the minimum number
    /// required by the receiving subnet to complete the IDKG protocol successfully.
    /// The initial dealings contain at most one dealing from every dealer.
    ///
    /// A `InitialIDkgDealings` can only be created if the following invariants hold:
    /// * The `params.operation_type` is `IDkgTranscriptOperation::ReshareOfUnmasked`, otherwise
    ///   the error variant `InvalidTranscriptOperation` is returned.
    /// * The dealings are from nodes in `params.dealers`, otherwise the error variant
    ///   `DealerNotAllowed` is returned.
    /// * The dealings are for the transcript `params.transcript_id`, otherwise the error variant
    ///   `MismatchingDealing` is returned.
    /// * Only one dealing is provided from each dealer, otherwise the error variant
    ///   `MultipleDealingsFromSameDealer` is returned.
    /// * There are at least `params.unverified_dealings_collection_threshold()` dealings from
    ///   distinct dealers, otherwise the error variant `UnsatisfiedCollectionThreshold` is returned.
    /// * The `params.dealers` and `params.receivers` are disjoint, otherwise the error variant
    ///   `DealersAndReceiversNotDisjoint` is returned.
    pub fn new(
        params: IDkgTranscriptParams,
        dealings: Vec<SignedIDkgDealing>,
    ) -> Result<Self, InitialIDkgDealingsValidationError> {
        if !params.dealers.get().is_disjoint(params.receivers.get()) {
            return Err(InitialIDkgDealingsValidationError::DealersAndReceiversNotDisjoint);
        }
        match params.unverified_dealings_collection_threshold() {
            Some(threshold) => {
                let mut dealings_map = BTreeMap::new();
                for dealing in &dealings {
                    if params.dealer_index(dealing.dealer_id()).is_none() {
                        return Err(InitialIDkgDealingsValidationError::DealerNotAllowed {
                            node_id: dealing.dealer_id(),
                        });
                    }
                    if dealing.idkg_dealing().transcript_id != params.transcript_id {
                        return Err(InitialIDkgDealingsValidationError::MismatchingDealing);
                    }
                    if dealings_map.insert(dealing.dealer_id(), dealing).is_some() {
                        return Err(
                            InitialIDkgDealingsValidationError::MultipleDealingsFromSameDealer {
                                node_id: dealing.dealer_id(),
                            },
                        );
                    }
                }
                let min_dealings: Vec<SignedIDkgDealing> = dealings_map
                    .into_values()
                    .take(threshold.get() as usize)
                    .cloned()
                    .collect();

                if min_dealings.len() < threshold.get() as usize {
                    return Err(
                        InitialIDkgDealingsValidationError::UnsatisfiedCollectionThreshold {
                            threshold: threshold.get(),
                            dealings_count: min_dealings.len() as u32,
                        },
                    );
                }

                Ok(Self {
                    params,
                    dealings: min_dealings,
                })
            }
            None => Err(InitialIDkgDealingsValidationError::InvalidTranscriptOperation),
        }
    }

    pub fn params(&self) -> &IDkgTranscriptParams {
        &self.params
    }
    pub fn dealings(&self) -> &Vec<SignedIDkgDealing> {
        &self.dealings
    }
}

impl<'de> Deserialize<'de> for InitialIDkgDealings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct InitialIDkgDealingsUnchecked {
            params: IDkgTranscriptParams,
            dealings: Vec<SignedIDkgDealing>,
        }
        let unchecked = InitialIDkgDealingsUnchecked::deserialize(deserializer)?;

        InitialIDkgDealings::new(unchecked.params, unchecked.dealings).map_err(|validation_error| {
            D::Error::custom(format!("invariants violated: {validation_error}"))
        })
    }
}

/// Origin identifier of a Masked IDkg transcript.
///
/// When the transcript derives from earlier transcripts, these are included
/// in this enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum IDkgMaskedTranscriptOrigin {
    Random,
    UnmaskedTimesMasked(IDkgTranscriptId, IDkgTranscriptId),
}

/// Origin identifier of an Unmasked IDkg transcript.
///
/// The earlier transcripts used to derive this transcript are included in this
/// enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum IDkgUnmaskedTranscriptOrigin {
    ReshareMasked(IDkgTranscriptId),
    ReshareUnmasked(IDkgTranscriptId),
    Random,
}

/// Type and origin of an IDkg transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum IDkgTranscriptType {
    /// Masked transcripts contain dealings based on Pedersen verifiable secret sharing which
    /// perfectly hides the value shared in the dealing. This means that the commitment to the
    /// coefficients of the polynomial looks like the sequence `g^(a_0)h^(r_0), g^(a_1)h^(r_1), ...
    /// g^(a_n)h^(r_n)`, where the `r_i` are random elements and `g` and `h` are two diffenrent
    /// group's generators.
    Masked(IDkgMaskedTranscriptOrigin),

    /// Unmasked transcripts contain dealings based on Feldmann verifiable secret sharing which
    /// leak `g^(a_0)` (`a_0` being the shared value) and are therefore not hiding. The commitment to
    /// the coefficients of the polynomial looks like the sequence `g^(a_0),g^(a_1),...,g^(a_n)`,
    /// where the `a_i` correspond to the polynomial's coefficients and `g` to a group's generator.
    Unmasked(IDkgUnmaskedTranscriptOrigin),
}

/// An IDKG transcript contains a collection of verified IDKG dealings together with some metadata.
///
/// Depending on the type of commitment to the polynomial used for the IDKG dealings, the
/// transcript is considered:
/// * [`Masked`][`IDkgTranscriptType::Masked`] if the commitment perfectly hides the shared value.
/// * [`Unmasked`][`IDkgTranscriptType::Unmasked`] if the commitment is not perfectly hiding and
///   may reveal some information about the shared value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgTranscript {
    pub transcript_id: IDkgTranscriptId,
    pub receivers: IDkgReceivers,
    pub registry_version: RegistryVersion,
    pub verified_dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
    pub transcript_type: IDkgTranscriptType,
    pub algorithm_id: AlgorithmId,
    #[serde(with = "serde_bytes")]
    pub internal_transcript_raw: Vec<u8>,
}

impl AsRef<IDkgReceivers> for IDkgTranscript {
    fn as_ref(&self) -> &IDkgReceivers {
        &self.receivers
    }
}

/// Identifier for the way an IDKG transcript is created.
///
/// If earlier transcripts are used in the creation, these are included here.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum IDkgTranscriptOperation {
    /// Generates a new public/private key pair shared among the replicas.
    ///
    /// The resulting transcript is `masked` and so the public key is also not revealed to the
    /// parties.
    Random,

    /// Starts from a `masked` transcript and returns an `unmasked` transcript.
    ///
    /// Takes in a secret share `x` and outputs `g^x` (g is a group's generator) to
    /// all parties.
    ///
    /// Useful to compute the public key from a masked transcript.
    ReshareOfMasked(IDkgTranscript),

    /// Starts from an `unmasked` transcript and returns an `unmasked` transcript.
    ///
    /// Reshares the public key. Needed, e.g., after subnet topology changes.
    ReshareOfUnmasked(IDkgTranscript),

    /// Starts from a pair of transcripts (the first being `unmasked` while the second is `masked`)
    /// to produce a `masked` transcript.
    ///
    /// Useful to compute the product transcripts in
    /// [`EcdsaPreSignatureQuadruple`][`crate::crypto::canister_threshold_sig::EcdsaPreSignatureQuadruple`]:
    /// * Given a unmasked transcript for sharing a random value `kappa` and a masked transcript
    ///   for sharing a random value `lambda`, compute the masked transcript for sharing the value
    ///   `kappa * lambda`.
    /// * Given a unmasked transcript for sharing a random value `alpha` and a masked transcript
    ///   for sharing the aforementioned random value `lambda`, compute the masked transcript for
    ///   sharing the value `alpha * lambda`.
    UnmaskedTimesMasked(IDkgTranscript, IDkgTranscript),

    /// Generates a new public/private key pair shared among the replicas.
    ///
    /// The resulting transcript is `unmasked`; the public key is immediately
    /// revealed to all parties
    RandomUnmasked,
}

impl Debug for IDkgTranscriptOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => write!(f, "IDkgTranscriptOperation::Random"),
            Self::RandomUnmasked => write!(f, "IDkgTranscriptOperation::RandomUnmasked"),
            Self::ReshareOfMasked(transcript) => write!(
                f,
                "IDkgTranscriptOperation::ReshareOfMasked({:?})",
                transcript.transcript_id
            ),
            Self::ReshareOfUnmasked(transcript) => write!(
                f,
                "IDkgTranscriptOperation::ReshareOfUnmasked({:?})",
                transcript.transcript_id
            ),
            Self::UnmaskedTimesMasked(unmasked_transcript, masked_transcript) => write!(
                f,
                "UnmaskedTimesMasked::ReshareOfMasked({}, {:?})",
                unmasked_transcript.transcript_id, masked_transcript.transcript_id
            ),
        }
    }
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
            .map(|verified_dealing| verified_dealing.dealer_id())
    }

    /// Returns the index of the dealer with the given ID, or `None` if there is no such index.
    pub fn index_for_dealer_id(&self, dealer_id: NodeId) -> Option<NodeIndex> {
        self.verified_dealings
            .iter()
            .find(|(_index, verified_dealing)| verified_dealing.dealer_id() == dealer_id)
            .map(|(index, _signed_dealing)| *index)
    }

    /// Verifies consistency with the given transcript `params`.
    ///
    /// The verification succeeds iff the following conditions hold between the
    /// transcript and the `params`:
    /// * the transcript IDs match
    /// * the receivers match
    /// * the registry versions match
    /// * the algorithm IDs match
    /// * the transcript's type matches the transcript type derived from
    ///   the params' transcript operation
    /// * the transcript has sufficient dealings, i.e., the number of dealings
    ///   in the transcript is at least the param's collection threshold
    /// * the transcript only contains dealings from nodes that are dealers
    ///   according to the params
    /// * the dealer indexes match
    /// * the signers of the transcript's verified dealings are eligible for
    ///   signing, i.e., they are receivers in the params
    pub fn verify_consistency_with_params(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<(), String> {
        if self.transcript_id != params.transcript_id() {
            return Err(format!(
                "mismatching transcript IDs in transcript ({:?}) and params ({:?})",
                self.transcript_id,
                params.transcript_id(),
            ));
        }
        if self.receivers != *params.receivers() {
            return Err(format!(
                "mismatching receivers in transcript ({:?}) and params ({:?})",
                self.receivers,
                params.receivers(),
            ));
        }
        if self.registry_version != params.registry_version() {
            return Err(format!(
                "mismatching registry versions in transcript ({:?}) and params ({:?})",
                self.registry_version,
                params.registry_version(),
            ));
        }
        if self.algorithm_id != params.algorithm_id() {
            return Err(format!(
                "mismatching algorithm IDs in transcript ({:?}) and params ({:?})",
                self.algorithm_id,
                params.algorithm_id(),
            ));
        }
        type Itop = IDkgTranscriptOperation;
        type Itt = IDkgTranscriptType;
        type Imto = IDkgMaskedTranscriptOrigin;
        type Iuto = IDkgUnmaskedTranscriptOrigin;
        let transcript_type_from_params_op = match params.operation_type() {
            Itop::Random => Itt::Masked(Imto::Random),
            Itop::RandomUnmasked => Itt::Unmasked(Iuto::Random),
            Itop::ReshareOfMasked(r) => Itt::Unmasked(Iuto::ReshareMasked(r.transcript_id)),
            Itop::ReshareOfUnmasked(r) => Itt::Unmasked(Iuto::ReshareUnmasked(r.transcript_id)),
            Itop::UnmaskedTimesMasked(l, r) => {
                Itt::Masked(Imto::UnmaskedTimesMasked(l.transcript_id, r.transcript_id))
            }
        };
        if self.transcript_type != transcript_type_from_params_op {
            return Err(format!(
                "transcript's type ({:?}) does not match transcript type derived from param's transcript operation ({:?})",
                self.transcript_type,
                transcript_type_from_params_op,
            ));
        }
        if self.verified_dealings.len() < params.collection_threshold().get() as usize {
            return Err(format!(
                "insufficient number of dealings ({}<{})",
                self.verified_dealings.len(),
                params.collection_threshold().get() as usize,
            ));
        }
        let dealer_index_to_dealer_id: BTreeMap<NodeIndex, NodeId> = self
            .verified_dealings
            .iter()
            .map(|(dealer_index, verified_dealing)| (*dealer_index, verified_dealing.dealer_id()))
            .collect();
        for (dealer_index, dealer_id) in dealer_index_to_dealer_id {
            let dealer_index_in_params = params.dealer_index(dealer_id).ok_or_else(|| {
                format!(
                    "transcript contains dealings from non-dealer with ID {}",
                    dealer_id
                )
            })?;
            if dealer_index != dealer_index_in_params {
                return Err(format!(
                    "mismatching dealer indexes in transcript ({}) and params ({}) for dealer {}",
                    dealer_index, dealer_index_in_params, dealer_id
                ));
            }
        }
        for (dealer_index, signed_dealing) in &self.verified_dealings {
            let signers: BTreeSet<NodeId> = signed_dealing.signers();
            let ineligible_signers: BTreeSet<NodeId> = signers
                .difference(params.receivers.get())
                .copied()
                .collect();
            if !ineligible_signers.is_empty() {
                return Err(format!(
                    "ineligible signers (non-receivers) for dealer index {}: {:?} ",
                    dealer_index, ineligible_signers
                ));
            }
        }
        Ok(())
    }

    /// Return the index of the signer with the given ID, or `None` if there is no such index.
    pub fn index_for_signer_id(&self, signer_id: NodeId) -> Option<NodeIndex> {
        self.receivers.position(signer_id)
    }

    /// Checks if the specified `NodeId` is a receiver of the transcript.
    pub fn has_receiver(&self, receiver_id: NodeId) -> bool {
        self.receivers.contains(receiver_id)
    }

    /// Returns a copy of the raw internal transcript.
    #[inline]
    pub fn transcript_to_bytes(&self) -> Vec<u8> {
        self.internal_transcript_raw.clone()
    }
}

impl Debug for IDkgTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "IDkgTranscript {{ ")?;
        write!(f, "transcript_id: {:?}", self.transcript_id)?;
        write!(f, ", receivers: {:?}", self.receivers)?;
        write!(f, ", registry_version: {:?}", self.registry_version)?;
        write!(
            f,
            ", verified_dealings: {:?}",
            self.verified_dealings.keys()
        )?;
        write!(f, ", transcript_type: {:?}", self.transcript_type)?;
        write!(f, ", algorithm_id: {:?}", self.algorithm_id)?;
        write!(
            f,
            ", internal_transcript_raw: 0x{}",
            hex::encode(&self.internal_transcript_raw)
        )?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl_display_using_debug!(IDkgTranscript);

/// Dealing of an IDkg sharing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct IDkgDealing {
    pub transcript_id: IDkgTranscriptId,
    #[serde(with = "serde_bytes")]
    pub internal_dealing_raw: Vec<u8>,
}

impl IDkgDealing {
    /// Returns a copy of the internal dealing.
    #[inline]
    pub fn dealing_to_bytes(&self) -> Vec<u8> {
        self.internal_dealing_raw.clone()
    }
}

impl Debug for IDkgDealing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "IDkgDealing {{ transcript_id: {}", self.transcript_id)?;
        write!(
            f,
            ", internal_dealing_raw: 0x{}",
            hex::encode(&self.internal_dealing_raw)
        )?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl Display for IDkgDealing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Dealing[transcript_id = {:?}]", self.transcript_id,)
    }
}

impl SignedBytesWithoutDomainSeparator for IDkgDealing {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// The signed dealing sent by dealers
///
/// The iDKG protocol requires `IDkgDealing` to be signed with non-malleable
/// signatures, that is, the signature-part in the `Signed` struct must use
/// a type produced by a non-malleable signature scheme. For `BasicSignature`
/// this is the case, because it is produced by `BasicSigner`, which
/// guarantees non-malleability.
pub type SignedIDkgDealing = Signed<IDkgDealing, BasicSignature<IDkgDealing>>;

impl SignedIDkgDealing {
    pub fn idkg_dealing(&self) -> &IDkgDealing {
        &self.content
    }

    pub fn dealer_id(&self) -> NodeId {
        self.signature.signer
    }
}

impl Display for SignedIDkgDealing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, dealer_id = {:?}",
            self.content, self.signature.signer,
        )
    }
}

impl SignedBytesWithoutDomainSeparator for SignedIDkgDealing {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// The individual signature share in support of a dealing
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct IDkgDealingSupport {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    pub dealing_hash: CryptoHashOf<SignedIDkgDealing>,
    pub sig_share: BasicSignature<SignedIDkgDealing>,
}

impl Display for IDkgDealingSupport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transcript_id = {:?}, dealer_id = {:?}, signer_id = {:?}, dealing_hash = {:?}",
            self.transcript_id, self.dealer_id, self.sig_share.signer, self.dealing_hash
        )
    }
}

/// IDKG Dealing signed from the dealer, along with a batch of basic signatures in support from the receivers.
pub type BatchSignedIDkgDealing = Signed<SignedIDkgDealing, BasicSignatureBatch<SignedIDkgDealing>>;

impl BatchSignedIDkgDealing {
    pub fn idkg_dealing(&self) -> &IDkgDealing {
        &self.content.content
    }

    pub fn dealer_id(&self) -> NodeId {
        self.content.signature.signer
    }

    pub fn signed_idkg_dealing(&self) -> &SignedIDkgDealing {
        &self.content
    }

    pub fn signers(&self) -> BTreeSet<NodeId> {
        self.signature.signatures_map.keys().copied().collect()
    }

    pub fn signers_count(&self) -> usize {
        self.signature.signatures_map.len()
    }
}

/// Collection of [`BatchSignedIDkgDealing`]s.
///
/// It is guaranteed that all dealings in the collection originate from *distinct* dealers.
///
/// Remark: it is essential that the [`BatchSignedIDkgDealing`]s in the collection are immutable
/// to ensure that the value of [`BatchSignedIDkgDealing::dealer_id`] cannot be changed. Otherwise,
/// the guarantee that all dealers are distinct could be broken.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BatchSignedIDkgDealings {
    dealings: BTreeMap<NodeId, BatchSignedIDkgDealing>,
}

impl BatchSignedIDkgDealings {
    pub fn new() -> Self {
        BatchSignedIDkgDealings {
            dealings: Default::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.dealings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dealings.is_empty()
    }

    /// Inserts or update a [`BatchSignedIDkgDealing`] in the collection.
    ///
    /// If the collection did not have any dealing from this dealer (given by [`BatchSignedIDkgDealing::dealer_id`]),
    /// the dealing is inserted and `None` is returned.
    ///
    /// Otherwise, if the collection did contain a dealing from the same dealer, the dealing
    /// is updated and the old value is returned.
    pub fn insert_or_update(
        &mut self,
        dealing: BatchSignedIDkgDealing,
    ) -> Option<BatchSignedIDkgDealing> {
        self.dealings.insert(dealing.dealer_id(), dealing)
    }

    /// Returns an Iterator over the [`NodeId`]s of all dealers contained in the collection.
    pub fn dealer_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.dealings.keys()
    }

    pub fn iter(&self) -> btree_map::Values<'_, NodeId, BatchSignedIDkgDealing> {
        self.dealings.values()
    }
}

impl IntoIterator for BatchSignedIDkgDealings {
    type Item = BatchSignedIDkgDealing;
    type IntoIter = btree_map::IntoValues<NodeId, BatchSignedIDkgDealing>;

    fn into_iter(self) -> Self::IntoIter {
        self.dealings.into_values()
    }
}

impl<'a> IntoIterator for &'a BatchSignedIDkgDealings {
    type Item = &'a BatchSignedIDkgDealing;
    type IntoIter = btree_map::Values<'a, NodeId, BatchSignedIDkgDealing>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<BatchSignedIDkgDealing> for BatchSignedIDkgDealings {
    fn from_iter<T: IntoIterator<Item = BatchSignedIDkgDealing>>(iter: T) -> Self {
        let mut dealings = BatchSignedIDkgDealings::new();
        for dealing in iter {
            dealings.insert_or_update(dealing);
        }
        dealings
    }
}

/// Complaint against an individual IDkg dealing in a transcript.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgComplaint {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    #[serde(with = "serde_bytes")]
    pub internal_complaint_raw: Vec<u8>,
}

impl_display_using_debug!(IDkgComplaint);

impl Debug for IDkgComplaint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "IDkgComplaint {{ transcript_id: {}", self.transcript_id)?;
        write!(f, ", dealer_id: {}", self.dealer_id)?;
        // Not including internal_complaint_raw in the output, since it may potentially leak some
        // information that we do not want included in logs that may stay around for a long time.
        write!(f, "}}")?;
        Ok(())
    }
}

/// Opening created in response to an IDkgComplaint.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct IDkgOpening {
    pub transcript_id: IDkgTranscriptId,
    pub dealer_id: NodeId,
    #[serde(with = "serde_bytes")]
    pub internal_opening_raw: Vec<u8>,
}

impl_display_using_debug!(IDkgOpening);

impl Debug for IDkgOpening {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "IDkgOpening {{ transcript_id: {}", self.transcript_id)?;
        write!(f, ", dealer_id: {}", self.dealer_id)?;
        // Not including internal_opening_raw in the output, since it may potentially leak some
        // information that we do not want included in logs that may stay around for a long time.
        write!(f, "}}")?;
        Ok(())
    }
}

fn number_of_nodes_from_usize(number: usize) -> Result<NumberOfNodes, TryFromIntError> {
    let count = NodeIndex::try_from(number)?;
    Ok(NumberOfNodes::from(count))
}

/// Contextual data needed for the creation of a dealing.
///
/// Returns a byte vector consisting of the concatenation of the following:
/// The transcript ID, serialized as the concatenation of the following byte vectors:
/// - IDkgTranscriptId::SubnetId, as a byte-string (prefixed with its
///   64-bit-big-endian-integer length)
/// - IDkgTranscriptId::id, as a big-endian 64-bit integer
/// - IDkgTranscriptId::source_subnet, as a big-endian 64-bit integer
/// - The registry version, as a big-endian 64-bit integer
/// - The Algorithm ID, as an 8-bit integer value
fn context_data(
    transcript_id: &IDkgTranscriptId,
    registry_version: RegistryVersion,
    algorithm_id: AlgorithmId,
) -> Vec<u8> {
    let mut ret = Vec::with_capacity(
        8 + transcript_id.source_subnet().get().as_slice().len() + 8 + 8 + 8 + 1,
    );

    ret.extend_from_slice(
        &(transcript_id.source_subnet().get().as_slice().len() as u64).to_be_bytes(),
    );
    ret.extend_from_slice(transcript_id.source_subnet().get().as_slice());
    ret.extend_from_slice(&transcript_id.id().to_be_bytes());
    ret.extend_from_slice(&(transcript_id.source_height().get()).to_be_bytes());
    ret.extend_from_slice(&registry_version.get().to_be_bytes());
    ret.push(algorithm_id as u8);

    ret
}

#[test]
fn should_fail_deserializing_invalid_initial_idkg_dealings() {
    use crate::crypto::canister_threshold_sig::IDkgUnmaskedTranscriptOrigin;
    use crate::{PrincipalId, SubnetId};
    use ic_crypto_test_utils_canister_threshold_sigs::set_of_nodes;
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_protobuf::proxy::ProxyDecodeError;
    use ic_protobuf::registry::subnet::v1::InitialIDkgDealings as InitialIDkgDealingsProto;
    use rand::Rng;

    fn random_transcript_id(rng: &mut ReproducibleRng) -> IDkgTranscriptId {
        let id = rng.gen();
        let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
        let height = Height::from(rng.gen::<u64>());

        IDkgTranscriptId::new(subnet, id, height)
    }

    let rng = &mut reproducible_rng();

    let receivers = IDkgReceivers::new(set_of_nodes(&[1])).expect("failed to create IDkgReceivers");
    let dummy_transcript_unmasked = IDkgTranscript {
        transcript_id: random_transcript_id(rng),
        receivers,
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };

    let dummy_transcript_masked = {
        let mut tmp = dummy_transcript_unmasked.clone();
        tmp.transcript_type = IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random);
        tmp
    };

    let invalid_transcript_operations = vec![
        IDkgTranscriptOperation::Random,
        IDkgTranscriptOperation::RandomUnmasked,
        IDkgTranscriptOperation::ReshareOfMasked(dummy_transcript_masked.clone()),
        IDkgTranscriptOperation::UnmaskedTimesMasked(
            dummy_transcript_unmasked,
            dummy_transcript_masked,
        ),
    ];

    for invalid_transcript_operation in invalid_transcript_operations {
        let params = IDkgTranscriptParams {
            transcript_id: random_transcript_id(rng),
            dealers: IDkgDealers::new(set_of_nodes(&[1])).expect("failed to create IDkgDealers"),
            receivers: IDkgReceivers::new(set_of_nodes(&[2]))
                .expect("failed to create IDkgReceivers"),
            registry_version: RegistryVersion::new(0),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            operation_type: invalid_transcript_operation.clone(),
        };
        let initial_dealings = InitialIDkgDealings {
            params,
            dealings: vec![],
        };

        let invalid_serialization = InitialIDkgDealingsProto::from(&initial_dealings);

        assert_matches::assert_matches!(
            InitialIDkgDealings::try_from(&invalid_serialization),
            Err(ProxyDecodeError::Other(s))
            if s == "InvalidTranscriptOperation" || s == "Unspecified transcript operation in IDkgTranscriptParams"
        );
    }
}
