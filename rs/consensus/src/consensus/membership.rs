use crate::consensus::utils::{
    active_high_threshold_transcript, active_low_threshold_transcript, registry_version_at_height,
};
use ic_crypto::prng::{Csprng, RandomnessPurpose};
use ic_interfaces::{consensus_pool::ConsensusPoolCache, registry::RegistryClient};
use ic_types::{
    consensus::{
        get_committee_size, get_faults_tolerated, Committee, HasHeight, RandomBeacon, Rank,
        Threshold,
    },
    registry::RegistryClientError,
    Height, NodeId, SubnetId,
};
use rand::seq::SliceRandom;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MembershipError {
    NodeNotFound(NodeId),
    RegistryClientError(RegistryClientError),
    UnableToRetrieveDkgSummary(Height),
}

/// Allow a node to determine what its roles are for the current round, e.g.
/// what its rank is and what committees it belongs to.
pub struct Membership {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    pub(crate) registry_client: Arc<dyn RegistryClient>,
    pub(crate) subnet_id: SubnetId,
}

impl Membership {
    /// Construct a new MembershipImpl instance.
    pub fn new(
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        registry_client: Arc<dyn RegistryClient>,
        subnet_id: SubnetId,
    ) -> Self {
        Self {
            consensus_cache,
            registry_client,
            subnet_id,
        }
    }

    /// Return the node IDs from the registry.
    fn get_nodes(&self, height: Height) -> Result<Vec<NodeId>, MembershipError> {
        use ic_registry_client::helper::subnet::SubnetRegistry;
        let registry_version = registry_version_at_height(self.consensus_cache.as_ref(), height)
            .ok_or_else(|| MembershipError::UnableToRetrieveDkgSummary(height))?;

        let list = self
            .registry_client
            .get_node_ids_on_subnet(self.subnet_id, registry_version)
            .map_err(MembershipError::RegistryClientError)?;

        Ok(list.unwrap_or_default())
    }

    /// Return a shuffled list of the node IDs at a given height using the given
    /// previous beacon.
    // Here we asserts that the given random beacon is from the previous height.
    // Note, if we'd wait until the random beacon is available for the current
    // height, we'd sequentialize the making of the random beacon and block
    // proposals.  One consequence of this design, is that the randomness
    // derived from the genesis random beacon at height 1 is predictable,
    // because the beacon from the genesis height is preconstructed and known in
    // advance
    fn get_shuffled_nodes(
        &self,
        height: Height,
        previous_beacon: &RandomBeacon,
        purpose: &RandomnessPurpose,
    ) -> Result<Vec<NodeId>, MembershipError> {
        assert_eq!(height, previous_beacon.height().increment());
        let mut node_ids = self.get_nodes(height)?;
        // To achieve a deterministic shuffling, we sort the ids first, to not rely on
        // any ordering by the registry. We assume all node_ids are unique, so
        // `sort_unstable` is effectively the same as `sort` but slightly more
        // efficient.
        node_ids.sort_unstable();
        let mut rng = Csprng::from_random_beacon_and_purpose(&previous_beacon, purpose);
        node_ids.shuffle(&mut rng);
        Ok(node_ids)
    }

    /// Return the the block maker rank of the given node id at the given
    /// height. If the returned rank is None, it means the node id is not a
    /// block maker at this height.
    pub fn get_block_maker_rank(
        &self,
        height: Height,
        previous_beacon: &RandomBeacon,
        node_id: NodeId,
    ) -> Result<Option<Rank>, MembershipError> {
        let shuffled_nodes = self.get_shuffled_nodes(
            height,
            previous_beacon,
            &RandomnessPurpose::BlockmakerRanking,
        )?;
        Membership::get_block_maker_rank_from_shuffled_nodes(&node_id, &shuffled_nodes)
    }

    fn get_block_maker_rank_from_shuffled_nodes(
        node_id: &NodeId,
        shuffled_nodes: &[NodeId],
    ) -> Result<Option<Rank>, MembershipError> {
        let index = match shuffled_nodes.iter().position(|id| id == node_id) {
            Some(index) => index,
            None => return Err(MembershipError::NodeNotFound(*node_id)),
        };

        // We only elect f+1 nodes as block makers, which is the minimum amount that
        // still guarantees at least one honest block maker is elected.
        if index <= get_faults_tolerated(shuffled_nodes.len()) {
            Ok(Some(Rank(index as u64)))
        } else {
            Ok(None)
        }
    }

    /// Return whether the given node is part of the given consensus committee
    /// at the specified height
    pub fn node_belongs_to_threshold_committee(
        &self,
        node_id: NodeId,
        height: Height,
        committee: Committee,
    ) -> Result<bool, MembershipError> {
        match committee {
            Committee::HighThreshold => {
                self.node_belongs_to_high_threshold_committee(node_id, height)
            }
            Committee::LowThreshold => {
                self.node_belongs_to_low_threshold_committee(node_id, height)
            }
            Committee::Notarization => {
                unreachable!("Notarization/Finalization does not use threshold committee")
            }
        }
    }

    /// Return the threshold of the given consensus committee at the specified
    /// height
    pub fn get_committee_threshold(
        &self,
        height: Height,
        committee: Committee,
    ) -> Result<usize, MembershipError> {
        match committee {
            Committee::HighThreshold => self.get_high_threshold_committee_threshold(height),
            Committee::LowThreshold => self.get_low_threshold_committee_threshold(height),
            Committee::Notarization => self.get_notarization_committee_threshold(height),
        }
    }

    /// Return true if the given node ID is part of the notarization committee
    /// at the given height
    pub fn node_belongs_to_notarization_committee(
        &self,
        height: Height,
        previous_beacon: &RandomBeacon,
        node_id: NodeId,
    ) -> Result<bool, MembershipError> {
        let shuffled_nodes = self.get_shuffled_nodes(
            height,
            previous_beacon,
            &RandomnessPurpose::CommitteeSampling,
        )?;
        Ok(match shuffled_nodes.iter().position(|id| *id == node_id) {
            Some(i) => i < get_committee_size(shuffled_nodes.len()),
            None => false,
        })
    }

    /// Return true if the given node ID is in the low threshold committee at
    /// the given height
    fn node_belongs_to_low_threshold_committee(
        &self,
        node_id: NodeId,
        height: Height,
    ) -> Result<bool, MembershipError> {
        match active_low_threshold_transcript(self.consensus_cache.as_ref(), height) {
            Some(transcript) => Ok(transcript.committee.position(node_id).is_some()),
            None => Err(MembershipError::UnableToRetrieveDkgSummary(height)),
        }
    }

    /// Return true if the given node ID is in the high threshold committee at
    /// the given height
    fn node_belongs_to_high_threshold_committee(
        &self,
        node_id: NodeId,
        height: Height,
    ) -> Result<bool, MembershipError> {
        match active_high_threshold_transcript(self.consensus_cache.as_ref(), height) {
            Some(transcript) => Ok(transcript.committee.position(node_id).is_some()),
            None => Err(MembershipError::UnableToRetrieveDkgSummary(height)),
        }
    }

    /// Return the notarization committee threshold.
    fn get_notarization_committee_threshold(
        &self,
        height: Height,
    ) -> Result<Threshold, MembershipError> {
        let number_of_nodes = self.get_nodes(height)?.len();
        Ok(get_notarization_threshold_for_subnet_of_size(
            number_of_nodes,
        ))
    }

    /// Return the low-threshold committee threshold.
    fn get_low_threshold_committee_threshold(
        &self,
        height: Height,
    ) -> Result<Threshold, MembershipError> {
        match active_low_threshold_transcript(self.consensus_cache.as_ref(), height) {
            Some(transcript) => Ok(transcript.threshold.get().get() as usize),
            None => Err(MembershipError::UnableToRetrieveDkgSummary(height)),
        }
    }

    /// Return the high-threshold committee threshold.
    fn get_high_threshold_committee_threshold(
        &self,
        height: Height,
    ) -> Result<Threshold, MembershipError> {
        match active_high_threshold_transcript(self.consensus_cache.as_ref(), height) {
            Some(transcript) => Ok(transcript.threshold.get().get() as usize),
            None => Err(MembershipError::UnableToRetrieveDkgSummary(height)),
        }
    }
}

/// Returns the notary threshold for the given committee size.
pub fn get_notarization_threshold_for_subnet_of_size(subnet_size: usize) -> Threshold {
    let committee_size = get_committee_size(subnet_size);
    committee_size - get_faults_tolerated(committee_size)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_types::consensus::*;

    #[test]
    fn test_sufficient_block_makers_elected() {
        for n in 1..201 {
            let subnet_members = (0..n).map(node_test_id).collect::<Vec<NodeId>>();
            let block_makers: Vec<_> = subnet_members
                .iter()
                .filter(|node| {
                    match Membership::get_block_maker_rank_from_shuffled_nodes(
                        *node,
                        &subnet_members,
                    ) {
                        Ok(Some(_)) => true,
                        _ => false,
                    }
                })
                .collect();
            assert_eq!(
                block_makers.len(),
                get_faults_tolerated(subnet_members.len()) + 1usize
            );
        }
    }

    #[test]
    fn test_notarization_threshold_for_safety_and_liveness() {
        // This test is written assuming that the finalization treshold and
        // the notarization treshold are the same.
        let finalization_uses_notarization_threshold =
            FinalizationContent::committee() == NotarizationContent::committee();
        assert!(finalization_uses_notarization_threshold);

        for n in 1..201 {
            let c = get_committee_size(n);
            let f = get_faults_tolerated(n);
            let t_not = get_notarization_threshold_for_subnet_of_size(n);
            let t_fin = t_not;

            assert!(
                // For safety, we need that if a finalization on height-h block b exists, no other
                // block may be notarized at height h. A finalization requires `t_fin` signatures.
                // `t_fin - f` of those are honest, and we know that they only finality sign if
                // they did not contribute to notarizing a different height-h block. The remaining
                // committee members (`c - (t_fin - f)`) must be smaller than the notarization
                // threshold, which shows that no other height-h block can be notarized.
                c - (t_fin - f) < t_not,
                "The thresholds violate the safety property of consensus. \
                    committee_size = {}, f = {}, t_not = t_fin = {}",
                c,
                f,
                t_not
            );

            assert!(
                c - f >= t_not, /* and c - f >= t_fin because we cannot expect corrupt nodes to
                                 * participate, so we must be able to reach the threshold with
                                 * only the honest nodes. */
                "The thresholds violate the liveness property of consensus. \
                    committee_size = {}, f = {}, t_not = t_fin = {}",
                c,
                f,
                t_not
            );
        }
    }
}
