use crate::{
    active_high_threshold_committee, active_low_threshold_committee, registry_version_at_height,
};
use ic_crypto_prng::{Csprng, RandomnessPurpose};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_types::{
    Height, NodeId, RegistryVersion, SubnetId,
    canister_http::canister_http_threshold,
    consensus::{
        Committee, HasHeight, RandomBeacon, Rank, Threshold, get_committee_size,
        get_faults_tolerated,
    },
    registry::RegistryClientError,
};
use rand::seq::SliceRandom;
use std::sync::Arc;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum MembershipError {
    NodeNotFound(NodeId),
    RegistryClientError(RegistryClientError),
    UnableToRetrieveDkgSummary(Height),
}

/// The canister http committee at a given registry version, together with the
/// BFT parameters derived from its size.
pub struct CanisterHttpCommittee {
    /// The subnet node set acting as the canister http committee.
    pub committee: Vec<NodeId>,
    /// The number of matching shares required to form a response
    /// (`committee.len() - faults_tolerated`).
    pub threshold: Threshold,
    /// The number of faults tolerated for a committee of this size.
    pub faults_tolerated: usize,
}

/// Allow a node to determine what its roles are for the current round, e.g.
/// what its rank is and what committees it belongs to.
pub struct Membership {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    pub registry_client: Arc<dyn RegistryClient>,
    pub subnet_id: SubnetId,
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
    pub fn get_nodes(&self, height: Height) -> Result<Vec<NodeId>, MembershipError> {
        let registry_version = registry_version_at_height(self.consensus_cache.as_ref(), height)
            .ok_or(MembershipError::UnableToRetrieveDkgSummary(height))?;
        self.get_nodes_at_version(registry_version)
    }

    /// Return the node IDs on the subnet at the given registry version.
    pub fn get_nodes_at_version(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<Vec<NodeId>, MembershipError> {
        use ic_registry_client_helpers::subnet::SubnetRegistry;
        let list = self
            .registry_client
            .get_node_ids_on_subnet(self.subnet_id, registry_version)
            .map_err(MembershipError::RegistryClientError)?;

        Ok(list.unwrap_or_default())
    }

    /// Return a shuffled list of the node IDs at a given height using the given
    /// previous beacon.
    // Here we assert that the given random beacon is from the previous height.
    // Note, if we'd wait until the random beacon is available for the current
    // height, we'd sequentialize the making of the random beacon and block
    // proposals. One consequence of this design, is that the randomness
    // derived from the genesis random beacon at height 1 is predictable,
    // because the beacon from the genesis height is preconstructed and known in
    // advance
    pub fn get_shuffled_nodes(
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
        let mut rng = Csprng::from_random_beacon_and_purpose(previous_beacon, purpose);
        node_ids.shuffle(&mut rng);
        Ok(node_ids)
    }

    /// Return the block maker rank of the given node id at the given
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

    /// Get the committee to be used for canister http at the given registry
    /// version, along with the [`threshold`](CanisterHttpCommittee::threshold)
    /// and [`faults_tolerated`](CanisterHttpCommittee::faults_tolerated)
    /// derived from its size.
    pub fn get_canister_http_committee(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<CanisterHttpCommittee, MembershipError> {
        // IMPORTANT: if this ever becomes something else, we should make sure that:
        // 1. Shares from non committee nodes are not included in the payload
        //    this should be enforced already by the pool validator, though it might
        //    make sense for the payload builder to check too.
        // 2. Non replicated request should only be sent to committee nodes.
        let committee = self.get_nodes_at_version(registry_version)?;
        let faults_tolerated = get_faults_tolerated(committee.len());
        let threshold = canister_http_threshold(committee.len());
        Ok(CanisterHttpCommittee {
            committee,
            threshold,
            faults_tolerated,
        })
    }

    /// Return true if the given node ID is part of the canister http committee
    /// at the given registry version.
    pub fn node_belongs_to_canister_http_committee(
        &self,
        registry_version: RegistryVersion,
        node_id: &NodeId,
    ) -> Result<bool, MembershipError> {
        Ok(self
            .get_canister_http_committee(registry_version)?
            .committee
            .contains(node_id))
    }

    /// Return true if the given node ID is in the low threshold committee at
    /// the given height
    fn node_belongs_to_low_threshold_committee(
        &self,
        node_id: NodeId,
        height: Height,
    ) -> Result<bool, MembershipError> {
        match active_low_threshold_committee(self.consensus_cache.as_ref(), height) {
            Some((_, committee)) => Ok(committee.position(node_id).is_some()),
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
        match active_high_threshold_committee(self.consensus_cache.as_ref(), height) {
            Some((_, committee)) => Ok(committee.position(node_id).is_some()),
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
        match active_low_threshold_committee(self.consensus_cache.as_ref(), height) {
            Some((threshold, _)) => Ok(threshold),
            None => Err(MembershipError::UnableToRetrieveDkgSummary(height)),
        }
    }

    /// Return the high-threshold committee threshold.
    fn get_high_threshold_committee_threshold(
        &self,
        height: Height,
    ) -> Result<Threshold, MembershipError> {
        match active_high_threshold_committee(self.consensus_cache.as_ref(), height) {
            Some((threshold, _)) => Ok(threshold),
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
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        ReplicaVersion,
        consensus::*,
        crypto::{
            CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        },
        signature::ThresholdSignature,
    };

    #[test]
    fn test_sufficient_block_makers_elected() {
        for n in 1..201 {
            let subnet_members = (0..n).map(node_test_id).collect::<Vec<NodeId>>();

            assert_eq!(
                subnet_members
                    .iter()
                    .filter(|node| {
                        matches!(
                            Membership::get_block_maker_rank_from_shuffled_nodes(
                                node,
                                &subnet_members,
                            ),
                            Ok(Some(_))
                        )
                    })
                    .count(),
                get_faults_tolerated(subnet_members.len()) + 1_usize
            );
        }
    }

    #[test]
    fn test_notarization_threshold_for_safety_and_liveness() {
        // This test is written assuming that the finalization threshold and
        // the notarization threshold are the same.
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
                    committee_size = {c}, f = {f}, t_not = t_fin = {t_not}"
            );

            assert!(
                c - f >= t_not, /* and c - f >= t_fin because we cannot expect corrupt nodes to
                                 * participate, so we must be able to reach the threshold with
                                 * only the honest nodes. */
                "The thresholds violate the liveness property of consensus. \
                    committee_size = {c}, f = {f}, t_not = t_fin = {t_not}"
            );
        }
    }

    /// Pins the output of `get_shuffled_nodes`, which ranks the block makers and
    /// samples the notarization committee. All replicas of a subnet must compute
    /// the same order, so a change in this output (for example from a new
    /// `rand` version) changes the consensus protocol.
    #[test]
    fn get_shuffled_nodes_is_stable() {
        // (subnet size, purpose, indices `i` of the shuffled nodes `node_test_id(i)`)
        let cases: [(u64, RandomnessPurpose, &[u64]); 4] = [
            (
                13,
                RandomnessPurpose::BlockmakerRanking,
                &[7, 1, 5, 2, 4, 12, 11, 6, 8, 9, 0, 3, 10],
            ),
            (
                13,
                RandomnessPurpose::CommitteeSampling,
                &[5, 11, 10, 4, 12, 8, 3, 7, 0, 6, 9, 1, 2],
            ),
            (
                40,
                RandomnessPurpose::BlockmakerRanking,
                &[
                    28, 19, 9, 4, 36, 15, 8, 24, 30, 20, 33, 17, 26, 18, 22, 29, 21, 5, 16, 12, 14,
                    34, 7, 38, 1, 13, 27, 25, 0, 23, 37, 35, 32, 39, 10, 2, 3, 11, 6, 31,
                ],
            ),
            (
                40,
                RandomnessPurpose::CommitteeSampling,
                &[
                    18, 8, 13, 24, 17, 15, 35, 14, 36, 12, 1, 28, 4, 34, 9, 32, 29, 22, 16, 10, 6,
                    2, 5, 30, 3, 7, 11, 27, 25, 31, 19, 26, 20, 37, 21, 38, 39, 23, 0, 33,
                ],
            ),
        ];

        for (subnet_size, purpose, expected_order) in cases {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let Dependencies { membership, .. } =
                    DependenciesBuilder::new(pool_config, subnet_size).build();

                let shuffled_nodes = membership
                    .get_shuffled_nodes(Height::new(1), &fixed_random_beacon(), &purpose)
                    .unwrap();

                assert_eq!(
                    shuffled_nodes,
                    expected_order
                        .iter()
                        .copied()
                        .map(node_test_id)
                        .collect::<Vec<_>>(),
                    "subnet size {subnet_size}, purpose {purpose:?}"
                );
            });
        }
    }

    /// A random beacon at height 0 built from fixed values, so that the
    /// randomness derived from it does not depend on how the test consensus
    /// pool creates its genesis beacon.
    fn fixed_random_beacon() -> RandomBeacon {
        Signed {
            content: RandomBeaconContent::new(
                Height::new(0),
                CryptoHashOf::new(CryptoHash(vec![0; 32])),
                ReplicaVersion::try_from("0.9.0").unwrap(),
            ),
            signature: ThresholdSignature {
                signer: NiDkgId {
                    start_block_height: Height::new(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::LowThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                },
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![0; 48])),
            },
        }
    }
}
