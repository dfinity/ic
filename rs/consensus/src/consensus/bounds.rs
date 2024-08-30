//! To prevent memory exhaustion attacks, we require that the advertised validated pool
//! be always bounded in size. This module contains checks for invariants that we
//! want to uphold at all times.

use ic_consensus_utils::{
    pool_reader::PoolReader, registry_version_at_height, ACCEPTABLE_NOTARIZATION_CUP_GAP,
};
use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{consensus::get_faults_tolerated, replica_config::ReplicaConfig};

use super::MINIMUM_CHAIN_LENGTH;

/// Summary of when the consensus pool exceeds certain bounds.
#[derive(Debug, PartialEq, Eq)]
pub struct ExcessEvent {
    /// The expected number of artifacts in the pool (i.e. our bound).
    pub expected: ArtifactCounts,
    /// The actual number of artifacts in the pool.
    pub found: ArtifactCounts,
}

/// Number of artifacts in the consensus pool.
#[derive(Debug, PartialEq, Eq)]
pub struct ArtifactCounts {
    block_proposals: usize,
    notarizations: usize,
    finalization: usize,
    random_beacon: usize,
    random_tape: usize,
    notarization_shares: usize,
    finalization_shares: usize,
    random_beacon_shares: usize,
    random_tape_shares: usize,
    cup_shares: usize,
    cups: usize,
    equivocation_proofs: usize,
}

/// Returns the upper limit on the artifact counts a validated pool is allowed
/// to have. NOTE: This bound is tied to the implementation. If we move towards
/// a more aggressive purging strategy, this bound can be lowered.
fn get_maximum_validated_artifacts(node_count: usize, dkg_interval: usize) -> ArtifactCounts {
    let n = node_count;
    let k = dkg_interval + 1;
    let f = get_faults_tolerated(node_count);
    let d = ACCEPTABLE_NOTARIZATION_CUP_GAP as usize;
    let e = MINIMUM_CHAIN_LENGTH as usize;
    /*
     * To derive our bounds, we consider a worst-case scenario in which we have
     * notarizations (or finalizations) for d rounds into the DKG interval i, without
     * having a CUP for it yet. In this case, we keep all artifacts from the (i-1)-th
     * interval, including a minimum chain length of `e` from the (i-2)-th interval.
     *
     *       [B] Ordinary blocks                            notarized/finalized
     *       [S] Summary blocks                                   height
     *                                                              |
     *  ..-[B]-[B]-...-[B]-[S]-[B]-[B]-...-[B]-[B]-[S]-[B]-...-[B]-[B] <- chain tip
     *      |               |                       |               |
     *      +--- minimum  --+---- DKG interval -----+-- d rounds ---+
     *      |  chain length           (k)                           |
     *      |      (e)                                              |
     *      +------------------- l = e + k + d ---------------------+
     *
     * In the above scenario, assuming `d` is equal to the maximum notarization/CUP
     * gap, nodes will refuse to notarize any further blocks. So `l` is the maximum
     * height span we need to consider for placing a bound on the artifact counts.
     */
    let l = k + e + d;
    // The aggregator/validator may produce one CUP in addition to the current CUP.
    // Additionally, if the DKG interval is smaller than the minimum chain length,
    // we can have one CUP for every time a full DKG interval fits into e.
    let cups = 2 + e / k;
    ArtifactCounts {
        // We keep at most l finalized block proposals, as well as f+1
        // non-finalized blocks for every height in the d rounds.
        block_proposals: (l + 1) + (d + 1) * f,
        // The same bounds apply for block proposals and notarizations.
        notarizations: (l + 1) + (d + 1) * f,
        // There can only be one finalization at every height. In the worst
        // case, the chain tip is a finalized block, in which case our upper
        // bound for finalizations is l.
        finalization: l,
        // Only one random beacon per height. Random beacons are created
        // one height ahead of the notarized tip, thus the bound is l+1.
        random_beacon: l + 1,
        // Only one random tape per height. Assuming execution keeps up,
        // the max height for new random tapes is finalized_height+1.
        random_tape: l + 1,
        // We purge notarization shares below finalized height. So we consider
        // at most d+1 heights, for which n replicas may notary-sign f+1
        // different blocks.
        notarization_shares: (d + 1) * (f + 1) * n,
        // We purge finalization shares below finalized height. So we consider
        // at most d heights, for which n replicas may issue a finalization
        // share for a single block.
        finalization_shares: d * n,
        // For every height, every replica may submit a random beacon share.
        // Because we don't purge them below the CUP height, we use l.
        random_beacon_shares: (l + 1) * n,
        // Same justification as for the random_beacon_shares.
        random_tape_shares: (l + 1) * n,
        // One cup share for each CUP, issued by each replica.
        cup_shares: cups * n,
        cups,
        // We purge equivocation proofs below and at the finalized height.
        // This means we can have at most D heights, each with a maximum
        // of f + 1 equivocation proofs (one proof per block maker).
        equivocation_proofs: d * (f + 1),
    }
}

/// Returns excess event when our validated pool exceeds the bounds. Otherwise,
/// or if the registry client doesn't have the relevant records, returns `None`.
pub fn validated_pool_within_bounds(
    pool_reader: &PoolReader,
    registry_client: &dyn RegistryClient,
    replica_config: &ReplicaConfig,
) -> Option<ExcessEvent> {
    let nh = pool_reader.get_notarized_height();
    let validated = pool_reader.pool().validated();

    let registry_version = registry_version_at_height(pool_reader.as_cache(), nh)?;
    let dkg_interval = registry_client
        .get_dkg_interval_length(replica_config.subnet_id, registry_version)
        .ok()??
        .get() as usize;
    let nodes = registry_client
        .get_node_ids_on_subnet(replica_config.subnet_id, registry_version)
        .ok()??;
    let bounds = get_maximum_validated_artifacts(nodes.len(), dkg_interval);

    let actual_counts = ArtifactCounts {
        block_proposals: validated.block_proposal().size(),
        notarizations: validated.notarization().size(),
        finalization: validated.finalization().size(),
        random_beacon: validated.random_beacon().size(),
        random_tape: validated.random_tape().size(),
        notarization_shares: validated.notarization_share().size(),
        finalization_shares: validated.finalization_share().size(),
        random_beacon_shares: validated.random_beacon_share().size(),
        random_tape_shares: validated.random_tape_share().size(),
        cup_shares: validated.catch_up_package_share().size(),
        cups: validated.catch_up_package().size(),
        equivocation_proofs: validated.equivocation_proof().size(),
    };

    (actual_counts.block_proposals > bounds.block_proposals
        || actual_counts.notarizations > bounds.notarizations
        || actual_counts.finalization > bounds.finalization
        || actual_counts.random_beacon > bounds.random_beacon
        || actual_counts.random_tape > bounds.random_tape
        || actual_counts.notarization_shares > bounds.notarization_shares
        || actual_counts.finalization_shares > bounds.finalization_shares
        || actual_counts.random_beacon_shares > bounds.random_beacon_shares
        || actual_counts.random_tape_shares > bounds.random_tape_shares
        || actual_counts.cup_shares > bounds.cup_shares
        || actual_counts.cups > bounds.cups
        || actual_counts.equivocation_proofs > bounds.equivocation_proofs)
        .then_some(ExcessEvent {
            expected: bounds,
            found: actual_counts,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};

    #[test]
    fn test_pool_bounds() {
        // Example for 40-node subnet w/ 499 DKG interval, assuming e=50 and d=70
        let max_counts = ArtifactCounts {
            block_proposals: 1544,
            notarizations: 1544,
            finalization: 620,
            random_beacon: 621,
            random_tape: 621,
            notarization_shares: 39760,
            finalization_shares: 2800,
            random_beacon_shares: 24840,
            random_tape_shares: 24840,
            cup_shares: 80,
            cups: 2,
            equivocation_proofs: 980,
        };
        assert_eq!(get_maximum_validated_artifacts(40, 499), max_counts);

        // Simple check: advance pool without purging, until we have too many
        // finalized blocks.
        ic_test_artifact_pool::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = (0..40).map(node_test_id).collect::<Vec<_>>();
            let record = SubnetRecordBuilder::from(&committee)
                .with_dkg_interval_length(499)
                .build();
            let Dependencies {
                mut pool,
                registry,
                replica_config,
                ..
            } = dependencies_with_subnet_params(pool_config, subnet_test_id(0), vec![(1, record)]);

            // Still within bounds.
            pool.advance_round_normal_operation_n(max_counts.finalization as u64);
            assert_eq!(
                validated_pool_within_bounds(
                    &PoolReader::new(&pool),
                    registry.as_ref(),
                    &replica_config,
                ),
                None
            );

            // One too many finalizations should trigger excess event.
            pool.advance_round_normal_operation();
            assert!(validated_pool_within_bounds(
                &PoolReader::new(&pool),
                registry.as_ref(),
                &replica_config,
            )
            .is_some());
        });
    }
}
