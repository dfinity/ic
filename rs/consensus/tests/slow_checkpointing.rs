//! This test lives in its own target because it drives consensus over
//! `2 * (DKG_INTERVAL_LENGTH + 1) + ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` heights, which
//! takes an order of magnitude longer than every other test in `tests/integration.rs` combined.
//! Sharing a target (and therefore a timeout) with them made that target time out under CI load.
#[cfg(test)]
mod framework;

use crate::framework::{ConsensusInstance, ConsensusRunnerConfig, TestRunner};
use ic_consensus::consensus::ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::Height;
use std::cmp::Ordering;

/// Regression test for the incident that stalled subnet `3hhby` on 2026-05-22, fixed in
/// https://github.com/dfinity/ic/pull/10347.
/// Tests that if checkpointing is slow at an upgrade boundary, i.e. consensus reaches hard bound
/// `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` before the upgrade height is certified, then
/// consensus still creates a CUP.
/// This used not to be the case because CUP shares were only created when the finalized tip's
/// certified height reached the upgrade height, which would never happen because consensus had
/// reached the hard bound.
/// This was fixed by ignoring this condition when the subnet is halting.
///
/// Steps of the test:
/// 1. Certified height is frozen at the upgrade height minus 1 (simulating a slow checkpoint).
/// 2. Consensus advances with empty blocks until the bound
///    `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` is reached, then stops creating more blocks.
/// 3. The certified-height override is released; consensus resumes and a CUP should be created at
///    the upgrade height, even though there exists no finalized block whose certified height
///    reached the upgrade height.
#[test]
fn slow_checkpointing_at_upgrade_boundary() {
    const DKG_INTERVAL_LENGTH: u64 = 74; // On purpose larger than `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP`
    // We need to execute one first interval to trigger the upgrade at the end of the second.
    let upgrade_height = Height::from(2 * (DKG_INTERVAL_LENGTH + 1));

    let config = ConsensusRunnerConfig {
        num_nodes: 4,
        dkg_interval_length: DKG_INTERVAL_LENGTH,
        ..Default::default()
    };

    // Make the subnet upgrade at `upgrade_height`
    let additional_registry_mutations =
        |data_provider: &ProtoRegistryDataProvider, registry_client: &FakeRegistryClient| {
            let latest_version = data_provider.latest_version();
            let subnet_record = registry_client
                .get_subnet_record(subnet_test_id(0), latest_version)
                .unwrap()
                .unwrap();
            data_provider
                .add(
                    &ic_registry_keys::make_subnet_record_key(subnet_test_id(0)),
                    latest_version + 1.into(),
                    Some(SubnetRecord {
                        replica_version_id: "upgrade_version".to_string(),
                        ..subnet_record
                    }),
                )
                .unwrap();
            registry_client.reload();
        };

    let frozen_state_height = upgrade_height - 1.into();
    let mut is_checkpointing = true;
    let stop = move |inst: &ConsensusInstance<'_>| {
        let pool = inst.driver.consensus_pool.read().unwrap();
        let reader = PoolReader::new(&*pool);
        let finalized_height = reader.get_finalized_height();

        // As long as we are checkpointing, we should not have a CUP at the upgrade height yet.
        if is_checkpointing {
            let cup_height = reader.get_catch_up_height();
            assert_ne!(
                cup_height, upgrade_height,
                "Should not have created a CUP at the upgrade height {} before finishing checkpointing",
                upgrade_height,
            );
        }

        let stall_height = frozen_state_height.get() + ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP;
        match Ord::cmp(&finalized_height.get(), &stall_height) {
            Ordering::Less => {
                // Freeze the certified height at `frozen_state_height` on all nodes to simulate a
                // slow checkpoint at the upgrade boundary, so that consensus reaches the hard
                // bound `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` before the upgrade height is
                // certified.
                *inst
                    .deps
                    .state_manager
                    .override_max_state_height
                    .write()
                    .unwrap() = Some(frozen_state_height);
            }
            Ordering::Equal => {
                // Until the stall height, every block should still carry `certified_height ==
                // frozen_state_height` (the cap is still active).
                let finalized_certified_height = reader
                    .get_finalized_block(finalized_height)
                    .unwrap()
                    .context
                    .certified_height;
                assert_eq!(
                    finalized_certified_height, frozen_state_height,
                    "finalized block at height {} should have certified_height == {}, but got {}",
                    finalized_height, frozen_state_height, finalized_certified_height
                );

                // Now, simulate that checkpointing has finished by releasing the override
                *inst
                    .deps
                    .state_manager
                    .override_max_state_height
                    .write()
                    .unwrap() = None;
                is_checkpointing = false;
            }
            Ordering::Greater => {
                // This should happen only after we have released the override. In this case, we
                // should only have created a single block past the upgrade height, and its
                // certified height should still be equal to the frozen height.
                // Note: It is possible not to enter that branch at all if the CUP was created
                // before making a new block.
                assert!(
                    !is_checkpointing,
                    "finalized height should not have exceeded the stall point before finishing checkpointing"
                );
                assert_eq!(
                    finalized_height.get(),
                    frozen_state_height.get() + ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP + 1,
                    "finalized height should only exceed the bound by 1, but got {}",
                    finalized_height
                );
                let finalized_certified_height = reader
                    .get_finalized_block(finalized_height)
                    .unwrap()
                    .context
                    .certified_height;
                assert_eq!(
                    finalized_certified_height, frozen_state_height,
                    "finalized block at height {} should still have certified_height == {}, but got {}",
                    finalized_height, frozen_state_height, finalized_certified_height
                );
            }
        }

        let cup_height = reader.get_catch_up_height();
        // Success condition is to have been able to create a CUP at the upgrade height.
        cup_height == upgrade_height
    };

    // This test doesn't exercise chain keys, and generating their transcripts, dealings and
    // pre-signatures with real crypto would more than double its runtime.
    TestRunner::new(config, true)
        .without_chain_keys()
        .with_stop_predicate(Box::new(stop))
        .with_additional_registry_mutations(Box::new(additional_registry_mutations))
        .run_test();
}
