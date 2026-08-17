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
        if finalized_height.get() < stall_height {
            // Freeze the certified height at `frozen_state_height` on this node to simulate a
            // slow checkpoint at the upgrade boundary, so that consensus reaches the hard bound
            // `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` before the upgrade height is certified.
            *inst
                .deps
                .state_manager
                .override_max_state_height
                .write()
                .unwrap() = Some(frozen_state_height);
        } else {
            // Up to the stall height, every block should still carry `certified_height ==
            // frozen_state_height`, because the cap was active while they were created.
            assert_certified_height(&reader, Height::from(stall_height), frozen_state_height);

            // Consensus should get at most a single block past the bound, because the block maker
            // is always one height ahead of the notary. That block should also still carry the
            // frozen certified height.
            // Note that a node may go from below the bound straight to that block: a single step
            // of the driver can validate the notarizations and finalizations of several heights
            // at once.
            assert!(
                finalized_height.get() <= stall_height + 1,
                "finalized height should exceed the bound {} by at most 1, but got {}",
                stall_height,
                finalized_height
            );
            if finalized_height.get() > stall_height {
                assert_certified_height(&reader, finalized_height, frozen_state_height);
            }

            // Now, simulate that checkpointing has finished on this node by releasing the
            // override. Note that this has to happen per node, as soon as that node reaches the
            // bound: nodes reach it in different steps, and a node that keeps its override never
            // creates a CUP share, which would stall the test.
            *inst
                .deps
                .state_manager
                .override_max_state_height
                .write()
                .unwrap() = None;
            is_checkpointing = false;
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

/// Asserts that the finalized block at `height` carries the given `certified_height`.
fn assert_certified_height(
    reader: &PoolReader<'_>,
    height: Height,
    expected_certified_height: Height,
) {
    let certified_height = reader
        .get_finalized_block(height)
        .unwrap()
        .context
        .certified_height;
    assert_eq!(
        certified_height, expected_certified_height,
        "finalized block at height {height} should have certified_height == {expected_certified_height}, but got {certified_height}"
    );
}
