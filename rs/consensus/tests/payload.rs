#[cfg(test)]
mod framework;

use crate::framework::ConsensusDriver;
use ic_artifact_pool::{consensus_pool, dkg_pool, idkg_pool};
use ic_consensus::consensus::dkg_key_manager::DkgKeyManager;
use ic_consensus::{certification::CertifierImpl, dkg, idkg};
use ic_consensus_utils::{membership::Membership, pool_reader::PoolReader};
use ic_https_outcalls_consensus::test_utils::FakeCanisterHttpPayloadBuilder;
use ic_interfaces_state_manager::Labeled;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities::{
    crypto::CryptoReturningOk, ingress_selector::FakeIngressSelector,
    message_routing::FakeMessageRouting,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    xnet_payload_builder::FakeXNetPayloadBuilder,
};
use ic_test_utilities_consensus::batch::MockBatchPayloadBuilder;
use ic_test_utilities_consensus::{make_genesis, IDkgStatsNoOp};
use ic_test_utilities_registry::{setup_registry, SubnetRecordBuilder};
use ic_test_utilities_state::get_initial_state;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    crypto::CryptoHash, malicious_flags::MaliciousFlags, replica_config::ReplicaConfig,
    CryptoHashOfState, Height,
};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::watch;

/// Test that the batches that Consensus produces contain expected batch
/// numbers and payloads
#[test]
fn consensus_produces_expected_batches() {
    const DKG_INTERVAL_LENGTH: u64 = 4;
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let ingress0 = SignedIngressBuilder::new().nonce(0).build();
        let ingress1 = SignedIngressBuilder::new().nonce(1).build();
        let ingress_selector = FakeIngressSelector::new();
        ingress_selector.enqueue(vec![ingress0.clone()]);
        ingress_selector.enqueue(vec![ingress1.clone()]);
        let ingress_selector = Arc::new(ingress_selector);

        let xnet_payload_builder = FakeXNetPayloadBuilder::new();
        let xnet_payload_builder = Arc::new(xnet_payload_builder);

        let self_validating_payload_builder = FakeSelfValidatingPayloadBuilder::new();
        let self_validating_payload_builder = Arc::new(self_validating_payload_builder);

        let canister_http_payload_builder = FakeCanisterHttpPayloadBuilder::new();
        let canister_http_payload_builder = Arc::new(canister_http_payload_builder);

        let query_stats_payload_builder = MockBatchPayloadBuilder::new().expect_noop();
        let query_stats_payload_builder = Arc::new(query_stats_payload_builder);

        let mut state_manager = MockStateManager::new();
        state_manager.expect_remove_states_below().return_const(());
        state_manager
            .expect_list_state_hashes_to_certify()
            .return_const(vec![]);
        state_manager
            .expect_latest_certified_height()
            .return_const(Height::new(0));
        state_manager
            .expect_latest_state_height()
            .return_const(Height::from(0));
        state_manager
            .expect_get_state_hash_at()
            .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![]))));
        state_manager
            .expect_get_state_at()
            .return_const(Ok(Labeled::new(
                Height::new(0),
                Arc::new(get_initial_state(0, 0)),
            )));
        state_manager
            .expect_get_certified_state_snapshot()
            .returning(|| None);
        let state_manager = Arc::new(state_manager);

        let router = FakeMessageRouting::default();
        *router.next_batch_height.write().unwrap() = Height::from(1); // skip genesis block

        let router = Arc::new(router);
        let node_id = node_test_id(0);
        let subnet_id = subnet_test_id(0);
        let replica_config = ReplicaConfig { node_id, subnet_id };
        let fake_crypto = CryptoReturningOk::default();
        let fake_crypto = Arc::new(fake_crypto);
        let metrics_registry = MetricsRegistry::new();
        let time_source = FastForwardTimeSource::new();
        let dkg_pool = Arc::new(RwLock::new(dkg_pool::DkgPoolImpl::new(
            metrics_registry.clone(),
            no_op_logger(),
        )));
        let idkg_pool = Arc::new(RwLock::new(idkg_pool::IDkgPoolImpl::new(
            pool_config.clone(),
            no_op_logger(),
            metrics_registry.clone(),
            Box::new(IDkgStatsNoOp {}),
        )));

        let registry_client = setup_registry(
            replica_config.subnet_id,
            vec![(
                1,
                SubnetRecordBuilder::from(&[node_test_id(0)])
                    .with_dkg_interval_length(DKG_INTERVAL_LENGTH)
                    .build(),
            )],
        );
        let summary = dkg::make_genesis_summary(&*registry_client, replica_config.subnet_id, None);
        let consensus_pool = Arc::new(RwLock::new(consensus_pool::ConsensusPoolImpl::new(
            node_id,
            subnet_id,
            (&make_genesis(summary)).into(),
            pool_config.clone(),
            MetricsRegistry::new(),
            no_op_logger(),
            time_source.clone(),
        )));
        let consensus_cache = consensus_pool.read().unwrap().get_cache();
        let membership = Membership::new(
            consensus_cache.clone(),
            registry_client.clone(),
            replica_config.subnet_id,
        );
        let membership = Arc::new(membership);
        let dkg_key_manager = Arc::new(Mutex::new(DkgKeyManager::new(
            metrics_registry.clone(),
            Arc::clone(&fake_crypto) as Arc<_>,
            no_op_logger(),
            &PoolReader::new(&*consensus_pool.read().unwrap()),
        )));

        let (dummy_watcher, _) = watch::channel(Height::from(0));

        let consensus = ic_consensus::consensus::ConsensusImpl::new(
            replica_config.clone(),
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&membership) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&ingress_selector) as Arc<_>,
            Arc::clone(&xnet_payload_builder) as Arc<_>,
            Arc::clone(&self_validating_payload_builder) as Arc<_>,
            Arc::clone(&canister_http_payload_builder) as Arc<_>,
            query_stats_payload_builder,
            Arc::clone(&dkg_pool) as Arc<_>,
            Arc::clone(&idkg_pool) as Arc<_>,
            dkg_key_manager.clone(),
            Arc::clone(&router) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&time_source) as Arc<_>,
            0,
            MaliciousFlags::default(),
            metrics_registry.clone(),
            no_op_logger(),
        );
        let consensus_bouncer = ic_consensus::consensus::ConsensusBouncer::new(router.clone());
        let dkg = dkg::DkgImpl::new(
            replica_config.node_id,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&consensus_cache),
            dkg_key_manager,
            metrics_registry.clone(),
            no_op_logger(),
        );
        let idkg = idkg::IDkgImpl::new(
            replica_config.node_id,
            consensus_pool.read().unwrap().get_block_cache(),
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            metrics_registry.clone(),
            no_op_logger(),
            MaliciousFlags::default(),
        );
        let certifier = CertifierImpl::new(
            replica_config.clone(),
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&consensus_cache),
            metrics_registry.clone(),
            no_op_logger(),
            dummy_watcher,
        );

        let driver = ConsensusDriver::new(
            replica_config.node_id,
            pool_config,
            Box::new(consensus),
            consensus_bouncer,
            dkg,
            Box::new(idkg),
            Box::new(certifier),
            consensus_pool,
            dkg_pool,
            idkg_pool,
            no_op_logger(),
            metrics_registry,
        );
        driver.step(); // this stops before notary timeout expires after making 1st block
        time_source.advance_time(Duration::from_millis(2000));
        driver.step(); // this stops before notary timeout expires after making 2nd block
        time_source.advance_time(Duration::from_millis(2000));
        driver.step(); // this stops before notary timeout expires after making 3rd block

        // Make a few more batches past the summary.
        for _ in 0..=DKG_INTERVAL_LENGTH {
            time_source.advance_time(Duration::from_millis(2000));
            driver.step();
        }
        let batches = router.batches.read().unwrap().clone();
        *router.batches.write().unwrap() = Vec::new();
        // Plus 2 initial driver steps.
        assert_eq!(batches.len(), DKG_INTERVAL_LENGTH as usize + 2);
        assert_ne!(batches[0].batch_number, batches[1].batch_number);
        let first_batch_summary = batches[0].batch_summary.clone().unwrap();
        assert_eq!(
            first_batch_summary.next_checkpoint_height,
            batches[0].batch_number + DKG_INTERVAL_LENGTH.into()
        );
        for b in &batches {
            let batch_summary = b.batch_summary.clone().unwrap();
            // Assert the `next_checkpoint_height` is strictly greater than the `batch_number`.
            assert!(batch_summary.next_checkpoint_height > b.batch_number);
            assert_eq!(
                batch_summary.current_interval_length,
                DKG_INTERVAL_LENGTH.into()
            );
            // Assert the `batch_number` plus `current_interval_length` is greater
            // or equal than the `next_checkpoint_height`.
            assert!(
                // The +1 is because the "normal" `current_interval_length` is 499, not 500.
                b.batch_number + batch_summary.current_interval_length + 1.into()
                    >= batch_summary.next_checkpoint_height
            );
        }
        // Assert the summary batch numbers.
        let last_batch = &batches[DKG_INTERVAL_LENGTH as usize - 1];
        assert_eq!(last_batch.batch_number.get(), DKG_INTERVAL_LENGTH);
        let last_batch_summary = last_batch.batch_summary.clone().unwrap();
        assert_eq!(
            last_batch_summary.next_checkpoint_height.get(),
            DKG_INTERVAL_LENGTH + 1
        );
        let summary_batch = &batches[DKG_INTERVAL_LENGTH as usize];
        assert_eq!(summary_batch.batch_number.get(), DKG_INTERVAL_LENGTH + 1);
        let summary_batch_summary = summary_batch.batch_summary.clone().unwrap();
        assert_eq!(
            summary_batch_summary.next_checkpoint_height.get(),
            (DKG_INTERVAL_LENGTH + 1) * 2
        );
        assert_eq!(batches[0].batch_summary, batches[1].batch_summary);
        let mut msgs: Vec<_> = batches[0].messages.signed_ingress_msgs.clone();
        assert_eq!(msgs.pop(), Some(ingress0));
        let mut msgs: Vec<_> = batches[1].messages.signed_ingress_msgs.clone();
        assert_eq!(msgs.pop(), Some(ingress1));
    })
}
