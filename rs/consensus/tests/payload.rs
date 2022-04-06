mod framework;

use crate::framework::ConsensusDriver;
use ic_artifact_pool::{canister_http_pool, consensus_pool, dkg_pool, ecdsa_pool};
use ic_consensus::consensus::dkg_key_manager::DkgKeyManager;
use ic_consensus::{certification::CertifierImpl, consensus::ConsensusImpl, dkg};
use ic_interfaces::time_source::TimeSource;
use ic_interfaces_state_manager::Labeled;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities::{
    consensus::make_genesis,
    crypto::CryptoReturningOk,
    ingress_selector::FakeIngressSelector,
    message_routing::FakeMessageRouting,
    registry::{setup_registry, SubnetRecordBuilder},
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state::get_initial_state,
    state_manager::MockStateManager,
    types::ids::{node_test_id, subnet_test_id},
    types::messages::SignedIngressBuilder,
    xnet_payload_builder::FakeXNetPayloadBuilder,
    FastForwardTimeSource,
};
use ic_types::{
    crypto::CryptoHash, malicious_flags::MaliciousFlags, replica_config::ReplicaConfig,
    CryptoHashOfState, Height,
};
use std::convert::TryInto;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Test that the batches that Consensus produces contain expected batch
/// numbers and payloads
#[test]
fn consensus_produces_expected_batches() {
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
        let state_manager = Arc::new(state_manager);

        let router = FakeMessageRouting::default();
        *router.next_batch_height.write().unwrap() = Height::from(1); // skip genesis block

        let router = Arc::new(router);
        let subnet_id = subnet_test_id(0);
        let replica_config = ReplicaConfig {
            node_id: node_test_id(0),
            subnet_id,
        };
        let fake_crypto = CryptoReturningOk::default();
        let fake_crypto = Arc::new(fake_crypto);
        let metrics_registry = MetricsRegistry::new();
        let time = FastForwardTimeSource::new();
        let dkg_pool = Arc::new(RwLock::new(dkg_pool::DkgPoolImpl::new(
            metrics_registry.clone(),
        )));
        let ecdsa_pool = Arc::new(RwLock::new(ecdsa_pool::EcdsaPoolImpl::new(
            pool_config.clone(),
            no_op_logger(),
            metrics_registry.clone(),
        )));
        let canister_http_pool = Arc::new(RwLock::new(
            canister_http_pool::CanisterHttpPoolImpl::new(metrics_registry.clone()),
        ));

        let registry_client = setup_registry(
            replica_config.subnet_id,
            vec![(1, SubnetRecordBuilder::from(&[node_test_id(0)]).build())],
        );
        let summary = ic_consensus::dkg::make_genesis_summary(
            &*registry_client,
            replica_config.subnet_id,
            None,
        );
        let consensus_pool = Arc::new(RwLock::new(
            consensus_pool::ConsensusPoolImpl::new_from_cup_without_bytes(
                subnet_id,
                make_genesis(summary),
                pool_config.clone(),
                ic_metrics::MetricsRegistry::new(),
                no_op_logger(),
            ),
        ));
        let consensus_cache = consensus_pool.read().unwrap().get_cache();
        let membership = ic_consensus::consensus::Membership::new(
            consensus_cache.clone(),
            registry_client.clone(),
            replica_config.subnet_id,
        );
        let membership = Arc::new(membership);
        let dkg_key_manager = Arc::new(Mutex::new(DkgKeyManager::new(
            metrics_registry.clone(),
            Arc::clone(&fake_crypto) as Arc<_>,
            no_op_logger(),
        )));

        let consensus = ConsensusImpl::new(
            replica_config.clone(),
            Default::default(),
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&membership) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&ingress_selector) as Arc<_>,
            Arc::clone(&xnet_payload_builder) as Arc<_>,
            Arc::clone(&self_validating_payload_builder) as Arc<_>,
            Arc::clone(&dkg_pool) as Arc<_>,
            Arc::clone(&ecdsa_pool) as Arc<_>,
            Arc::clone(&canister_http_pool) as Arc<_>,
            dkg_key_manager.clone(),
            Arc::clone(&router) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&time) as Arc<_>,
            Duration::from_secs(0),
            MaliciousFlags::default(),
            metrics_registry.clone(),
            no_op_logger(),
            None,
        );
        let dkg = dkg::DkgImpl::new(
            replica_config.node_id,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&consensus_cache),
            dkg_key_manager,
            metrics_registry.clone(),
            no_op_logger(),
        );
        let certifier = CertifierImpl::new(
            replica_config,
            Arc::clone(&membership) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&state_manager) as Arc<_>,
            metrics_registry.clone(),
            no_op_logger(),
        );

        let driver = ConsensusDriver::new(
            pool_config,
            consensus,
            dkg,
            Box::new(certifier),
            consensus_pool,
            dkg_pool,
            no_op_logger(),
            metrics_registry,
        );
        driver.step(time.as_ref()); // this stops before notary timeout expires after making 1st block
        time.set_time(time.get_relative_time() + Duration::from_millis(2000))
            .unwrap();
        driver.step(time.as_ref()); // this stops before notary timeout expires after making 2nd block
        time.set_time(time.get_relative_time() + Duration::from_millis(2000))
            .unwrap();
        driver.step(time.as_ref()); // this stops before notary timeout expires after making 3rd block
        let batches = router.batches.read().unwrap().clone();
        *router.batches.write().unwrap() = Vec::new();
        assert_eq!(batches.len(), 2);
        assert_ne!(batches[0].batch_number, batches[1].batch_number);
        let mut msgs: Vec<_> = batches[0].payload.ingress.clone().try_into().unwrap();
        assert_eq!(msgs.pop(), Some(ingress0));
        let mut msgs: Vec<_> = batches[1].payload.ingress.clone().try_into().unwrap();
        assert_eq!(msgs.pop(), Some(ingress1));
    })
}
