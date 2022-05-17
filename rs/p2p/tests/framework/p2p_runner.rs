use crate::framework::file_tree_artifact_mgr::ArtifactChunkingTestImpl;
use ic_config::subnet_config::SubnetConfigs;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::IngressHistoryReaderImpl;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces_transport::Transport;
use ic_logger::{debug, info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_subnet_type::SubnetType;
use ic_replica_setup_ic_network::{
    create_networking_stack, init_artifact_pools, P2PStateSyncClient,
};
use ic_test_utilities::{
    consensus::make_catch_up_package_with_empty_transcript,
    crypto::fake_tls_handshake::FakeTlsHandshake,
    crypto::CryptoReturningOk,
    message_routing::FakeMessageRouting,
    metrics::fetch_int_gauge,
    p2p::*,
    port_allocation::allocate_ports,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state_manager::FakeStateManager,
    thread_transport::*,
    types::ids::{node_test_id, subnet_test_id},
    xnet_payload_builder::FakeXNetPayloadBuilder,
};
use ic_types::{consensus::catchup::CUPWithOriginalProtobuf, replica_config::ReplicaConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::Builder;

pub const P2P_TEST_END_BARRIER: &str = "TEST_END";
pub const P2P_TEST_START_BARRIER: &str = "TEST_START";

/// Setup and execute a test for replica with Mock dependencies.
/// Currently these components' mocked versions are used:
/// StateManager
/// XNetPayloadBuilder
/// MessageRouting
///
/// # Parameters
/// - replica_config: configuration for this node.
/// - registry: copy of the registry describing endpoints for the replica
///   network
/// - transport: Thread transport to use [TcpLoopBack|RustChannels]
/// - test_synchronizer: Provides barriers and signals for tests co-ordination
/// - test: closure that will run the actual test.
#[allow(clippy::too_many_arguments)]
fn execute_test(
    node_num: u64,
    replica_config: ReplicaConfig,
    registry: Arc<dyn RegistryClient>,
    transport: Arc<dyn Transport>,
    test_synchronizer: P2PTestSynchronizer,
    log: ReplicaLogger,
    test: Box<impl FnOnce(&mut P2PTestContext) + Send + Sync + 'static>,
    rt_handle: tokio::runtime::Handle,
) {
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|artifact_pool_config| {
        let _rt_guard = rt_handle.enter();
        let metrics_registry = MetricsRegistry::new();
        let state_manager = Arc::new(FakeStateManager::new());
        let node_id = replica_config.node_id;
        let subnet_id = replica_config.subnet_id;
        let transport_config = get_replica_transport_config(&replica_config, Arc::clone(&registry));
        info!(log, "Spawning Replica with config {:?}", transport_config);
        let message_router =
            FakeMessageRouting::with_state_manager(Arc::clone(&state_manager) as Arc<_>);
        let message_router = Arc::new(message_router);
        let fake_crypto = CryptoReturningOk::default();
        let fake_crypto = Arc::new(fake_crypto);
        let xnet_payload_builder = FakeXNetPayloadBuilder::new();
        let xnet_payload_builder = Arc::new(xnet_payload_builder);
        let self_validating_payload_builder = FakeSelfValidatingPayloadBuilder::new();
        let self_validating_payload_builder = Arc::new(self_validating_payload_builder);
        let no_state_sync_client = P2PStateSyncClient::TestClient();
        let ingress_hist_reader = Box::new(IngressHistoryReaderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
        ));
        let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::System);
        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            SubnetType::System,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));

        let artifact_pools = init_artifact_pools(
            subnet_id,
            artifact_pool_config,
            metrics_registry.clone(),
            log.clone(),
            CUPWithOriginalProtobuf::from_cup(make_catch_up_package_with_empty_transcript(
                registry.clone(),
                subnet_id,
            )),
        );

        let (_, p2p_runner) = create_networking_stack(
            metrics_registry.clone(),
            log.clone(),
            rt_handle,
            transport_config,
            Default::default(),
            Default::default(),
            node_id,
            subnet_id,
            Some(transport),
            Arc::new(FakeTlsHandshake::new()),
            Arc::clone(&state_manager) as Arc<_>,
            no_state_sync_client,
            xnet_payload_builder as Arc<_>,
            self_validating_payload_builder as Arc<_>,
            message_router as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            registry.clone(),
            ingress_hist_reader,
            &artifact_pools,
            cycles_account_manager,
            None,
            0,
        );

        let mut p2p_test_context = P2PTestContext::new(
            node_num,
            subnet_id,
            metrics_registry,
            test_synchronizer.clone(),
            p2p_runner,
        );

        std::thread::sleep(Duration::from_millis(400));

        // Call the test
        test_synchronizer.wait_on_barrier(P2P_TEST_START_BARRIER.to_string());
        test(&mut p2p_test_context);
        test_synchronizer.wait_on_barrier(P2P_TEST_END_BARRIER.to_string());
    })
}

/// Helper function for P2P test, runs a replica until consensus certifies a
/// given height
///
/// # Parameters
/// - p2p_test_context        Test context for the replica
/// - till_height             height to reach
pub fn replica_run_till_height(p2p_test_context: &P2PTestContext, till_height: u64) {
    std::println!("Instance id: {}", p2p_test_context.node_id);
    let mut last_finalized_height = 0;
    let mut last_notarized_height = 0;
    let mut last_certified_height = 0;
    std::thread::sleep(Duration::from_millis(800));
    loop {
        let finalized_height = fetch_int_gauge(
            &p2p_test_context.metrics_registry,
            "consensus_pool_validated_finalization_max_height",
        )
        .unwrap_or(last_finalized_height);
        let notarized_height = fetch_int_gauge(
            &p2p_test_context.metrics_registry,
            "consensus_pool_validated_notarization_max_height",
        )
        .unwrap_or(last_notarized_height);
        let certified_height = fetch_int_gauge(
            &p2p_test_context.metrics_registry,
            "certification_last_certified_height",
        )
        .unwrap_or(last_certified_height);
        std::thread::sleep(Duration::from_millis(10));

        if finalized_height > last_finalized_height
            || notarized_height > last_notarized_height
            || certified_height > last_certified_height
        {
            last_finalized_height = finalized_height.max(last_finalized_height);
            last_notarized_height = notarized_height.max(last_notarized_height);
            last_certified_height = certified_height.max(last_certified_height);
            println!(
                " Node {} at notarized height {:?} finalized height {:?} certified height {:?}",
                p2p_test_context.node_id,
                last_notarized_height,
                last_finalized_height,
                last_certified_height
            );
        }
        if last_certified_height >= till_height {
            p2p_test_context.test_synchronizer.set_group_stop();
            break;
        }

        if p2p_test_context.test_synchronizer.is_group_stopped() {
            break;
        }
    }
    p2p_test_context
        .test_synchronizer
        .wait_on_barrier(P2P_TEST_END_BARRIER.to_string());
}

#[allow(clippy::too_many_arguments)]
fn execute_test_chunking_pool(
    node_num: u64,
    replica_config: ReplicaConfig,
    registry: Arc<dyn RegistryClient>,
    transport: Arc<dyn Transport>,
    test_synchronizer: P2PTestSynchronizer,
    log: ReplicaLogger,
    test: impl FnOnce(&mut P2PTestContext) + Send + Sync + 'static,
    rt_handle: tokio::runtime::Handle,
) {
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|artifact_pool_config| {
        let _rt_guard = rt_handle.enter();
        let metrics_registry = MetricsRegistry::new();
        let state_manager = Arc::new(FakeStateManager::new());
        let node_id = replica_config.node_id;
        let subnet_id = replica_config.subnet_id;

        let transport_config = get_replica_transport_config(&replica_config, Arc::clone(&registry));
        debug!(log, "Spawning Replica with config {:?}", transport_config);
        let ingress_hist_reader = Box::new(IngressHistoryReaderImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
        ));

        let message_router =
            FakeMessageRouting::with_state_manager(Arc::clone(&state_manager) as Arc<_>);
        let message_router = Arc::new(message_router);
        let xnet_payload_builder = FakeXNetPayloadBuilder::new();
        let xnet_payload_builder = Arc::new(xnet_payload_builder);
        let self_validating_payload_builder = FakeSelfValidatingPayloadBuilder::new();
        let self_validating_payload_builder = Arc::new(self_validating_payload_builder);
        let fake_crypto = CryptoReturningOk::default();
        let fake_crypto = Arc::new(fake_crypto);
        let node_pool_dir = test_synchronizer.get_test_group_directory();
        let state_sync_client = Arc::new(ArtifactChunkingTestImpl::new(node_pool_dir, node_id));
        let state_sync_client =
            P2PStateSyncClient::TestChunkingPool(state_sync_client.clone(), state_sync_client);
        let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::System);
        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            SubnetType::System,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));

        let artifact_pools = init_artifact_pools(
            subnet_id,
            artifact_pool_config,
            metrics_registry.clone(),
            log.clone(),
            CUPWithOriginalProtobuf::from_cup(make_catch_up_package_with_empty_transcript(
                registry.clone(),
                subnet_id,
            )),
        );

        let (_a, p2p_runner) = create_networking_stack(
            metrics_registry.clone(),
            log.clone(),
            rt_handle,
            transport_config,
            Default::default(),
            Default::default(),
            node_id,
            subnet_id,
            Some(transport),
            Arc::new(FakeTlsHandshake::new()),
            Arc::clone(&state_manager) as Arc<_>,
            state_sync_client,
            xnet_payload_builder,
            self_validating_payload_builder,
            message_router,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            Arc::clone(&fake_crypto) as Arc<_>,
            registry.clone(),
            ingress_hist_reader,
            &artifact_pools,
            cycles_account_manager,
            None,
            0,
        );
        let mut p2p_test_context = P2PTestContext::new(
            node_num,
            subnet_id,
            metrics_registry,
            test_synchronizer.clone(),
            p2p_runner,
        );

        std::thread::sleep(Duration::from_millis(1000));
        println!("\n \n \n Starting p2p (SMS) test \n \n \n ");
        // Call the test
        test_synchronizer.wait_on_barrier(P2P_TEST_START_BARRIER.to_string());
        test(&mut p2p_test_context);
        test_synchronizer.wait_on_barrier(P2P_TEST_END_BARRIER.to_string());
    })
}

/// Runs a test group by spawning replicas as threads
///
/// # Parameters
/// - num_replicas            Number of replicas in the test group
/// - test                    p2p test callback that need to be invoked for each
///   replica
pub fn spawn_replicas_as_threads(
    real_artifact_pool: bool,
    num_replicas: u16,
    test: impl FnOnce(&mut P2PTestContext) + Copy + Send + Sync + 'static,
) {
    // Create a directory inside of `std::env::temp_dir()`
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _rt_guard = rt.enter();
    let temp_dir = Builder::new()
        .prefix("p2p_tests")
        .tempdir()
        .expect("Cannot create a test directory");
    println!("Exec Test in {:?}", temp_dir);

    let allocated_ports =
        allocate_ports("127.0.0.1", num_replicas).expect("Port allocation for test failed");
    let node_port_allocation: Vec<u16> = allocated_ports.iter().map(|np| np.port).collect();
    assert_eq!(num_replicas as usize, node_port_allocation.len());
    let node_port_allocation = Arc::new(node_port_allocation);

    // Setup the test directory once. Child replicas should not do the setup
    let test_synchronizer = P2PTestSynchronizer::new(
        temp_dir.path().to_owned(),
        node_test_id(0),
        num_replicas,
        node_port_allocation.clone(),
    );
    test_synchronizer
        .setup_test_group_directory()
        .expect("Failed To Setup test directory");

    // Build the registry for the test
    let data_provider =
        test_group_set_registry(subnet_test_id(P2P_SUBNET_ID_DEFAULT), node_port_allocation);

    // Keep this around until the end of the test, as it contains a guard that stops
    // async logging on drop.
    let logger = p2p_test_setup_logger();
    let log: ReplicaLogger = logger.root.into();

    // Build the thread network/transport if
    let transport_hub: Hub = Default::default();
    let hub_access: HubAccess = Arc::new(Mutex::new(transport_hub));
    for instance_id in 0..num_replicas {
        let thread_port = ThreadPort::new(
            node_test_id(instance_id as u64),
            hub_access.clone(),
            log.clone(),
            rt.handle().clone(),
        );
        hub_access
            .lock()
            .unwrap()
            .insert(node_test_id(instance_id as u64), thread_port);
    }

    let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
    registry_client.fetch_and_start_polling().unwrap();

    let mut join_handles = Vec::new();
    for i in 0..num_replicas {
        let test = test;
        let test = Box::new(test);
        let replica_log = log.clone();
        let transport_hub = hub_access.lock().unwrap();
        let tp = transport_hub.get(&node_test_id(i as u64)).clone();
        let replica_registry = Arc::clone(&registry_client) as Arc<dyn RegistryClient>;
        let replica_config = ReplicaConfig {
            node_id: node_test_id(i as u64),
            subnet_id: subnet_test_id(P2P_SUBNET_ID_DEFAULT),
        };
        let mut replica_test_synchronizer = test_synchronizer.clone();
        replica_test_synchronizer.node_id = node_test_id(i as u64);
        let rt_handle = rt.handle().clone();
        let jh = std::thread::Builder::new()
            .name(format!("Thread Node {}", i))
            .spawn(move || {
                // Spawn System
                if real_artifact_pool {
                    execute_test(
                        i as u64,
                        replica_config,
                        replica_registry,
                        tp,
                        replica_test_synchronizer,
                        replica_log.clone(),
                        test,
                        rt_handle,
                    );
                } else {
                    execute_test_chunking_pool(
                        i as u64,
                        replica_config,
                        replica_registry,
                        tp,
                        replica_test_synchronizer,
                        replica_log,
                        test,
                        rt_handle,
                    );
                }
            })
            .unwrap();
        join_handles.push(jh);
    }

    for join_handle in join_handles {
        assert!(join_handle.join().is_ok())
    }

    test_synchronizer
        .cleanup_test_group_directory()
        .expect("Failed To Setup test directory");
}
