use ic_btc_adapter_client::{setup_bitcoin_adapter_clients, BitcoinAdapterClients};
use ic_btc_consensus::BitcoinPayloadBuilder;
use ic_config::{artifact_pool::ArtifactPoolConfig, subnet_config::SubnetConfig, Config};
use ic_consensus::certification::VerifierImpl;
use ic_crypto::CryptoComponent;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::ExecutionServices;
use ic_https_outcalls_adapter_client::setup_canister_http_client;
use ic_icos_sev::Sev;
use ic_interfaces::artifact_manager::JoinGuard;
use ic_interfaces::execution_environment::QueryHandler;
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_p2p::IngressIngestionService;
use ic_interfaces_registry::{LocalStoreCertifiedTimeReader, RegistryClient};
use ic_logger::{info, ReplicaLogger};
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replica_setup_ic_network::{
    create_networking_stack, init_artifact_pools, P2PStateSyncClient,
};
use ic_replicated_state::ReplicatedState;
use ic_state_manager::{state_sync::StateSync, StateManagerImpl};
use ic_types::{consensus::CatchUpPackage, NodeId, SubnetId};
use ic_xnet_endpoint::{XNetEndpoint, XNetEndpointConfig};
use ic_xnet_payload_builder::XNetPayloadBuilderImpl;
use std::sync::Arc;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn construct_ic_stack(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: tokio::runtime::Handle,
    rt_handle_http: tokio::runtime::Handle,
    rt_handle_xnet: tokio::runtime::Handle,
    config: Config,
    subnet_config: SubnetConfig,
    node_id: NodeId,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    root_subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient + Send + Sync>,
    crypto: Arc<CryptoComponent>,
    catch_up_package: Option<CatchUpPackage>,
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
) -> std::io::Result<(
    // TODO: remove this return value since it is used only in tests
    Arc<StateManagerImpl>,
    // TODO: remove this return value since it is used only in tests
    Arc<dyn QueryHandler<State = ReplicatedState>>,
    Box<dyn JoinGuard>,
    // TODO: remove this return value since it is used only in tests
    IngressIngestionService,
    XNetEndpoint,
)> {
    // ---------- ARTIFACT POOLS DEPS FOLLOW ----------
    // Determine the correct catch-up package.
    let catch_up_package = {
        use ic_types::consensus::HasHeight;
        let make_registry_cup = || {
            ic_consensus::dkg::make_registry_cup(&*registry, subnet_id, None)
                .expect("Couldn't create a registry CUP")
        };
        match catch_up_package {
            // The replica was started on a CUP persisted by the orchestrator.
            Some(cup_from_orc) => {
                // The CUP passed by the orchestrator can be signed or unsigned. If it's signed, it
                // was created and signed by the subnet. An unsigned CUP was created by the orchestrator
                // from the registry CUP contents and can only happen during a subnet recovery or subnet genesis.
                let signed = !cup_from_orc.signature.signature.clone().get().0.is_empty();
                info!(
                    log,
                    "Using the {} CUP with height {}",
                    if signed { "signed" } else { "unsigned" },
                    cup_from_orc.height()
                );
                cup_from_orc
            }
            // This case is only possible if the replica is started without an orchestrator which
            // is currently only possible in the local development mode with `dfx`.
            None => {
                let registry_cup = CatchUpPackage::try_from(&make_registry_cup())
                    .expect("deserializing CUP failed");
                info!(
                    log,
                    "Using the CUP with height {} generated from the registry",
                    registry_cup.height()
                );
                registry_cup
            }
        }
    };
    let artifact_pool_config = ArtifactPoolConfig::from(config.artifact_pool.clone());
    let artifact_pools = init_artifact_pools(
        subnet_id,
        artifact_pool_config,
        metrics_registry.clone(),
        log.clone(),
        catch_up_package,
    );

    // ---------- REPLICATED STATE DEPS FOLLOW ----------
    let consensus_pool_cache = artifact_pools.consensus_pool.read().unwrap().get_cache();
    let verifier = Arc::new(VerifierImpl::new(crypto.clone()));
    let state_manager = Arc::new(StateManagerImpl::new(
        verifier,
        subnet_id,
        subnet_type,
        log.clone(),
        metrics_registry,
        &config.state_manager,
        // In order for the state manager to start, it needs to know the height of the last
        // CUP and/or certification. This information part of the persisted consensus pool.
        // Hence the need of the dependency on consensus here.
        Some(consensus_pool_cache.starting_height()),
        config.malicious_behaviour.malicious_flags.clone(),
    ));
    // ---------- EXECUTION DEPS FOLLOW ----------
    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        subnet_type,
        subnet_id,
        subnet_config.cycles_account_manager_config,
    ));
    let execution_services = ExecutionServices::setup_execution(
        log.clone(),
        metrics_registry,
        subnet_id,
        subnet_type,
        subnet_config.scheduler_config,
        config.hypervisor.clone(),
        cycles_account_manager.clone(),
        state_manager.clone(),
        state_manager.get_fd_factory(),
    );
    // ---------- MESSAGE ROUTING DEPS FOLLOW ----------
    let certified_stream_store: Arc<dyn CertifiedStreamStore> =
        Arc::clone(&state_manager) as Arc<_>;
    let message_router = if config
        .malicious_behaviour
        .malicious_flags
        .maliciously_disable_execution
    {
        MessageRoutingImpl::new_fake(
            subnet_id,
            Arc::clone(&state_manager) as Arc<_>,
            execution_services.ingress_history_writer,
            metrics_registry,
            log.clone(),
        )
    } else {
        MessageRoutingImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&certified_stream_store) as Arc<_>,
            execution_services.ingress_history_writer,
            execution_services.scheduler,
            config.hypervisor,
            Arc::clone(&cycles_account_manager),
            subnet_id,
            metrics_registry,
            log.clone(),
            registry.clone(),
            config.malicious_behaviour.malicious_flags.clone(),
        )
    };
    let message_router = Arc::new(message_router);
    let xnet_config = XNetEndpointConfig::from(Arc::clone(&registry) as Arc<_>, node_id, log);
    let xnet_endpoint = XNetEndpoint::new(
        rt_handle_xnet,
        Arc::clone(&certified_stream_store),
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        xnet_config,
        metrics_registry,
        log.clone(),
    );
    // Use default runtime to spawn xnet client threads.
    let xnet_payload_builder = Arc::new(XNetPayloadBuilderImpl::new(
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&certified_stream_store) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        rt_handle.clone(),
        node_id,
        subnet_id,
        metrics_registry,
        log.clone(),
    ));
    // ---------- BITCOIN INTEGRATION DEPS FOLLOW ----------
    let BitcoinAdapterClients {
        btc_testnet_client,
        btc_mainnet_client,
    } = setup_bitcoin_adapter_clients(
        log.clone(),
        metrics_registry,
        rt_handle.clone(),
        config.adapters_config.clone(),
    );
    let self_validating_payload_builder = Arc::new(BitcoinPayloadBuilder::new(
        state_manager.clone(),
        metrics_registry,
        btc_mainnet_client,
        btc_testnet_client,
        subnet_id,
        registry.clone(),
        log.clone(),
    ));
    // ---------- HTTPS OUTCALLS DEPS FOLLOW ----------
    let canister_http_adapter_client = setup_canister_http_client(
        rt_handle.clone(),
        metrics_registry,
        config.adapters_config,
        execution_services.anonymous_query_handler,
        log.clone(),
        subnet_type,
    );
    // ---------- CONSENSUS AND P2P DEPS FOLLOW ----------
    let state_sync = StateSync::new(state_manager.clone(), log.clone());
    let sev_handshake = Arc::new(Sev::new(node_id, registry.clone()));
    let (ingress_ingestion_service, p2p_runner) = create_networking_stack(
        metrics_registry,
        log.clone(),
        rt_handle,
        config.transport,
        config.consensus,
        config.malicious_behaviour.malicious_flags.clone(),
        node_id,
        subnet_id,
        None,
        Arc::clone(&crypto) as Arc<_>,
        sev_handshake,
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&state_manager) as Arc<_>,
        P2PStateSyncClient::Client(state_sync),
        xnet_payload_builder,
        self_validating_payload_builder,
        message_router,
        // TODO(SCL-213)
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        execution_services.ingress_history_reader,
        artifact_pools,
        cycles_account_manager,
        local_store_time_reader,
        canister_http_adapter_client,
        config.nns_registry_replicator.poll_delay_duration_ms,
    );
    // ---------- PUBLIC ENDPOINT DEPS FOLLOW ----------
    ic_http_endpoints_public::start_server(
        rt_handle_http,
        metrics_registry,
        config.http_handler.clone(),
        execution_services.ingress_filter,
        ingress_ingestion_service.clone(),
        execution_services.async_query_handler,
        Arc::clone(&state_manager) as Arc<_>,
        registry,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        subnet_id,
        root_subnet_id,
        log.clone(),
        consensus_pool_cache,
        subnet_type,
        config.malicious_behaviour.malicious_flags,
    );

    Ok((
        state_manager,
        execution_services.sync_query_handler,
        p2p_runner,
        ingress_ingestion_service,
        xnet_endpoint,
    ))
}
