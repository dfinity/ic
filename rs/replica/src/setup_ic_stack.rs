use crate::setup::get_subnet_type;
use ic_artifact_pool::{
    consensus_pool::ConsensusPoolImpl, ensure_persistent_pool_replica_version_compatibility,
};
use ic_btc_adapter_client::{setup_bitcoin_adapter_clients, BitcoinAdapterClients};
use ic_btc_consensus::BitcoinPayloadBuilder;
use ic_config::{artifact_pool::ArtifactPoolConfig, subnet_config::SubnetConfig, Config};
use ic_consensus::certification::VerifierImpl;
use ic_crypto::CryptoComponent;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::ExecutionServices;
use ic_https_outcalls_adapter_client::setup_canister_http_client;
use ic_interfaces::{
    execution_environment::QueryExecutionService, p2p::artifact_manager::JoinGuard,
    time_source::SysTimeSource,
};
use ic_interfaces_certified_stream_store::CertifiedStreamStore;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{info, ReplicaLogger};
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_pprof::Pprof;
use ic_protobuf::types::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replica_setup_ic_network::setup_consensus_and_p2p;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::{state_sync::StateSync, StateManagerImpl};
use ic_tracing::ReloadHandles;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    consensus::{CatchUpPackage, HasHeight},
    messages::SignedIngress,
    Height, NodeId, PrincipalId, SubnetId,
};
use ic_xnet_endpoint::{XNetEndpoint, XNetEndpointConfig};
use ic_xnet_payload_builder::XNetPayloadBuilderImpl;
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::sync::{
    mpsc::{channel, UnboundedSender},
    watch,
};

/// The buffer size for the channel that [`IngressHistoryWriterImpl`] uses to send
/// the message id and height of messages that complete execution.
const COMPLETED_EXECUTION_MESSAGES_BUFFER_SIZE: usize = 10_000;

/// The subnets that can serve synchronous responses to update calls received
/// on the `/api/v3/.../call`` endpoint.
const WHITELISTED_SUBNETS_FOR_SYNCHRONOUS_CALL_V3: [&str; 1] =
    ["snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae"];

/// Returns true if the subnet is whitelisted to serve synchronous responses to v3
/// update calls.
fn subnet_is_whitelisted_for_synchronous_call_v3(subnet_id: &SubnetId) -> bool {
    WHITELISTED_SUBNETS_FOR_SYNCHRONOUS_CALL_V3
        .iter()
        .any(|s| match PrincipalId::from_str(s) {
            Ok(principal_id) => SubnetId::from(principal_id) == *subnet_id,
            Err(_) => false,
        })
}

/// Create the consensus pool directory (if none exists)
fn create_consensus_pool_dir(config: &Config) {
    std::fs::create_dir_all(&config.artifact_pool.consensus_pool_path).unwrap_or_else(|err| {
        panic!(
            "Failed to create consensus pool directory {}: {}",
            config.artifact_pool.consensus_pool_path.display(),
            err
        )
    });
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn construct_ic_stack(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle_main: &tokio::runtime::Handle,
    rt_handle_p2p: &tokio::runtime::Handle,
    rt_handle_http: &tokio::runtime::Handle,
    rt_handle_xnet: &tokio::runtime::Handle,
    rt_handle_xnet_payload: &tokio::runtime::Handle,
    config: Config,
    node_id: NodeId,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient + Send + Sync>,
    crypto: Arc<CryptoComponent>,
    catch_up_package: Option<pb::CatchUpPackage>,
    tracing_handle: ReloadHandles,
) -> std::io::Result<(
    // TODO: remove next three return values since they are used only in tests
    Arc<dyn StateReader<State = ReplicatedState>>,
    QueryExecutionService,
    UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    Vec<Box<dyn JoinGuard>>,
    XNetEndpoint,
)> {
    // Determine the correct catch-up package.
    let (catch_up_package, catch_up_package_proto) = {
        match catch_up_package {
            // The replica was started on a CUP persisted by the orchestrator.
            Some(cup_proto_from_orchestrator) => {
                // We crash if we fail to deserialize the CUP, as there is no reasonable CUP we
                // could fall back to.
                let cup_from_orchestrator = CatchUpPackage::try_from(&cup_proto_from_orchestrator)
                    .expect("deserializing CUP failed");

                // The CUP passed by the orchestrator can be signed or unsigned. If it's signed, it
                // was created and signed by the subnet. An unsigned CUP was created by the
                // orchestrator from the registry CUP contents and can only happen during a subnet
                // recovery or subnet genesis.
                let signed = cup_from_orchestrator.is_signed();
                info!(
                    log,
                    "Using the {} CUP with height {}",
                    if signed { "signed" } else { "unsigned" },
                    cup_from_orchestrator.height()
                );

                (cup_from_orchestrator, cup_proto_from_orchestrator)
            }
            // This case is only possible if the replica is started without an orchestrator which
            // is currently only possible in the local development mode with `dfx`.
            None => {
                let registry_cup = ic_consensus::dkg::make_registry_cup(&*registry, subnet_id, log)
                    .expect("Couldn't create a registry CUP");

                info!(
                    log,
                    "Using the CUP with height {} generated from the registry",
                    registry_cup.height()
                );

                let registry_cup_proto = pb::CatchUpPackage::from(&registry_cup);
                (registry_cup, registry_cup_proto)
            }
        }
    };

    let root_subnet_id = registry
        .get_root_subnet_id(catch_up_package.content.registry_version())
        .expect("cannot read from registry")
        .expect("cannot find root subnet id");
    let subnet_type = get_subnet_type(
        log,
        subnet_id,
        registry.get_latest_version(),
        registry.as_ref(),
    );
    // ---------- THE PERSISTED CONSENSUS ARTIFACT POOL DEPS FOLLOW ----------
    // This is the first object that is required for the creation of the IC stack. Initializing the
    // persistent consensus pool is the only way for retrieving the height of the last CUP and/or
    // certification.
    let artifact_pool_config = ArtifactPoolConfig::from(config.artifact_pool.clone());
    create_consensus_pool_dir(&config);
    ensure_persistent_pool_replica_version_compatibility(
        artifact_pool_config.persistent_pool_db_path(),
    );

    let consensus_pool = Arc::new(RwLock::new(ConsensusPoolImpl::new(
        node_id,
        subnet_id,
        // Note: it's important to pass the original proto which came from the command line (as
        // opposed to, for example, a proto which was first deserialized and then serialized
        // again). Since the proto file could have been produced and signed by nodes running a
        // different replica version, there is a possibility that the format of
        // `pb::CatchUpContent` has changed across the versions, in which case deserializing and
        // serializing the proto could result in a different value of
        // `pb::CatchUpPackage::content` which will make it impossible to validate the signature of
        // the proto.
        catch_up_package_proto,
        artifact_pool_config.clone(),
        metrics_registry.clone(),
        log.clone(),
        // TODO: use a builder pattern and remove the time source implementation from the constructor.
        Arc::new(SysTimeSource::new()),
    )));

    // ---------- REPLICATED STATE DEPS FOLLOW ----------
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
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
    let subnet_config = SubnetConfig::new(subnet_type);
    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        subnet_type,
        subnet_id,
        subnet_config.cycles_account_manager_config,
    ));

    let (completed_execution_messages_tx, finalized_ingress_height_rx) =
        channel(COMPLETED_EXECUTION_MESSAGES_BUFFER_SIZE);
    let max_canister_http_requests_in_flight =
        config.hypervisor.max_canister_http_requests_in_flight;

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
        completed_execution_messages_tx,
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
        rt_handle_xnet.clone(),
        Arc::clone(&certified_stream_store),
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        xnet_config,
        metrics_registry,
        log.clone(),
    );
    // Use XNet runtime to spawn XNet client threads.
    let xnet_payload_builder = Arc::new(XNetPayloadBuilderImpl::new(
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&certified_stream_store) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        rt_handle_xnet_payload.clone(),
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
        rt_handle_main.clone(),
        config.adapters_config.clone(),
    );
    let self_validating_payload_builder = Arc::new(BitcoinPayloadBuilder::new(
        state_manager.clone(),
        metrics_registry,
        btc_mainnet_client,
        btc_testnet_client,
        subnet_id,
        registry.clone(),
        config.bitcoin_payload_builder_config,
        log.clone(),
    ));
    // ---------- HTTPS OUTCALLS DEPS FOLLOW ----------
    let canister_http_adapter_client = setup_canister_http_client(
        rt_handle_main.clone(),
        metrics_registry,
        config.adapters_config,
        execution_services.query_execution_service.clone(),
        max_canister_http_requests_in_flight,
        log.clone(),
        subnet_type,
    );
    // ---------- QUERY STATS DEPS FOLLOW -----------
    let query_stats_payload_builder = execution_services
        .query_stats_payload_builder
        .into_payload_builder(state_manager.clone(), node_id, log.clone());
    // ---------- CONSENSUS AND P2P DEPS FOLLOW ----------
    let state_sync = StateSync::new(state_manager.clone(), log.clone());
    let (max_certified_height_tx, max_certified_height_rx) = watch::channel(Height::from(0));

    let (ingress_throttler, ingress_tx, p2p_runner) = setup_consensus_and_p2p(
        log,
        metrics_registry,
        rt_handle_p2p,
        artifact_pool_config,
        config.transport,
        config.malicious_behaviour.malicious_flags.clone(),
        node_id,
        subnet_id,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&state_manager) as Arc<_>,
        consensus_pool,
        catch_up_package,
        Arc::new(state_sync),
        xnet_payload_builder,
        self_validating_payload_builder,
        query_stats_payload_builder,
        message_router,
        // TODO(SCL-213)
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry.clone(),
        execution_services.ingress_history_reader,
        cycles_account_manager,
        canister_http_adapter_client,
        config.nns_registry_replicator.poll_delay_duration_ms,
        max_certified_height_tx,
    );
    // ---------- PUBLIC ENDPOINT DEPS FOLLOW ----------
    ic_http_endpoints_public::start_server(
        rt_handle_http.clone(),
        metrics_registry,
        config.http_handler.clone(),
        execution_services.ingress_filter,
        execution_services.query_execution_service.clone(),
        ingress_throttler,
        ingress_tx.clone(),
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        node_id,
        subnet_id,
        root_subnet_id,
        log.clone(),
        consensus_pool_cache,
        subnet_type,
        config.malicious_behaviour.malicious_flags,
        None,
        Arc::new(Pprof),
        tracing_handle,
        max_certified_height_rx,
        finalized_ingress_height_rx,
        subnet_is_whitelisted_for_synchronous_call_v3(&subnet_id),
    );

    Ok((
        state_manager,
        execution_services.query_execution_service,
        ingress_tx,
        p2p_runner,
        xnet_endpoint,
    ))
}
