use ic_config::{artifact_pool::ArtifactPoolConfig, subnet_config::SubnetConfig, Config};
use ic_consensus::certification::VerifierImpl;
use ic_crypto::CryptoComponent;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::{setup_execution, IngressHistoryReaderImpl};
use ic_interfaces::registry::LocalStoreCertifiedTimeReader;
use ic_interfaces::{
    certified_stream_store::CertifiedStreamStore,
    consensus_pool::ConsensusPoolCache,
    execution_environment::{ExecutionEnvironment, QueryHandler},
    p2p::IngressEventHandler,
    p2p::P2PRunner,
    registry::RegistryClient,
    transport::Transport,
};
use ic_logger::ReplicaLogger;
use ic_messaging::{MessageRoutingImpl, XNetPayloadBuilderImpl};
use ic_messaging::{XNetEndpoint, XNetEndpointConfig};
use ic_p2p::p2p::{P2PStateSyncClient, P2P};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_state_manager::StateManagerImpl;
use ic_types::{consensus::catchup::CUPWithOriginalProtobuf, transport::FlowTag, NodeId, SubnetId};
use std::sync::Arc;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn construct_p2p_stack(
    replica_logger: ReplicaLogger,
    config: Config,
    subnet_config: SubnetConfig,
    node_id: NodeId,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    registry: Arc<dyn RegistryClient + Send + Sync>,
    crypto: Arc<CryptoComponent>,
    metrics_registry: ic_metrics::MetricsRegistry,
    transport: Arc<dyn Transport>,
    catch_up_package: Option<CUPWithOriginalProtobuf>,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
) -> std::io::Result<(
    // TODO(SCL-213): When Rust traits support it, simplify and pass a single
    // trait.
    Arc<CryptoComponent>,
    Arc<StateManagerImpl>,
    Arc<dyn QueryHandler<State = ReplicatedState>>,
    Box<dyn P2PRunner>,
    Arc<dyn IngressEventHandler>,
    Arc<dyn ConsensusPoolCache>,
    Arc<dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>>,
    XNetEndpoint,
)> {
    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        config.hypervisor.max_cycles_per_canister,
        subnet_type,
        subnet_id,
        subnet_config.cycles_account_manager_config,
    ));
    let (exec_env, ingress_history_writer, http_query_handler) = setup_execution(
        replica_logger.clone(),
        &metrics_registry,
        subnet_id,
        subnet_type,
        subnet_config.scheduler_config.scheduler_cores,
        config.hypervisor.clone(),
        Arc::clone(&cycles_account_manager),
    );

    let verifier = VerifierImpl::new(crypto.clone());
    let state_manager = StateManagerImpl::new(
        Arc::new(verifier),
        subnet_id,
        subnet_type,
        replica_logger.clone(),
        &metrics_registry,
        &config.state_manager,
        config.malicious_behaviour.malicious_flags.clone(),
    );
    let state_manager = Arc::new(state_manager);

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
            ingress_history_writer,
            &metrics_registry,
            replica_logger.clone(),
        )
    } else {
        MessageRoutingImpl::new(
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&certified_stream_store) as Arc<_>,
            ingress_history_writer,
            Arc::clone(&exec_env) as Arc<_>,
            Arc::clone(&cycles_account_manager),
            subnet_config.scheduler_config,
            subnet_id,
            subnet_type,
            &metrics_registry,
            replica_logger.clone(),
            Arc::clone(&registry) as Arc<_>,
        )
    };
    let message_router = Arc::new(message_router);

    let xnet_config =
        XNetEndpointConfig::from(Arc::clone(&registry) as Arc<_>, node_id, &replica_logger);

    let xnet_endpoint = XNetEndpoint::new(
        tokio::runtime::Handle::current(),
        Arc::clone(&certified_stream_store),
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&registry),
        xnet_config,
        &metrics_registry,
        replica_logger.clone(),
    );

    // Use default runtime to spawn xnet client threads.
    let xnet_payload_builder = XNetPayloadBuilderImpl::new(
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&certified_stream_store) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&registry) as Arc<_>,
        tokio::runtime::Handle::current(),
        node_id,
        subnet_id,
        &metrics_registry,
        replica_logger.clone(),
    );
    let xnet_payload_builder = Arc::new(xnet_payload_builder);

    let artifact_pool_config = ArtifactPoolConfig::from(config.artifact_pool);

    let p2p_flow_tags = config
        .transport
        .p2p_flows
        .iter()
        .map(|flow_config| FlowTag::from(flow_config.flow_tag))
        .collect();

    let catch_up_package = catch_up_package.unwrap_or_else(|| {
        CUPWithOriginalProtobuf::from_cup(ic_consensus_message::make_genesis(
            ic_consensus::dkg::make_genesis_summary(&*registry, subnet_id, None),
        ))
    });

    let (p2p_event_handler, p2p_runner, consensus_pool_cache) = P2P::new(
        config.malicious_behaviour.malicious_flags,
        node_id,
        subnet_id,
        transport,
        p2p_flow_tags,
        Arc::clone(&state_manager) as Arc<_>,
        P2PStateSyncClient::Client(Arc::clone(&state_manager) as Arc<_>),
        xnet_payload_builder as Arc<_>,
        message_router as Arc<_>,
        // TODO(SCL-213)
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&crypto) as Arc<_>,
        registry,
        Box::new(IngressHistoryReaderImpl::new(
            Arc::clone(&state_manager) as Arc<_>
        )),
        artifact_pool_config,
        config.consensus,
        metrics_registry,
        replica_logger,
        catch_up_package,
        cycles_account_manager,
        local_store_time_reader,
        config.nns_registry_replicator.poll_delay_duration_ms,
    )
    .expect("Failed to construct p2p");

    Ok((
        crypto,
        state_manager,
        Arc::clone(&http_query_handler) as Arc<_>,
        Box::new(p2p_runner),
        p2p_event_handler,
        consensus_pool_cache,
        exec_env,
        xnet_endpoint,
    ))
}
