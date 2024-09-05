//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

use ic_artifact_manager::{create_artifact_handler, create_ingress_handlers};
use ic_artifact_pool::{
    canister_http_pool::CanisterHttpPoolImpl, certification_pool::CertificationPoolImpl,
    consensus_pool::ConsensusPoolImpl, dkg_pool::DkgPoolImpl, idkg_pool::IDkgPoolImpl,
    ingress_pool::IngressPoolImpl,
};
use ic_config::{artifact_pool::ArtifactPoolConfig, transport::TransportConfig};
use ic_consensus::{
    certification::{CertificationCrypto, CertifierBouncer, CertifierImpl},
    consensus::{dkg_key_manager::DkgKeyManager, ConsensusBouncer, ConsensusImpl},
    dkg, idkg,
};
use ic_consensus_manager::ConsensusManagerBuilder;
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, pool_reader::PoolReader,
};
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_https_outcalls_consensus::{
    gossip::CanisterHttpGossipImpl, payload_builder::CanisterHttpPayloadBuilderImpl,
    pool_manager::CanisterHttpPoolManagerImpl,
};
use ic_ingress_manager::{bouncer::IngressBouncer, IngressManager, RandomStateKind};
use ic_interfaces::{
    batch_payload::BatchPayloadBuilder,
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    p2p::artifact_manager::JoinGuard,
    p2p::state_sync::StateSyncClient,
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_quic_transport::create_udp_socket;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::state_sync::types::StateSyncMessage;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    canister_http::{CanisterHttpRequest, CanisterHttpResponse},
    consensus::{CatchUpPackage, HasHeight},
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    replica_config::ReplicaConfig,
    Height, NodeId, SubnetId,
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::{mpsc::UnboundedSender, watch};
use tower_http::trace::TraceLayer;

pub const MAX_ADVERT_BUFFER: usize = 100_000;

/// The collection of all artifact pools.
struct ArtifactPools {
    ingress_pool: Arc<RwLock<IngressPoolImpl>>,
    certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    idkg_pool: Arc<RwLock<IDkgPoolImpl>>,
    canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
}

pub type CanisterHttpAdapterClient =
    Box<dyn NonBlockingChannel<CanisterHttpRequest, Response = CanisterHttpResponse> + Send>;

/// The function constructs a P2P instance. Currently, it constructs all the
/// artifact pools and the Consensus/P2P time source. Artifact
/// clients are constructed and run in their separate actors.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::new_ret_no_self
)]
pub fn setup_consensus_and_p2p(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    artifact_pool_config: ArtifactPoolConfig,
    transport_config: TransportConfig,
    malicious_flags: MaliciousFlags,
    node_id: NodeId,
    subnet_id: SubnetId,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    catch_up_package: CatchUpPackage,
    state_sync_client: Arc<dyn StateSyncClient<Message = StateSyncMessage>>,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    query_stats_payload_builder: Box<dyn BatchPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    consensus_crypto: Arc<dyn ConsensusCrypto + Send + Sync>,
    certifier_crypto: Arc<dyn CertificationCrypto + Send + Sync>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    registry_poll_delay_duration_ms: u64,
    max_certified_height_tx: watch::Sender<Height>,
) -> (
    Arc<RwLock<IngressPoolImpl>>,
    UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    Vec<Box<dyn JoinGuard>>,
) {
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();

    let (ingress_pool, ingress_sender, join_handles, mut p2p_consensus) = start_consensus(
        log,
        metrics_registry,
        rt_handle,
        node_id,
        subnet_id,
        artifact_pool_config,
        catch_up_package,
        Arc::clone(&consensus_crypto) as Arc<_>,
        Arc::clone(&certifier_crypto) as Arc<_>,
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        Arc::clone(&registry_client),
        state_manager,
        state_reader,
        xnet_payload_builder,
        self_validating_payload_builder,
        query_stats_payload_builder,
        message_router,
        ingress_history_reader,
        consensus_pool.clone(),
        malicious_flags,
        cycles_account_manager,
        registry_poll_delay_duration_ms,
        canister_http_adapter_client,
        max_certified_height_tx,
    );

    // StateSync receive side => handler definition
    let (state_sync_router, state_sync_manager_rx) = ic_state_sync_manager::build_axum_router(
        state_sync_client.clone(),
        log.clone(),
        metrics_registry,
    );

    // Consensus receive side => handler definition

    // Merge all receive side handlers => router
    let p2p_router = state_sync_router
        .merge(p2p_consensus.router())
        .layer(TraceLayer::new_for_http());
    // Quic transport
    let (_, topology_watcher) = ic_peer_manager::start_peer_manager(
        log.clone(),
        metrics_registry,
        rt_handle,
        subnet_id,
        consensus_pool_cache.clone(),
        registry_client.clone(),
    );

    let transport_addr: SocketAddr = (
        IpAddr::from_str(&transport_config.node_ip).expect("Invalid IP"),
        transport_config.listening_port,
    )
        .into();

    let quic_transport = Arc::new(ic_quic_transport::QuicTransport::start(
        log,
        metrics_registry,
        rt_handle,
        tls_config,
        registry_client.clone(),
        node_id,
        topology_watcher.clone(),
        create_udp_socket(rt_handle, transport_addr),
        p2p_router,
    ));

    // Start the main event loops for StateSync and Consensus

    let _state_sync_manager = ic_state_sync_manager::start_state_sync_manager(
        log,
        metrics_registry,
        rt_handle,
        quic_transport.clone(),
        state_sync_client,
        state_sync_manager_rx,
    );

    let _cancellation_token = p2p_consensus.run(quic_transport, topology_watcher);

    (ingress_pool, ingress_sender, join_handles)
}

/// The function creates the Consensus stack (including all Consensus clients)
/// and starts the artifact manager event loop for each client.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn start_consensus(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    node_id: NodeId,
    subnet_id: SubnetId,
    artifact_pool_config: ArtifactPoolConfig,
    catch_up_package: CatchUpPackage,
    // ConsensusCrypto is an extension of the Crypto trait and we can
    // not downcast traits.
    consensus_crypto: Arc<dyn ConsensusCrypto>,
    certifier_crypto: Arc<dyn CertificationCrypto>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    query_stats_payload_builder: Box<dyn BatchPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    malicious_flags: MaliciousFlags,
    cycles_account_manager: Arc<CyclesAccountManager>,
    registry_poll_delay_duration_ms: u64,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    max_certified_height_tx: watch::Sender<Height>,
) -> (
    Arc<RwLock<IngressPoolImpl>>,
    UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    Vec<Box<dyn JoinGuard>>,
    ConsensusManagerBuilder,
) {
    let time_source = Arc::new(SysTimeSource::new());
    let mut new_p2p_consensus: ic_consensus_manager::ConsensusManagerBuilder =
        ic_consensus_manager::ConsensusManagerBuilder::new(
            log.clone(),
            rt_handle.clone(),
            metrics_registry.clone(),
        );

    let artifact_pools = init_artifact_pools(
        node_id,
        artifact_pool_config,
        metrics_registry,
        log,
        catch_up_package,
        time_source.as_ref(),
    );

    let mut join_handles = vec![];

    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
    let consensus_time = consensus_pool.read().unwrap().get_consensus_time();
    let replica_config = ReplicaConfig { node_id, subnet_id };
    let ingress_manager = Arc::new(IngressManager::new(
        time_source.clone(),
        consensus_time,
        ingress_history_reader,
        artifact_pools.ingress_pool.clone(),
        Arc::clone(&registry_client),
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        metrics_registry.clone(),
        subnet_id,
        log.clone(),
        Arc::clone(&state_reader),
        cycles_account_manager,
        malicious_flags.clone(),
        // todo: use a builder pattern and remove this from the constructor.
        RandomStateKind::Random,
    ));

    let canister_http_payload_builder = Arc::new(CanisterHttpPayloadBuilderImpl::new(
        artifact_pools.canister_http_pool.clone(),
        consensus_pool_cache.clone(),
        consensus_crypto.clone(),
        state_reader.clone(),
        subnet_id,
        registry_client.clone(),
        metrics_registry,
        log.clone(),
    ));

    let dkg_key_manager = Arc::new(Mutex::new(DkgKeyManager::new(
        metrics_registry.clone(),
        Arc::clone(&consensus_crypto),
        log.clone(),
        &PoolReader::new(&*consensus_pool.read().unwrap()),
    )));

    let (consensus_tx, consensus_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (certification_tx, certification_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (dkg_tx, dkg_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (ingress_tx, ingress_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (idkg_tx, idkg_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (http_outcalls_tx, http_outcalls_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);

    {
        let consensus_impl = ConsensusImpl::new(
            replica_config.clone(),
            Arc::clone(&registry_client),
            Arc::clone(&consensus_crypto),
            Arc::clone(&ingress_manager) as Arc<_>,
            xnet_payload_builder,
            self_validating_payload_builder,
            canister_http_payload_builder,
            Arc::from(query_stats_payload_builder),
            Arc::clone(&artifact_pools.dkg_pool) as Arc<_>,
            Arc::clone(&artifact_pools.idkg_pool) as Arc<_>,
            Arc::clone(&dkg_key_manager) as Arc<_>,
            message_router.clone(),
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&time_source) as Arc<_>,
            registry_poll_delay_duration_ms,
            malicious_flags.clone(),
            metrics_registry.clone(),
            log.clone(),
        );

        let consensus_pool = Arc::clone(&consensus_pool);

        // Create the consensus client.
        let (client, jh) = create_artifact_handler(
            consensus_tx,
            consensus_impl,
            time_source.clone(),
            consensus_pool.clone(),
            metrics_registry.clone(),
        );

        join_handles.push(jh);

        let bouncer = Arc::new(ConsensusBouncer::new(message_router));
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            consensus_pool,
            bouncer,
            metrics_registry.clone(),
        );
        new_p2p_consensus.add_client(consensus_rx, client, assembler);
    };

    let ingress_sender = {
        // Create the ingress client.
        let (client, jh) = create_ingress_handlers(
            ingress_tx,
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.ingress_pool),
            ingress_manager,
            metrics_registry.clone(),
        );

        join_handles.push(jh);

        let bouncer = Arc::new(IngressBouncer::new(time_source.clone()));
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            artifact_pools.ingress_pool.clone(),
            bouncer,
            metrics_registry.clone(),
        );

        new_p2p_consensus.add_client(ingress_rx, client.clone(), assembler);
        client
    };

    {
        let certifier = CertifierImpl::new(
            replica_config,
            Arc::clone(&registry_client),
            Arc::clone(&certifier_crypto),
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&consensus_pool_cache) as Arc<_>,
            metrics_registry.clone(),
            log.clone(),
            max_certified_height_tx,
        );

        // Create the certification client.
        let (client, jh) = create_artifact_handler(
            certification_tx,
            certifier,
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.certification_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);

        let bouncer = CertifierBouncer::new(Arc::clone(&consensus_pool_cache));
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            artifact_pools.certification_pool,
            Arc::new(bouncer),
            metrics_registry.clone(),
        );
        new_p2p_consensus.add_client(certification_rx, client, assembler);
    };

    {
        // Create the DKG client.
        let (client, jh) = create_artifact_handler(
            dkg_tx,
            dkg::DkgImpl::new(
                node_id,
                Arc::clone(&consensus_crypto),
                Arc::clone(&consensus_pool_cache),
                dkg_key_manager,
                metrics_registry.clone(),
                log.clone(),
            ),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.dkg_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);

        let bouncer = Arc::new(dkg::DkgBouncer);
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            artifact_pools.dkg_pool,
            bouncer,
            metrics_registry.clone(),
        );
        new_p2p_consensus.add_client(dkg_rx, client, assembler);
    };

    {
        let finalized = consensus_pool_cache.finalized_block();
        let chain_key_config =
            registry_client.get_chain_key_config(subnet_id, registry_client.get_latest_version());
        info!(
            log,
            "IDKG: finalized_height = {:?}, chain_key_config = {:?}, \
                 DKG interval start = {:?}, is_summary = {}, has_idkg_payload = {}",
            finalized.height(),
            chain_key_config,
            finalized.payload.as_ref().dkg_interval_start_height(),
            finalized.payload.as_ref().is_summary(),
            finalized.payload.as_ref().as_idkg().is_some(),
        );

        let (client, jh) = create_artifact_handler(
            idkg_tx,
            idkg::IDkgImpl::new(
                node_id,
                consensus_pool.read().unwrap().get_block_cache(),
                Arc::clone(&consensus_crypto),
                Arc::clone(&state_reader),
                metrics_registry.clone(),
                log.clone(),
                malicious_flags,
            ),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.idkg_pool),
            metrics_registry.clone(),
        );

        join_handles.push(jh);

        let bouncer = Arc::new(idkg::IDkgBouncer::new(
            subnet_id,
            consensus_pool.read().unwrap().get_block_cache(),
            Arc::clone(&state_reader),
        ));
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            artifact_pools.idkg_pool,
            bouncer,
            metrics_registry.clone(),
        );
        new_p2p_consensus.add_client(idkg_rx, client, assembler);
    };

    {
        let (client, jh) = create_artifact_handler(
            http_outcalls_tx,
            CanisterHttpPoolManagerImpl::new(
                Arc::clone(&state_reader),
                Arc::new(Mutex::new(canister_http_adapter_client)),
                Arc::clone(&consensus_crypto),
                Arc::clone(&consensus_pool_cache),
                ReplicaConfig { subnet_id, node_id },
                Arc::clone(&registry_client),
                metrics_registry.clone(),
                log.clone(),
            ),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.canister_http_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);

        let bouncer = Arc::new(CanisterHttpGossipImpl::new(
            Arc::clone(&consensus_pool_cache),
            Arc::clone(&state_reader),
            log.clone(),
        ));
        let assembler = ic_artifact_downloader::FetchArtifact::new(
            log.clone(),
            rt_handle.clone(),
            artifact_pools.canister_http_pool,
            bouncer,
            metrics_registry.clone(),
        );
        new_p2p_consensus.add_client(http_outcalls_rx, client, assembler);
    };

    (
        artifact_pools.ingress_pool,
        ingress_sender,
        join_handles,
        new_p2p_consensus,
    )
}

fn init_artifact_pools(
    node_id: NodeId,
    config: ArtifactPoolConfig,
    metrics_registry: &MetricsRegistry,
    log: &ReplicaLogger,
    catch_up_package: CatchUpPackage,
    time_source: &dyn TimeSource,
) -> ArtifactPools {
    let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
        node_id,
        config.clone(),
        metrics_registry.clone(),
        log.clone(),
    )));

    let mut idkg_pool = IDkgPoolImpl::new(
        config.clone(),
        log.clone(),
        metrics_registry.clone(),
        Box::new(idkg::IDkgStatsImpl::new(metrics_registry.clone())),
    );
    idkg_pool.add_initial_dealings(&catch_up_package, time_source);
    let idkg_pool = Arc::new(RwLock::new(idkg_pool));

    let certification_pool = Arc::new(RwLock::new(CertificationPoolImpl::new(
        node_id,
        config,
        log.clone(),
        metrics_registry.clone(),
    )));
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(
        metrics_registry.clone(),
        log.clone(),
    )));
    let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(
        metrics_registry.clone(),
        log.clone(),
    )));
    ArtifactPools {
        ingress_pool,
        certification_pool,
        dkg_pool,
        idkg_pool,
        canister_http_pool,
    }
}
