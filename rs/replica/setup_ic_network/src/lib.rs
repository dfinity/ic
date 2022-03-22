//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

use ic_artifact_manager::{manager, processors};
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl, consensus_pool::ConsensusPoolImpl,
    dkg_pool::DkgPoolImpl, ecdsa_pool::EcdsaPoolImpl,
    ensure_persistent_pool_replica_version_compatibility, ingress_pool::IngressPoolImpl,
};
use ic_config::{
    artifact_pool::ArtifactPoolConfig, consensus::ConsensusConfig, transport::TransportConfig,
};
use ic_consensus::{
    certification,
    consensus::{ConsensusCrypto, Membership},
    dkg, ecdsa,
};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactManager, ArtifactProcessor},
    consensus_pool::ConsensusPoolCache,
    crypto::{Crypto, IngressSigVerifier},
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    registry::{LocalStoreCertifiedTimeReader, RegistryClient},
    self_validating_payload::SelfValidatingPayloadBuilder,
    state_manager::StateManager,
    time_source::SysTimeSource,
};
use ic_interfaces_p2p::IngressIngestionService;
use ic_interfaces_transport::Transport;
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p::{fetch_gossip_config, start_p2p, AdvertSubscriber, P2PThreadJoiner};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::StateManagerImpl;
use ic_transport::transport::create_transport;
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, FileTreeSyncAttribute},
    consensus::catchup::CUPWithOriginalProtobuf,
    crypto::CryptoHash,
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    malicious_flags::MaliciousFlags,
    replica_config::ReplicaConfig,
    NodeId, SubnetId,
};
use std::sync::{Arc, Mutex, RwLock};

/// The P2P state sync client.
#[derive(Clone)]
pub enum P2PStateSyncClient {
    /// The main client variant.
    Client(Arc<StateManagerImpl>),
    /// The test client variant.
    TestClient(),
    /// The test chunking pool variant.
    TestChunkingPool(
        Arc<dyn ArtifactClient<TestArtifact>>,
        Arc<dyn ArtifactProcessor<TestArtifact> + Sync + 'static>,
    ),
}

/// The collection of all artifact pools.
pub struct ArtifactPools {
    pub ingress_pool: Arc<RwLock<IngressPoolImpl>>,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    pub consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    pub certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    pub dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    pub ecdsa_pool: Arc<RwLock<EcdsaPoolImpl>>,
}

/// The function constructs a P2P instance. Currently, it constructs all the
/// artifact pools and the Consensus/P2P time source. Artifact
/// clients are constructed and run in their separate actors.
#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::new_ret_no_self
)]
pub fn create_networking_stack(
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    transport_config: TransportConfig,
    consensus_config: ConsensusConfig,
    malicious_flags: MaliciousFlags,
    node_id: NodeId,
    subnet_id: SubnetId,
    // For testing purposes the caller can pass a transport object instead. Otherwise, the callee
    // constructs it from the 'transport_config'.
    transport: Option<Arc<dyn Transport>>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    crypto: Arc<dyn Crypto + Send + Sync>,
    consensus_crypto: Arc<dyn ConsensusCrypto + Send + Sync>,
    certifier_crypto: Arc<dyn certification::CertificationCrypto + Send + Sync>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    artifact_pools: &ArtifactPools,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
    registry_poll_delay_duration_ms: u64,
) -> (IngressIngestionService, P2PThreadJoiner) {
    let gossip_config = fetch_gossip_config(registry_client.clone(), subnet_id);
    let advert_subscriber =
        AdvertSubscriber::new(log.clone(), &metrics_registry, gossip_config.clone());

    // Now we setup the Artifact Pools and the manager.
    let artifact_manager = setup_artifact_manager(
        node_id,
        Arc::clone(&crypto) as Arc<_>,
        Arc::clone(&consensus_crypto) as Arc<_>,
        Arc::clone(&certifier_crypto) as Arc<_>,
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        subnet_id,
        consensus_config,
        log.clone(),
        metrics_registry.clone(),
        Arc::clone(&registry_client),
        state_manager,
        state_sync_client,
        xnet_payload_builder,
        self_validating_payload_builder,
        message_router,
        ingress_history_reader,
        artifact_pools,
        malicious_flags.clone(),
        cycles_account_manager,
        local_store_time_reader,
        registry_poll_delay_duration_ms,
        advert_subscriber.clone(),
    )
    .unwrap();

    let transport = transport.unwrap_or_else(|| {
        create_transport(
            node_id,
            transport_config.clone(),
            registry_client.get_latest_version(),
            metrics_registry.clone(),
            tls_handshake,
            rt_handle.clone(),
            log.clone(),
        )
    });

    start_p2p(
        metrics_registry,
        log,
        node_id,
        subnet_id,
        transport_config,
        gossip_config,
        registry_client,
        transport,
        artifact_pools.consensus_pool_cache.clone(),
        artifact_manager,
        artifact_pools.ingress_pool.clone(),
        malicious_flags,
        &advert_subscriber,
    )
}

/// The function sets up and returns the Artifact Manager and Consensus Pool.
///
/// The Artifact Manager runs all artifact clients as separate actors.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn setup_artifact_manager(
    node_id: NodeId,
    _crypto: Arc<dyn Crypto>,
    // ConsensusCrypto is an extension of the Crypto trait and we can
    // not downcast traits.
    consensus_crypto: Arc<dyn ConsensusCrypto>,
    certifier_crypto: Arc<dyn certification::CertificationCrypto>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    subnet_id: SubnetId,
    consensus_config: ConsensusConfig,
    replica_logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    registry_client: Arc<dyn RegistryClient>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    artifact_pools: &ArtifactPools,
    malicious_flags: MaliciousFlags,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
    registry_poll_delay_duration_ms: u64,
    event_handler: AdvertSubscriber,
) -> std::io::Result<Arc<dyn ArtifactManager>> {
    // Initialize the time source.
    let time_source = Arc::new(SysTimeSource::new());

    let mut artifact_manager_maker = manager::ArtifactManagerMaker::new(time_source.clone());

    let consensus_block_cache = artifact_pools
        .consensus_pool
        .read()
        .unwrap()
        .get_block_cache();

    if let P2PStateSyncClient::TestChunkingPool(client, client_on_state_change) = state_sync_client
    {
        let c_event_handler = event_handler;
        let addr = processors::ArtifactProcessorManager::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry,
            processors::BoxOrArcClient::ArcClient(client_on_state_change),
            move |req| c_event_handler.broadcast_advert(req.advert.into(), req.advert_class),
        );
        artifact_manager_maker.add_arc_client(client, addr);
        return Ok(artifact_manager_maker.finish());
    }
    if let P2PStateSyncClient::Client(state_sync_client) = state_sync_client {
        let event_handler = event_handler.clone();
        let addr = processors::ArtifactProcessorManager::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry.clone(),
            processors::BoxOrArcClient::ArcClient(Arc::clone(&state_sync_client) as Arc<_>),
            move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
        );
        artifact_manager_maker.add_arc_client(state_sync_client, addr);
    }

    let consensus_replica_config = ReplicaConfig { node_id, subnet_id };
    let membership = Membership::new(
        artifact_pools.consensus_pool_cache.clone(),
        Arc::clone(&registry_client),
        subnet_id,
    );
    let membership = Arc::new(membership);

    let ingress_manager = IngressManager::new(
        artifact_pools.consensus_pool_cache.clone(),
        ingress_history_reader,
        Arc::clone(&registry_client),
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        metrics_registry.clone(),
        subnet_id,
        replica_logger.clone(),
        Arc::clone(&state_manager) as Arc<_>,
        cycles_account_manager,
        malicious_flags.clone(),
    );
    let ingress_manager = Arc::new(ingress_manager);

    let dkg_key_manager = Arc::new(Mutex::new(
        ic_consensus::consensus::dkg_key_manager::DkgKeyManager::new(
            metrics_registry.clone(),
            Arc::clone(&consensus_crypto),
            replica_logger.clone(),
        ),
    ));

    {
        // Create the consensus client.
        let event_handler = event_handler.clone();
        let (consensus_client, actor) = processors::ConsensusProcessor::build(
            move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
            || {
                ic_consensus::consensus::setup(
                    consensus_replica_config.clone(),
                    consensus_config,
                    Arc::clone(&registry_client),
                    Arc::clone(&membership) as Arc<_>,
                    Arc::clone(&consensus_crypto),
                    Arc::clone(&ingress_manager) as Arc<_>,
                    Arc::clone(&xnet_payload_builder) as Arc<_>,
                    Arc::clone(&self_validating_payload_builder) as Arc<_>,
                    Arc::clone(&artifact_pools.dkg_pool) as Arc<_>,
                    Arc::clone(&artifact_pools.ecdsa_pool) as Arc<_>,
                    Arc::clone(&dkg_key_manager) as Arc<_>,
                    Arc::clone(&message_router) as Arc<_>,
                    Arc::clone(&state_manager) as Arc<_>,
                    Arc::clone(&time_source) as Arc<_>,
                    malicious_flags.clone(),
                    metrics_registry.clone(),
                    replica_logger.clone(),
                    local_store_time_reader,
                    registry_poll_delay_duration_ms,
                )
            },
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.consensus_pool),
            Arc::clone(&artifact_pools.ingress_pool),
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(consensus_client, actor);
    }

    {
        // Create the ingress client.
        let event_handler = event_handler.clone();
        let (ingress_client, actor) = processors::IngressProcessor::build(
            move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.ingress_pool),
            ingress_manager,
            replica_logger.clone(),
            metrics_registry.clone(),
            node_id,
            malicious_flags.clone(),
        );
        artifact_manager_maker.add_client(ingress_client, actor);
    }

    {
        // Create the certification client.
        let event_handler = event_handler.clone();
        let (certification_client, actor) = processors::CertificationProcessor::build(
            move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
            || {
                certification::setup(
                    consensus_replica_config.clone(),
                    Arc::clone(&membership) as Arc<_>,
                    Arc::clone(&certifier_crypto),
                    Arc::clone(&state_manager) as Arc<_>,
                    metrics_registry.clone(),
                    replica_logger.clone(),
                )
            },
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.consensus_pool_cache) as Arc<_>,
            Arc::clone(&artifact_pools.certification_pool),
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(certification_client, actor);
    }

    {
        // Create the DKG client.
        let event_handler = event_handler.clone();
        let (dkg_client, actor) = processors::DkgProcessor::build(
            move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
            || {
                (
                    dkg::DkgImpl::new(
                        consensus_replica_config.node_id,
                        Arc::clone(&consensus_crypto),
                        Arc::clone(&artifact_pools.consensus_pool_cache),
                        dkg_key_manager,
                        metrics_registry.clone(),
                        replica_logger.clone(),
                    ),
                    dkg::DkgGossipImpl {},
                )
            },
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.dkg_pool),
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(dkg_client, actor);
    }

    {
        // Create the ECDSA client if enabled by the config
        if registry_client
            .get_features(subnet_id, registry_client.get_latest_version())
            .ok()
            .flatten()
            .map(|features| features.ecdsa_signatures)
            == Some(true)
        {
            info!(replica_logger, "ECDSA feature enabled");
            let (ecdsa_client, actor) = processors::EcdsaProcessor::build(
                move |req| event_handler.broadcast_advert(req.advert.into(), req.advert_class),
                || {
                    (
                        ecdsa::EcdsaImpl::new(
                            consensus_replica_config.node_id,
                            Arc::clone(&consensus_block_cache),
                            Arc::clone(&consensus_crypto),
                            metrics_registry.clone(),
                            replica_logger.clone(),
                            malicious_flags,
                        ),
                        ecdsa::EcdsaGossipImpl::new(Arc::clone(&consensus_block_cache)),
                    )
                },
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.ecdsa_pool),
                metrics_registry.clone(),
                replica_logger.clone(),
            );
            artifact_manager_maker.add_client(ecdsa_client, actor);
        } else {
            info!(replica_logger, "ECDSA feature disabled");
        }
    }

    Ok(artifact_manager_maker.finish())
}

/// The function initializes the artifact pools.
#[allow(clippy::type_complexity)]
pub fn init_artifact_pools(
    subnet_id: SubnetId,
    config: ArtifactPoolConfig,
    registry: MetricsRegistry,
    log: ReplicaLogger,
    catch_up_package: CUPWithOriginalProtobuf,
) -> ArtifactPools {
    ensure_persistent_pool_replica_version_compatibility(config.persistent_pool_db_path());

    let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
        config.clone(),
        registry.clone(),
        log.clone(),
    )));
    let consensus_pool = Arc::new(RwLock::new(ConsensusPoolImpl::new(
        subnet_id,
        catch_up_package,
        config.clone(),
        registry.clone(),
        log.clone(),
    )));
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
    let certification_pool = Arc::new(RwLock::new(CertificationPoolImpl::new(
        config,
        log.clone(),
        registry.clone(),
    )));
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(registry.clone())));
    let ecdsa_pool = Arc::new(RwLock::new(EcdsaPoolImpl::new(log, registry)));
    ArtifactPools {
        ingress_pool,
        consensus_pool,
        consensus_pool_cache,
        certification_pool,
        dkg_pool,
        ecdsa_pool,
    }
}

// The following types are used for testing only. Ideally, they should only
// appear in the test module, but `TestArtifact` is used by
// `P2PStateSyncClient` so these definitions are still required here.

#[derive(Eq, PartialEq)]
/// The artifact struct used by the testing framework.
pub struct TestArtifact;
/// The artifact message used by the testing framework.
pub type TestArtifactMessage = FileTreeSyncArtifact;
/// The artifact ID used by the testing framework.
pub type TestArtifactId = FileTreeSyncId;
/// The attribute of the artifact used by the testing framework.
pub type TestArtifactAttribute = FileTreeSyncAttribute;

/// `TestArtifact` implements the `ArtifactKind` trait.
impl ArtifactKind for TestArtifact {
    const TAG: ArtifactTag = ArtifactTag::FileTreeSyncArtifact;
    type Message = TestArtifactMessage;
    type SerializeAs = TestArtifactMessage;
    type Id = TestArtifactId;
    type Attribute = TestArtifactAttribute;
    type Filter = ();

    /// The function converts a TestArtifactMessage to an advert for a
    /// TestArtifact.
    fn message_to_advert(msg: &TestArtifactMessage) -> Advert<TestArtifact> {
        Advert {
            attribute: msg.id.to_string(),
            size: 0,
            id: msg.id.clone(),
            integrity_hash: CryptoHash(msg.id.clone().into_bytes()),
        }
    }
}
