//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

mod setup_ingress;

use ic_artifact_manager::{manager, *};
use ic_artifact_pool::{
    canister_http_pool::CanisterHttpPoolImpl,
    certification_pool::CertificationPoolImpl,
    consensus_pool::ConsensusPoolImpl,
    dkg_pool::DkgPoolImpl,
    ecdsa_pool::EcdsaPoolImpl,
    ensure_persistent_pool_replica_version_compatibility,
    ingress_pool::{IngressPoolImpl, IngressPrioritizer},
};
use ic_config::{
    artifact_pool::ArtifactPoolConfig, consensus::ConsensusConfig, transport::TransportConfig,
};
use ic_consensus::{
    canister_http::{
        gossip::CanisterHttpGossipImpl, payload_builder::CanisterHttpPayloadBuilderImpl,
        pool_manager::CanisterHttpPoolManagerImpl,
    },
    certification::{setup as certification_setup, CertificationCrypto},
    consensus::{dkg_key_manager::DkgKeyManager, setup as consensus_setup},
    dkg, ecdsa,
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, pool_reader::PoolReader,
};
use ic_crypto_tls_interfaces::{TlsHandshake, TlsStream};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_manager::{AdvertBroadcaster, ArtifactClient, ArtifactManager, ArtifactProcessor},
    crypto::IngressSigVerifier,
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::SysTimeSource,
};
use ic_interfaces_p2p::IngressIngestionService;
use ic_interfaces_registry::{LocalStoreCertifiedTimeReader, RegistryClient};
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_interfaces_transport::Transport;
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p::{start_p2p, AdvertBroadcasterImpl, P2PThreadJoiner, MAX_ADVERT_BUFFER};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::state_sync::{StateSync, StateSyncArtifact};
use ic_transport::transport::create_transport;
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, FileTreeSyncAttribute},
    artifact_kind::{
        CanisterHttpArtifact, CertificationArtifact, ConsensusArtifact, DkgArtifact, EcdsaArtifact,
        IngressArtifact,
    },
    consensus::catchup::CUPWithOriginalProtobuf,
    consensus::HasHeight,
    crypto::CryptoHash,
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    malicious_flags::MaliciousFlags,
    replica_config::ReplicaConfig,
    NodeId, SubnetId,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::mpsc::channel;

/// The P2P state sync client.
pub enum P2PStateSyncClient {
    /// The main client variant.
    Client(StateSync),
    /// The test client variant.
    TestClient(),
    /// The test chunking pool variant.
    TestChunkingPool(
        Box<dyn ArtifactClient<TestArtifact>>,
        Box<dyn ArtifactProcessor<TestArtifact> + Sync + 'static>,
    ),
}

/// The collection of all artifact pools.
pub struct ArtifactPools {
    ingress_pool: Arc<RwLock<IngressPoolImpl>>,
    pub consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    ecdsa_pool: Arc<RwLock<EcdsaPoolImpl>>,
    canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
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
    metrics_registry: &MetricsRegistry,
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
    sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    consensus_crypto: Arc<dyn ConsensusCrypto + Send + Sync>,
    certifier_crypto: Arc<dyn CertificationCrypto + Send + Sync>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    artifact_pools: ArtifactPools,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    canister_http_adapter_client:
        ic_interfaces_https_outcalls_adapter_client::CanisterHttpAdapterClient,
    registry_poll_delay_duration_ms: u64,
) -> (IngressIngestionService, P2PThreadJoiner) {
    let (advert_tx, advert_rx) = channel(MAX_ADVERT_BUFFER);
    let advert_subscriber = Arc::new(AdvertBroadcasterImpl::new(
        log.clone(),
        metrics_registry,
        advert_tx,
    ));
    let ingress_pool = artifact_pools.ingress_pool.clone();
    let consensus_pool_cache = artifact_pools.consensus_pool.read().unwrap().get_cache();
    let oldest_registry_version_in_use = consensus_pool_cache.get_oldest_registry_version_in_use();
    // Now we setup the Artifact Pools and the manager.
    let artifact_manager = setup_artifact_manager(
        node_id,
        Arc::clone(&consensus_crypto) as Arc<_>,
        Arc::clone(&certifier_crypto) as Arc<_>,
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        subnet_id,
        consensus_config,
        log.clone(),
        metrics_registry.clone(),
        Arc::clone(&registry_client),
        state_manager,
        state_reader,
        state_sync_client,
        xnet_payload_builder,
        self_validating_payload_builder,
        message_router,
        ingress_history_reader,
        artifact_pools,
        malicious_flags,
        cycles_account_manager,
        local_store_time_reader,
        registry_poll_delay_duration_ms,
        advert_subscriber,
        canister_http_adapter_client,
    )
    .unwrap();

    let transport = transport.unwrap_or_else(|| {
        create_transport(
            node_id,
            transport_config.clone(),
            registry_client.get_latest_version(),
            oldest_registry_version_in_use,
            metrics_registry.clone(),
            tls_handshake,
            sev_handshake,
            rt_handle.clone(),
            log.clone(),
            false,
        )
    });

    let ingress_event_handler = {
        let _enter = rt_handle.enter();
        setup_ingress::IngressEventHandler::new_service(
            log.clone(),
            ingress_pool,
            artifact_manager.clone(),
            node_id,
        )
    };

    let p2p_thread = start_p2p(
        metrics_registry.clone(),
        log,
        node_id,
        subnet_id,
        transport_config,
        registry_client,
        transport,
        consensus_pool_cache,
        artifact_manager,
        advert_rx,
    );
    (ingress_event_handler, p2p_thread)
}

/// The function sets up and returns the Artifact Manager and Consensus Pool.
///
/// The Artifact Manager runs all artifact clients as separate actors.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn setup_artifact_manager(
    node_id: NodeId,
    // ConsensusCrypto is an extension of the Crypto trait and we can
    // not downcast traits.
    consensus_crypto: Arc<dyn ConsensusCrypto>,
    certifier_crypto: Arc<dyn CertificationCrypto>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    subnet_id: SubnetId,
    consensus_config: ConsensusConfig,
    replica_logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    registry_client: Arc<dyn RegistryClient>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    artifact_pools: ArtifactPools,
    malicious_flags: MaliciousFlags,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    registry_poll_delay_duration_ms: u64,
    advert_broadcaster: Arc<dyn AdvertBroadcaster + Send + Sync>,
    canister_http_adapter_client: ic_interfaces_https_outcalls_adapter_client::CanisterHttpAdapterClient,
) -> std::io::Result<Arc<dyn ArtifactManager>> {
    // Initialize the time source.
    let time_source = Arc::new(SysTimeSource::new());
    let consensus_pool_cache = artifact_pools.consensus_pool.read().unwrap().get_cache();

    let mut backends: HashMap<ArtifactTag, Box<dyn manager::ArtifactManagerBackend>> =
        HashMap::new();

    let consensus_block_cache = artifact_pools
        .consensus_pool
        .read()
        .unwrap()
        .get_block_cache();

    if let P2PStateSyncClient::TestChunkingPool(pool_reader, client_on_state_change) =
        state_sync_client
    {
        let advert_broadcaster = advert_broadcaster;
        let processor_handle = ArtifactProcessorHandle::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry,
            client_on_state_change,
            move |req| advert_broadcaster.process_delta(req.into()),
        );

        backends.insert(
            TestArtifact::TAG,
            Box::new(ArtifactClientHandle {
                pool_reader,
                processor_handle,
                time_source,
            }),
        );
        return Ok(Arc::new(
            manager::ArtifactManagerImpl::new_with_default_priority_fn(backends),
        ));
    }
    if let P2PStateSyncClient::Client(client) = state_sync_client {
        let advert_broadcaster = advert_broadcaster.clone();
        let processor_handle = ArtifactProcessorHandle::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry.clone(),
            Box::new(client.clone()) as Box<_>,
            move |req| advert_broadcaster.process_delta(req.into()),
        );

        backends.insert(
            StateSyncArtifact::TAG,
            Box::new(ArtifactClientHandle {
                pool_reader: Box::new(client),
                processor_handle,
                time_source: time_source.clone(),
            }),
        );
    }

    let replica_config = ReplicaConfig { node_id, subnet_id };
    let membership = Arc::new(Membership::new(
        consensus_pool_cache.clone(),
        Arc::clone(&registry_client),
        subnet_id,
    ));

    let ingress_manager = Arc::new(IngressManager::new(
        consensus_pool_cache.clone(),
        ingress_history_reader,
        artifact_pools.ingress_pool.clone(),
        Arc::clone(&registry_client),
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        metrics_registry.clone(),
        subnet_id,
        replica_logger.clone(),
        Arc::clone(&state_reader) as Arc<_>,
        cycles_account_manager,
        malicious_flags.clone(),
    ));

    let canister_http_payload_builder = Arc::new(CanisterHttpPayloadBuilderImpl::new(
        artifact_pools.canister_http_pool.clone(),
        consensus_pool_cache.clone(),
        consensus_crypto.clone(),
        state_reader.clone(),
        membership.clone(),
        subnet_id,
        registry_client.clone(),
        &metrics_registry,
        replica_logger.clone(),
    ));

    let dkg_key_manager = Arc::new(Mutex::new(DkgKeyManager::new(
        metrics_registry.clone(),
        Arc::clone(&consensus_crypto),
        replica_logger.clone(),
        &PoolReader::new(&*artifact_pools.consensus_pool.read().unwrap()),
    )));

    {
        // Create the consensus client.
        let advert_broadcaster = advert_broadcaster.clone();
        backends.insert(
            ConsensusArtifact::TAG,
            Box::new(create_consensus_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                consensus_setup(
                    replica_config.clone(),
                    consensus_config,
                    Arc::clone(&registry_client),
                    Arc::clone(&membership) as Arc<_>,
                    Arc::clone(&consensus_crypto),
                    Arc::clone(&ingress_manager) as Arc<_>,
                    xnet_payload_builder,
                    self_validating_payload_builder,
                    canister_http_payload_builder,
                    Arc::clone(&artifact_pools.dkg_pool) as Arc<_>,
                    Arc::clone(&artifact_pools.ecdsa_pool) as Arc<_>,
                    Arc::clone(&dkg_key_manager) as Arc<_>,
                    message_router,
                    Arc::clone(&state_manager) as Arc<_>,
                    Arc::clone(&time_source) as Arc<_>,
                    malicious_flags.clone(),
                    metrics_registry.clone(),
                    replica_logger.clone(),
                    local_store_time_reader,
                    registry_poll_delay_duration_ms,
                ),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.consensus_pool),
                replica_logger.clone(),
                metrics_registry.clone(),
            )),
        );
    }

    {
        // Create the ingress client.
        let advert_broadcaster = advert_broadcaster.clone();
        let ingress_prioritizer = IngressPrioritizer::new(time_source.clone());
        backends.insert(
            IngressArtifact::TAG,
            Box::new(create_ingress_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.ingress_pool),
                ingress_prioritizer,
                ingress_manager,
                replica_logger.clone(),
                metrics_registry.clone(),
                node_id,
                malicious_flags.clone(),
            )),
        );
    }

    {
        // Create the certification client.
        let advert_broadcaster = advert_broadcaster.clone();
        backends.insert(
            CertificationArtifact::TAG,
            Box::new(create_certification_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                certification_setup(
                    replica_config,
                    Arc::clone(&membership) as Arc<_>,
                    Arc::clone(&certifier_crypto),
                    Arc::clone(&state_manager) as Arc<_>,
                    Arc::clone(&consensus_pool_cache) as Arc<_>,
                    metrics_registry.clone(),
                    replica_logger.clone(),
                ),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.certification_pool),
                replica_logger.clone(),
                metrics_registry.clone(),
            )),
        );
    }

    {
        // Create the DKG client.
        let advert_broadcaster = advert_broadcaster.clone();
        backends.insert(
            DkgArtifact::TAG,
            Box::new(create_dkg_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                (
                    dkg::DkgImpl::new(
                        node_id,
                        Arc::clone(&consensus_crypto),
                        Arc::clone(&consensus_pool_cache),
                        dkg_key_manager,
                        metrics_registry.clone(),
                        replica_logger.clone(),
                    ),
                    dkg::DkgGossipImpl {},
                ),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.dkg_pool),
                replica_logger.clone(),
                metrics_registry.clone(),
            )),
        );
    }

    {
        let advert_broadcaster = advert_broadcaster.clone();
        let finalized = consensus_pool_cache.finalized_block();
        let ecdsa_config =
            registry_client.get_ecdsa_config(subnet_id, registry_client.get_latest_version());
        info!(
            replica_logger,
            "ECDSA: finalized_height = {:?}, ecdsa_config = {:?}, \
                 DKG interval start = {:?}, is_summary = {}, has_ecdsa = {}",
            finalized.height(),
            ecdsa_config,
            finalized.payload.as_ref().dkg_interval_start_height(),
            finalized.payload.as_ref().is_summary(),
            finalized.payload.as_ref().as_ecdsa().is_some(),
        );
        backends.insert(
            EcdsaArtifact::TAG,
            Box::new(create_ecdsa_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                (
                    ecdsa::EcdsaImpl::new(
                        node_id,
                        subnet_id,
                        Arc::clone(&consensus_block_cache),
                        Arc::clone(&consensus_crypto),
                        metrics_registry.clone(),
                        replica_logger.clone(),
                        malicious_flags,
                    ),
                    ecdsa::EcdsaGossipImpl::new(
                        subnet_id,
                        Arc::clone(&consensus_block_cache),
                        metrics_registry.clone(),
                    ),
                ),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.ecdsa_pool),
                metrics_registry.clone(),
            )),
        );
    }

    {
        backends.insert(
            CanisterHttpArtifact::TAG,
            Box::new(create_https_outcalls_handlers(
                move |req| advert_broadcaster.process_delta(req.into()),
                (
                    CanisterHttpPoolManagerImpl::new(
                        Arc::clone(&state_reader),
                        Arc::new(Mutex::new(canister_http_adapter_client)),
                        Arc::clone(&consensus_crypto),
                        Arc::clone(&membership),
                        Arc::clone(&consensus_pool_cache),
                        ReplicaConfig { subnet_id, node_id },
                        Arc::clone(&registry_client),
                        metrics_registry.clone(),
                        replica_logger.clone(),
                    ),
                    CanisterHttpGossipImpl::new(
                        Arc::clone(&consensus_pool_cache),
                        Arc::clone(&state_reader),
                        replica_logger,
                    ),
                ),
                Arc::clone(&time_source) as Arc<_>,
                Arc::clone(&artifact_pools.canister_http_pool),
                metrics_registry,
            )),
        );
    }
    Ok(Arc::new(
        manager::ArtifactManagerImpl::new_with_default_priority_fn(backends),
    ))
}

/// The function initializes the artifact pools.
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

    let mut ecdsa_pool = EcdsaPoolImpl::new_with_stats(
        config.clone(),
        log.clone(),
        registry.clone(),
        Box::new(ecdsa::EcdsaStatsImpl::new(registry.clone())),
    );
    ecdsa_pool.add_initial_dealings(&catch_up_package);
    let ecdsa_pool = Arc::new(RwLock::new(ecdsa_pool));

    let consensus_pool = Arc::new(RwLock::new(ConsensusPoolImpl::new(
        subnet_id,
        catch_up_package,
        config.clone(),
        registry.clone(),
        log.clone(),
    )));
    let certification_pool = Arc::new(RwLock::new(CertificationPoolImpl::new(
        config,
        log,
        registry.clone(),
    )));
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(registry.clone())));
    let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(registry)));
    ArtifactPools {
        ingress_pool,
        consensus_pool,
        certification_pool,
        dkg_pool,
        ecdsa_pool,
        canister_http_pool,
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
