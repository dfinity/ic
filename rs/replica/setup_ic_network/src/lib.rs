//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

use crossbeam_channel::Sender;
use ic_artifact_manager::{manager, *};
use ic_artifact_pool::{
    canister_http_pool::CanisterHttpPoolImpl,
    certification_pool::CertificationPoolImpl,
    consensus_pool::ConsensusPoolImpl,
    dkg_pool::DkgPoolImpl,
    ecdsa_pool::EcdsaPoolImpl,
    ingress_pool::{IngressPoolImpl, IngressPrioritizer},
};
use ic_config::{artifact_pool::ArtifactPoolConfig, transport::TransportConfig};
use ic_consensus::{
    certification::{setup as certification_setup, CertificationCrypto},
    consensus::{dkg_key_manager::DkgKeyManager, setup as consensus_setup},
    dkg, ecdsa,
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, pool_reader::PoolReader,
};
use ic_crypto_tls_interfaces::{TlsHandshake, TlsStream};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_https_outcalls_consensus::{
    gossip::CanisterHttpGossipImpl, payload_builder::CanisterHttpPayloadBuilderImpl,
    pool_manager::CanisterHttpPoolManagerImpl,
};
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_manager::{
        AdvertBroadcaster, ArtifactClient, ArtifactManager, ArtifactProcessor, JoinGuard,
    },
    artifact_pool::UnvalidatedArtifact,
    crypto::IngressSigVerifier,
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::SysTimeSource,
};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_registry::{LocalStoreCertifiedTimeReader, RegistryClient};
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_interfaces_transport::Transport;
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p::{start_p2p, AdvertBroadcasterImpl, MAX_ADVERT_BUFFER};
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
    canister_http::{CanisterHttpRequest, CanisterHttpResponse},
    consensus::CatchUpPackage,
    consensus::HasHeight,
    crypto::CryptoHash,
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
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
    certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    ecdsa_pool: Arc<RwLock<EcdsaPoolImpl>>,
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
    metrics_registry: &MetricsRegistry,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    artifact_pool_config: ArtifactPoolConfig,
    transport_config: TransportConfig,
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
    consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
    catch_up_package: CatchUpPackage,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    self_validating_payload_builder: Arc<dyn SelfValidatingPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    consensus_crypto: Arc<dyn ConsensusCrypto + Send + Sync>,
    certifier_crypto: Arc<dyn CertificationCrypto + Send + Sync>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    registry_poll_delay_duration_ms: u64,
    time_source: Arc<SysTimeSource>,
) -> (
    Arc<RwLock<IngressPoolImpl>>,
    Sender<UnvalidatedArtifact<SignedIngress>>,
    Vec<Box<dyn JoinGuard>>,
) {
    let artifact_pools = init_artifact_pools(
        node_id,
        artifact_pool_config,
        metrics_registry.clone(),
        log.clone(),
        catch_up_package,
    );
    let (advert_tx, advert_rx) = channel(MAX_ADVERT_BUFFER);
    let advert_subscriber = Arc::new(AdvertBroadcasterImpl::new(
        log.clone(),
        metrics_registry,
        advert_tx,
    ));
    let ingress_pool = artifact_pools.ingress_pool.clone();
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
    let oldest_registry_version_in_use = consensus_pool_cache.get_oldest_registry_version_in_use();
    // Initialize the time source.

    // Now we setup the Artifact Pools and the manager.
    let (artifact_manager, join_handles, ingress_sender) = setup_artifact_manager(
        node_id,
        Arc::clone(&consensus_crypto) as Arc<_>,
        Arc::clone(&certifier_crypto) as Arc<_>,
        Arc::clone(&ingress_sig_crypto) as Arc<_>,
        subnet_id,
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
        consensus_pool,
        malicious_flags,
        cycles_account_manager,
        local_store_time_reader,
        registry_poll_delay_duration_ms,
        advert_subscriber,
        canister_http_adapter_client,
        time_source,
    );

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

    start_p2p(
        metrics_registry.clone(),
        log,
        rt_handle,
        node_id,
        subnet_id,
        transport_config,
        registry_client,
        transport,
        consensus_pool_cache,
        artifact_manager.unwrap(),
        advert_rx,
    );
    (ingress_pool, ingress_sender, join_handles)
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
    consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,

    malicious_flags: MaliciousFlags,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    registry_poll_delay_duration_ms: u64,
    advert_broadcaster: Arc<dyn AdvertBroadcaster + Send + Sync>,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    time_source: Arc<SysTimeSource>,
) -> (
    std::io::Result<Arc<dyn ArtifactManager>>,
    Vec<Box<dyn JoinGuard>>,
    Sender<UnvalidatedArtifact<SignedIngress>>,
) {
    let mut backends: HashMap<ArtifactTag, Box<dyn manager::ArtifactManagerBackend>> =
        HashMap::new();
    let mut join_handles = vec![];

    if let P2PStateSyncClient::TestChunkingPool(pool_reader, client_on_state_change) =
        state_sync_client
    {
        let advert_broadcaster = advert_broadcaster;
        let (jh, sender) = run_artifact_processor(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry,
            client_on_state_change,
            move |req| advert_broadcaster.process_delta(req.into()),
        );
        join_handles.push(jh);
        backends.insert(
            TestArtifact::TAG,
            Box::new(ArtifactClientHandle {
                pool_reader,
                sender,
                time_source,
            }),
        );
        let (ingress_sender, _r) = crossbeam_channel::unbounded();

        return (
            Ok(Arc::new(
                manager::ArtifactManagerImpl::new_with_default_priority_fn(backends),
            )),
            join_handles,
            ingress_sender,
        );
    }
    if let P2PStateSyncClient::Client(client) = state_sync_client {
        let advert_broadcaster = advert_broadcaster.clone();
        let (jh, sender) = run_artifact_processor(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry.clone(),
            Box::new(client.clone()) as Box<_>,
            move |req| advert_broadcaster.process_delta(req.into()),
        );
        join_handles.push(jh);
        backends.insert(
            StateSyncArtifact::TAG,
            Box::new(ArtifactClientHandle {
                pool_reader: Box::new(client),
                sender,
                time_source: time_source.clone(),
            }),
        );
    }
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
    let consensus_block_cache = consensus_pool.read().unwrap().get_block_cache();
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
        &PoolReader::new(&*consensus_pool.read().unwrap()),
    )));

    {
        // Create the consensus client.
        let advert_broadcaster = advert_broadcaster.clone();
        let (client, jh) = create_consensus_handlers(
            move |req| advert_broadcaster.process_delta(req.into()),
            consensus_setup(
                replica_config.clone(),
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
            Arc::clone(&consensus_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        backends.insert(ConsensusArtifact::TAG, Box::new(client));
    }

    let ingress_sender = {
        // Create the ingress client.
        let advert_broadcaster = advert_broadcaster.clone();
        let ingress_prioritizer = IngressPrioritizer::new(time_source.clone());
        let (client, jh) = create_ingress_handlers(
            move |req| advert_broadcaster.process_delta(req.into()),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.ingress_pool),
            ingress_prioritizer,
            ingress_manager,
            metrics_registry.clone(),
            malicious_flags.clone(),
        );
        join_handles.push(jh);
        let ingress_sender = client.sender.clone();
        backends.insert(IngressArtifact::TAG, Box::new(client));
        ingress_sender
    };

    {
        // Create the certification client.
        let advert_broadcaster = advert_broadcaster.clone();
        let (client, jh) = create_certification_handlers(
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
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        backends.insert(CertificationArtifact::TAG, Box::new(client));
    }

    {
        // Create the DKG client.
        let advert_broadcaster = advert_broadcaster.clone();
        let (client, jh) = create_dkg_handlers(
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
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        backends.insert(DkgArtifact::TAG, Box::new(client));
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
        let (client, jh) = create_ecdsa_handlers(
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
        );
        join_handles.push(jh);
        backends.insert(EcdsaArtifact::TAG, Box::new(client));
    }

    {
        let (client, jh) = create_https_outcalls_handlers(
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
        );
        join_handles.push(jh);
        backends.insert(CanisterHttpArtifact::TAG, Box::new(client));
    }
    (
        Ok(Arc::new(
            manager::ArtifactManagerImpl::new_with_default_priority_fn(backends),
        )),
        join_handles,
        ingress_sender,
    )
}

fn init_artifact_pools(
    node_id: NodeId,
    config: ArtifactPoolConfig,
    registry: MetricsRegistry,
    log: ReplicaLogger,
    catch_up_package: CatchUpPackage,
) -> ArtifactPools {
    let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
        node_id,
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

    let certification_pool = Arc::new(RwLock::new(CertificationPoolImpl::new(
        config,
        log.clone(),
        registry.clone(),
    )));
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(registry.clone(), log.clone())));
    let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(registry, log)));
    ArtifactPools {
        ingress_pool,
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
