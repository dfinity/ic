//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

use crate::event_handler::{AdvertSubscriber, P2PEventHandlerControl, P2PEventHandlerImpl};
use crate::gossip_protocol::{Gossip, GossipImpl};
use crate::metrics::{DownloadManagementMetrics, DownloadPrioritizerMetrics, P2PMetrics};
use crate::utils::FlowMapper;
use crate::{download_management::DownloadManagerImpl, event_handler::IngressThrottler};
use crate::{
    download_prioritization::DownloadPrioritizerImpl, event_handler::IngressEventHandlerImpl,
};
use ic_artifact_manager::{actors, manager};
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl, consensus_pool::ConsensusPoolImpl,
    dkg_pool::DkgPoolImpl, ensure_persistent_pool_replica_version_compatibility,
    ingress_pool::IngressPoolImpl,
};
use ic_base_thread::async_safe_block_on_await;
use ic_config::{artifact_pool::ArtifactPoolConfig, consensus::ConsensusConfig};
use ic_consensus::{
    certification,
    consensus::{ConsensusCrypto, Membership},
    dkg,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactManager, ArtifactProcessor},
    consensus_pool::ConsensusPoolCache,
    crypto::{Crypto, IngressSigVerifier},
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    p2p::{IngressEventHandler, P2PRunner},
    registry::RegistryClient,
    state_manager::StateManager,
    time_source::SysTimeSource,
    transport::Transport,
};
use ic_logger::{debug, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::StateManagerImpl;
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, FileTreeSyncAttribute},
    consensus::catchup::CUPWithOriginalProtobuf,
    crypto::CryptoHash,
    filetree_sync::{FileTreeSyncArtifact, FileTreeSyncId},
    p2p,
    replica_config::ReplicaConfig,
    transport::FlowTag,
    NodeId, SubnetId,
};
use std::sync::{
    atomic::{AtomicBool, Ordering::SeqCst},
    Arc, RwLock,
};
use std::time::Duration;
use tokio::task::JoinHandle;

// import of malicious flags definition for p2p
use ic_interfaces::registry::LocalStoreCertifiedTimeReader;
use ic_types::malicious_flags::MaliciousFlags;

/// Periodic timer duration in milliseconds between polling calls to the P2P
/// component.
const P2P_TIMER_DURATION_MS: u64 = 100;

/// A helper service to run the P2P component.
pub struct P2PService {
    p2p: Option<P2P>,
}

impl Drop for P2PService {
    /// The method drops the P2PService.
    fn drop(&mut self) {
        if let Some(p2p) = self.p2p.take() {
            std::mem::drop(p2p);
        }
    }
}

impl P2PRunner for P2PService {
    /// The method starts the run loop of the P2P service.
    fn run(&mut self) {
        self.p2p.as_mut().unwrap().start_timer();
    }
}

/// The P2P struct, which encapsulates all relevant components including gossip
/// and event handler control.
#[allow(unused)]
pub struct P2P {
    /// The logger.
    pub(crate) log: ReplicaLogger,
    /// Handle to the Tokio runtime to be used by p2p.
    rt_handle: tokio::runtime::Handle,
    /// The time source.
    time_source: Arc<SysTimeSource>,
    /// The *Gossip* struct with automatic reference counting.
    gossip: Arc<GossipImpl>,
    /// The task handles.
    task_handles: Vec<JoinHandle<()>>,
    /// Flag indicating if P2P has been terminated.
    killed: Arc<AtomicBool>,
    /// The P2P metrics.
    metrics: P2PMetrics,
    /// The P2P event handler control with automatic reference counting.
    event_handler: Arc<dyn P2PEventHandlerControl>,
}

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

impl P2P {
    /// Fetch the Gossip configuration from the registry.
    pub fn fetch_gossip_config(
        registry_client: Arc<dyn RegistryClient>,
        subnet_id: SubnetId,
    ) -> GossipConfig {
        if let Ok(Some(Some(gossip_config))) =
            registry_client.get_gossip_config(subnet_id, registry_client.get_latest_version())
        {
            gossip_config
        } else {
            p2p::build_default_gossip_config()
        }
    }

    /// The function constructs a P2P instance. Currently, it constructs all the
    /// artifact pools and the Consensus/P2P time source. Artifact
    /// clients are constructed and run in their separate actors.
    #[allow(
        clippy::too_many_arguments,
        clippy::type_complexity,
        clippy::new_ret_no_self
    )]
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        malicious_flags: MaliciousFlags,
        node_id: NodeId,
        subnet_id: SubnetId,
        transport: Arc<dyn Transport>,
        flow_tags: Vec<FlowTag>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        state_sync_client: P2PStateSyncClient,
        xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
        message_router: Arc<dyn MessageRouting>,
        crypto: Arc<dyn Crypto + Send + Sync>,
        consensus_crypto: Arc<dyn ConsensusCrypto + Send + Sync>,
        certifier_crypto: Arc<dyn certification::CertificationCrypto + Send + Sync>,
        ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_history_reader: Box<dyn IngressHistoryReader>,
        artifact_pool_config: ArtifactPoolConfig,
        consensus_config: ConsensusConfig,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
        catch_up_package: CUPWithOriginalProtobuf,
        cycles_account_manager: Arc<CyclesAccountManager>,
        local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
        registry_poll_delay_duration_ms: u64,
    ) -> Result<
        (
            Arc<dyn IngressEventHandler>,
            P2PService,
            Arc<dyn ConsensusPoolCache>,
        ),
        String,
    > {
        let p2p_metrics = P2PMetrics::new(&metrics_registry);
        let flow_mapper = Arc::new(FlowMapper::new(flow_tags));
        // Initialize the time source.
        let time_source = SysTimeSource::new();
        let time_source = Arc::new(time_source);
        let task_handles = Vec::new();
        let killed = Arc::new(AtomicBool::new(false));

        // Now we setup the Artifact Pools and the manager.
        let (artifact_manager, consensus_pool_cache, event_handler, ingress_throttle) =
            setup_artifact_manager(
                rt_handle.clone(),
                node_id,
                Arc::clone(&crypto) as Arc<_>,
                Arc::clone(&consensus_crypto) as Arc<_>,
                Arc::clone(&certifier_crypto) as Arc<_>,
                Arc::clone(&ingress_sig_crypto) as Arc<_>,
                subnet_id,
                Arc::clone(&time_source),
                artifact_pool_config,
                consensus_config,
                log.clone(),
                metrics_registry.clone(),
                Arc::clone(&registry_client),
                state_manager,
                state_sync_client,
                xnet_payload_builder,
                message_router,
                ingress_history_reader,
                catch_up_package,
                malicious_flags.clone(),
                cycles_account_manager,
                local_store_time_reader,
                registry_poll_delay_duration_ms,
            )
            .unwrap();

        let download_prioritizer = Arc::new(DownloadPrioritizerImpl::new(
            artifact_manager.as_ref(),
            DownloadPrioritizerMetrics::new(&metrics_registry),
        ));

        let download_manager = DownloadManagerImpl::new(
            node_id,
            subnet_id,
            registry_client.clone(),
            artifact_manager.clone(),
            transport.clone(),
            event_handler.clone(),
            flow_mapper,
            log.clone(),
            Arc::clone(&download_prioritizer) as Arc<_>,
            DownloadManagementMetrics::new(&metrics_registry),
        )?;

        let gossip = Arc::new(GossipImpl::new(
            download_manager,
            Arc::clone(&artifact_manager),
            log.clone(),
            &metrics_registry,
            malicious_flags,
        ));

        event_handler.start(gossip.clone());

        let p2p = P2P {
            log,
            rt_handle,
            gossip: gossip.clone(),
            time_source,
            metrics: p2p_metrics,
            task_handles,
            killed,
            event_handler,
        };

        let p2p_runner = P2PService { p2p: Some(p2p) };
        let ingress_handler = Arc::from(IngressEventHandlerImpl::new(
            ingress_throttle,
            gossip,
            node_id,
        ));
        Ok((ingress_handler as Arc<_>, p2p_runner, consensus_pool_cache))
    }

    /// The method starts the P2P timer task in the background.
    fn start_timer(&mut self) {
        let gossip = self.gossip.clone();
        let event_handler = self.event_handler.clone();
        let log = self.log.clone();
        let killed = Arc::clone(&self.killed);
        let handle = self.rt_handle.spawn_blocking(move || {
            debug!(log, "P2P::p2p_timer(): started processing",);

            let timer_duration = Duration::from_millis(P2P_TIMER_DURATION_MS);
            while !killed.load(SeqCst) {
                std::thread::sleep(timer_duration);
                gossip.on_timer(&event_handler);
            }
        });
        self.task_handles.push(handle);
    }
}

impl Drop for P2P {
    /// The method signals the tasks to exit and waits for them to complete.
    fn drop(&mut self) {
        self.killed.store(true, SeqCst);
        while let Some(handle) = self.task_handles.pop() {
            async_safe_block_on_await(handle).ok();
        }
        self.event_handler.stop();
    }
}

/// The function sets up and returns the Artifact Manager and Consensus Pool.
///
/// The Artifact Manager runs all artifact clients as separate actors.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn setup_artifact_manager(
    rt_handle: tokio::runtime::Handle,
    node_id: NodeId,
    _crypto: Arc<dyn Crypto>,
    // ConsensusCrypto is an extension of the Crypto trait and we can
    // not downcast traits.
    consensus_crypto: Arc<dyn ConsensusCrypto>,
    certifier_crypto: Arc<dyn certification::CertificationCrypto>,
    ingress_sig_crypto: Arc<dyn IngressSigVerifier + Send + Sync>,
    subnet_id: SubnetId,
    time_source: Arc<SysTimeSource>,
    artifact_pool_config: ArtifactPoolConfig,
    consensus_config: ConsensusConfig,
    replica_logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    registry_client: Arc<dyn RegistryClient>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_sync_client: P2PStateSyncClient,
    xnet_payload_builder: Arc<dyn XNetPayloadBuilder>,
    message_router: Arc<dyn MessageRouting>,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    catch_up_package: CUPWithOriginalProtobuf,
    malicious_flags: MaliciousFlags,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_store_time_reader: Option<Arc<dyn LocalStoreCertifiedTimeReader>>,
    registry_poll_delay_duration_ms: u64,
) -> std::io::Result<(
    Arc<dyn ArtifactManager>,
    Arc<dyn ConsensusPoolCache>,
    Arc<P2PEventHandlerImpl>,
    IngressThrottler,
)> {
    let mut artifact_manager_maker = manager::ArtifactManagerMaker::new(time_source.clone());

    ensure_persistent_pool_replica_version_compatibility(
        artifact_pool_config.persistent_pool_db_path(),
    );

    let (ingress_pool, consensus_pool, cert_pool, dkg_pool) = init_artifact_pools(
        subnet_id,
        artifact_pool_config,
        metrics_registry.clone(),
        replica_logger.clone(),
        catch_up_package,
    );

    let event_handler = Arc::new(P2PEventHandlerImpl::new(
        rt_handle.clone(),
        node_id,
        replica_logger.clone(),
        &metrics_registry,
        P2P::fetch_gossip_config(registry_client.clone(), subnet_id),
    ));

    let consensus_cache = consensus_pool.read().unwrap().get_cache();

    if let P2PStateSyncClient::TestChunkingPool(client, client_on_state_change) = state_sync_client
    {
        let c_event_handler = event_handler.clone();
        let addr = actors::ClientActor::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry,
            actors::BoxOrArcClient::ArcClient(client_on_state_change),
            move |advert| c_event_handler.broadcast_advert(advert.into()),
            rt_handle,
        );
        artifact_manager_maker.add_arc_client(client, addr);
        return Ok((
            artifact_manager_maker.finish(),
            consensus_cache,
            event_handler,
            ingress_pool as Arc<_>,
        ));
    }
    if let P2PStateSyncClient::Client(state_sync_client) = state_sync_client {
        let event_handler = event_handler.clone();
        let addr = actors::ClientActor::new(
            Arc::clone(&time_source) as Arc<_>,
            metrics_registry.clone(),
            actors::BoxOrArcClient::ArcClient(Arc::clone(&state_sync_client) as Arc<_>),
            move |advert| event_handler.broadcast_advert(advert.into()),
            rt_handle.clone(),
        );
        artifact_manager_maker.add_arc_client(state_sync_client, addr);
    }

    let consensus_replica_config = ReplicaConfig { node_id, subnet_id };
    let membership = Membership::new(
        consensus_cache.clone(),
        Arc::clone(&registry_client),
        subnet_id,
    );
    let membership = Arc::new(membership);

    let ingress_manager = IngressManager::new(
        consensus_cache.clone(),
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

    {
        // Create the consensus client.
        let event_handler = event_handler.clone();
        let (consensus_client, actor) = actors::ConsensusProcessor::build(
            move |advert| event_handler.broadcast_advert(advert.into()),
            || {
                ic_consensus::consensus::setup(
                    consensus_replica_config.clone(),
                    consensus_config,
                    Arc::clone(&registry_client),
                    Arc::clone(&membership) as Arc<_>,
                    Arc::clone(&consensus_crypto),
                    Arc::clone(&ingress_manager) as Arc<_>,
                    Arc::clone(&xnet_payload_builder) as Arc<_>,
                    Arc::clone(&dkg_pool) as Arc<_>,
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
            Arc::clone(&consensus_pool),
            Arc::clone(&ingress_pool),
            rt_handle.clone(),
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(consensus_client, actor);
    }

    {
        // Create the ingress client.
        let event_handler = event_handler.clone();
        let (ingress_client, actor) = actors::IngressProcessor::build(
            move |advert| event_handler.broadcast_advert(advert.into()),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&ingress_pool),
            ingress_manager,
            rt_handle.clone(),
            replica_logger.clone(),
            metrics_registry.clone(),
            malicious_flags,
        );
        artifact_manager_maker.add_client(ingress_client, actor);
    }

    {
        // Create the certification client.
        let event_handler = event_handler.clone();
        let (certification_client, actor) = actors::CertificationProcessor::build(
            move |advert| event_handler.broadcast_advert(advert.into()),
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
            Arc::clone(&consensus_cache) as Arc<_>,
            Arc::clone(&cert_pool),
            rt_handle.clone(),
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(certification_client, actor);
    }

    {
        let event_handler = event_handler.clone();
        let (dkg_client, actor) = actors::DkgProcessor::build(
            move |advert| event_handler.broadcast_advert(advert.into()),
            || {
                (
                    dkg::DkgImpl::new(
                        consensus_replica_config.node_id,
                        Arc::clone(&consensus_crypto),
                        Arc::clone(&consensus_cache),
                        metrics_registry.clone(),
                        replica_logger.clone(),
                    ),
                    dkg::DkgGossipImpl {},
                )
            },
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&dkg_pool),
            rt_handle,
            replica_logger.clone(),
            metrics_registry.clone(),
        );
        artifact_manager_maker.add_client(dkg_client, actor);
    }

    Ok((
        artifact_manager_maker.finish(),
        consensus_cache,
        event_handler,
        ingress_pool as Arc<_>,
    ))
}

/// The function initializes the artifact pools.
#[allow(clippy::type_complexity)]
pub(crate) fn init_artifact_pools(
    subnet_id: SubnetId,
    config: ArtifactPoolConfig,
    registry: MetricsRegistry,
    log: ReplicaLogger,
    catch_up_package: CUPWithOriginalProtobuf,
) -> (
    Arc<RwLock<IngressPoolImpl>>,
    Arc<RwLock<ConsensusPoolImpl>>,
    Arc<RwLock<CertificationPoolImpl>>,
    Arc<RwLock<DkgPoolImpl>>,
) {
    (
        Arc::new(RwLock::new(IngressPoolImpl::new(
            config.clone(),
            registry.clone(),
            log.clone(),
        ))),
        Arc::new(RwLock::new(ConsensusPoolImpl::new(
            subnet_id,
            catch_up_package,
            config.clone(),
            registry.clone(),
            log.clone(),
        ))),
        Arc::new(RwLock::new(CertificationPoolImpl::new(
            config,
            log,
            registry.clone(),
        ))),
        Arc::new(RwLock::new(DkgPoolImpl::new(registry))),
    )
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
