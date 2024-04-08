//! The P2P module exposes the peer-to-peer functionality.
//!
//! Specifically, it constructs all the artifact pools and the Consensus/P2P
//! time source.

use crossbeam_channel::{bounded, Sender};
use either::Either;
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
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tls_interfaces::{TlsConfig, TlsHandshake};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_https_outcalls_consensus::{
    gossip::CanisterHttpGossipImpl, payload_builder::CanisterHttpPayloadBuilderImpl,
    pool_manager::CanisterHttpPoolManagerImpl,
};
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::{
    batch_payload::BatchPayloadBuilder,
    execution_environment::IngressHistoryReader,
    messaging::{MessageRouting, XNetPayloadBuilder},
    p2p::artifact_manager::{ArtifactProcessorEvent, JoinGuard},
    p2p::consensus::PriorityFnAndFilterProducer,
    p2p::state_sync::StateSyncClient,
    self_validating_payload::SelfValidatingPayloadBuilder,
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_registry::{LocalStoreCertifiedTimeReader, RegistryClient};
use ic_interfaces_state_manager::{StateManager, StateReader};
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_p2p::{start_p2p, MAX_ADVERT_BUFFER};
use ic_quic_transport::DummyUdpSocket;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::state_sync::types::StateSyncMessage;
use ic_types::{
    artifact::{ArtifactKind, ArtifactTag, UnvalidatedArtifactMutation},
    artifact_kind::{
        CanisterHttpArtifact, CertificationArtifact, ConsensusArtifact, DkgArtifact, EcdsaArtifact,
        IngressArtifact,
    },
    canister_http::{CanisterHttpRequest, CanisterHttpResponse},
    consensus::CatchUpPackage,
    consensus::HasHeight,
    malicious_flags::MaliciousFlags,
    p2p::GossipAdvert,
    replica_config::ReplicaConfig,
    NodeId, SubnetId,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::mpsc::{Sender as TokioSender, UnboundedSender};

const ENABLE_NEW_P2P_CONSENSUS: bool = true;
const ENABLE_NEW_P2P_CERTIFICATION: bool = true;
const ENABLE_NEW_P2P_DKG: bool = true;
const ENABLE_NEW_P2P_INGRESS: bool = true;
const ENABLE_NEW_P2P_ECDSA: bool = true;
const ENABLE_NEW_P2P_HTTPS_OUTCALLS: bool = true;

struct P2PSenders {
    consensus: Channel<ConsensusArtifact>,
    certification: Channel<CertificationArtifact>,
    dkg: Channel<DkgArtifact>,
    ingress: Channel<IngressArtifact>,
    ecdsa: Channel<EcdsaArtifact>,
    https_outcalls: Channel<CanisterHttpArtifact>,
}
enum Channel<A: ArtifactKind> {
    Old(Sender<GossipAdvert>),
    New(TokioSender<ArtifactProcessorEvent<A>>),
}

/// The collection of all artifact pools.
struct ArtifactPools {
    ingress_pool: Arc<RwLock<IngressPoolImpl>>,
    certification_pool: Arc<RwLock<CertificationPoolImpl>>,
    dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    ecdsa_pool: Arc<RwLock<EcdsaPoolImpl>>,
    canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
}

struct P2PClientAndPrioFn<Artifact: ArtifactKind + 'static, Pool> {
    client_handle: ArtifactClientHandle<Artifact>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
}

struct P2PClients {
    consensus: P2PClientAndPrioFn<ConsensusArtifact, ConsensusPoolImpl>,
    ingress: P2PClientAndPrioFn<IngressArtifact, IngressPoolImpl>,
    certification: P2PClientAndPrioFn<CertificationArtifact, CertificationPoolImpl>,
    dkg: P2PClientAndPrioFn<DkgArtifact, DkgPoolImpl>,
    ecdsa: P2PClientAndPrioFn<EcdsaArtifact, EcdsaPoolImpl>,
    https_outcalls: P2PClientAndPrioFn<CanisterHttpArtifact, CanisterHttpPoolImpl>,
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
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
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
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    registry_poll_delay_duration_ms: u64,
) -> (
    Arc<RwLock<IngressPoolImpl>>,
    UnboundedSender<UnvalidatedArtifactMutation<IngressArtifact>>,
    Vec<Box<dyn JoinGuard>>,
) {
    let time_source = Arc::new(SysTimeSource::new());
    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();

    let start_consensus = |advert_sender| {
        start_consensus(
            log,
            metrics_registry,
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
            local_store_time_reader,
            registry_poll_delay_duration_ms,
            advert_sender,
            canister_http_adapter_client,
            time_source.clone(),
        )
    };

    let (advert_tx, advert_rx) = bounded(MAX_ADVERT_BUFFER);
    let mut backends: HashMap<ArtifactTag, Box<dyn manager::ArtifactManagerBackend>> =
        HashMap::new();

    let mut new_p2p_consensus = ic_consensus_manager::ConsensusManagerBuilder::new(
        log.clone(),
        rt_handle.clone(),
        metrics_registry.clone(),
    );

    let mut p2p_router = None;

    let (consensus_advert_tx, consensus_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (certification_advert_tx, certification_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (dkg_tx, dkg_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (ingress_tx, ingress_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (ecdsa_tx, ecdsa_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let (http_outcalls_tx, http_outcalls_rx) = tokio::sync::mpsc::channel(MAX_ADVERT_BUFFER);
    let advert_tx = P2PSenders {
        consensus: if ENABLE_NEW_P2P_CONSENSUS {
            Channel::New(consensus_advert_tx)
        } else {
            Channel::Old(advert_tx.clone())
        },
        certification: if ENABLE_NEW_P2P_CERTIFICATION {
            Channel::New(certification_advert_tx)
        } else {
            Channel::Old(advert_tx.clone())
        },
        dkg: if ENABLE_NEW_P2P_DKG {
            Channel::New(dkg_tx)
        } else {
            Channel::Old(advert_tx.clone())
        },
        ingress: if ENABLE_NEW_P2P_INGRESS {
            Channel::New(ingress_tx)
        } else {
            Channel::Old(advert_tx.clone())
        },
        ecdsa: if ENABLE_NEW_P2P_ECDSA {
            Channel::New(ecdsa_tx)
        } else {
            Channel::Old(advert_tx.clone())
        },
        https_outcalls: if ENABLE_NEW_P2P_HTTPS_OUTCALLS {
            Channel::New(http_outcalls_tx)
        } else {
            Channel::Old(advert_tx)
        },
    };
    let (p2p_clients, mut join_handles, artifact_pools) = start_consensus(advert_tx);
    let ArtifactPools {
        certification_pool,
        dkg_pool,
        ecdsa_pool,
        canister_http_pool,
        ingress_pool,
    } = artifact_pools;

    if ENABLE_NEW_P2P_CONSENSUS {
        new_p2p_consensus.add_client(
            consensus_rx,
            consensus_pool,
            p2p_clients.consensus.priority_fn_producer,
            p2p_clients.consensus.client_handle.sender,
        );
    } else {
        backends.insert(
            ConsensusArtifact::TAG,
            Box::new(p2p_clients.consensus.client_handle),
        );
    }

    if ENABLE_NEW_P2P_CERTIFICATION {
        new_p2p_consensus.add_client(
            certification_rx,
            certification_pool,
            p2p_clients.certification.priority_fn_producer,
            p2p_clients.certification.client_handle.sender,
        );
    } else {
        backends.insert(
            CertificationArtifact::TAG,
            Box::new(p2p_clients.certification.client_handle),
        );
    }

    if ENABLE_NEW_P2P_DKG {
        new_p2p_consensus.add_client(
            dkg_rx,
            dkg_pool,
            p2p_clients.dkg.priority_fn_producer,
            p2p_clients.dkg.client_handle.sender,
        );
    } else {
        backends.insert(DkgArtifact::TAG, Box::new(p2p_clients.dkg.client_handle));
    }
    let (ingress_sender, ingress_pool) = if ENABLE_NEW_P2P_INGRESS {
        new_p2p_consensus.add_client(
            ingress_rx,
            ingress_pool.clone(),
            p2p_clients.ingress.priority_fn_producer,
            p2p_clients.ingress.client_handle.sender.clone(),
        );
        (p2p_clients.ingress.client_handle.sender, ingress_pool)
    } else {
        let ingress_sender = p2p_clients.ingress.client_handle.sender.clone();

        backends.insert(
            IngressArtifact::TAG,
            Box::new(p2p_clients.ingress.client_handle),
        );
        (ingress_sender, ingress_pool)
    };

    if ENABLE_NEW_P2P_ECDSA {
        new_p2p_consensus.add_client(
            ecdsa_rx,
            ecdsa_pool,
            p2p_clients.ecdsa.priority_fn_producer,
            p2p_clients.ecdsa.client_handle.sender,
        );
    } else {
        backends.insert(
            EcdsaArtifact::TAG,
            Box::new(p2p_clients.ecdsa.client_handle),
        );
    }

    if ENABLE_NEW_P2P_HTTPS_OUTCALLS {
        new_p2p_consensus.add_client(
            http_outcalls_rx,
            canister_http_pool,
            p2p_clients.https_outcalls.priority_fn_producer,
            p2p_clients.https_outcalls.client_handle.sender,
        );
    } else {
        backends.insert(
            CanisterHttpArtifact::TAG,
            Box::new(p2p_clients.https_outcalls.client_handle),
        );
    }
    p2p_router = Some(
        new_p2p_consensus
            .router()
            .merge(p2p_router.unwrap_or_default()),
    );

    // StateSync
    let (state_sync_router, state_sync_manager_rx) = ic_state_sync_manager::build_axum_router(
        state_sync_client.clone(),
        log.clone(),
        metrics_registry,
    );
    p2p_router = Some(state_sync_router.merge(p2p_router.unwrap_or_default()));

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
        Either::<_, DummyUdpSocket>::Left(transport_addr),
        p2p_router.unwrap_or_default(),
    ));

    let _state_sync_manager = ic_state_sync_manager::start_state_sync_manager(
        log,
        metrics_registry,
        rt_handle,
        quic_transport.clone(),
        state_sync_client,
        state_sync_manager_rx,
    );

    let _cancellation_token = new_p2p_consensus.run(quic_transport, topology_watcher);

    if !(ENABLE_NEW_P2P_CONSENSUS
        && ENABLE_NEW_P2P_CERTIFICATION
        && ENABLE_NEW_P2P_DKG
        && ENABLE_NEW_P2P_INGRESS
        && ENABLE_NEW_P2P_ECDSA
        && ENABLE_NEW_P2P_HTTPS_OUTCALLS)
    {
        let artifact_manager = Arc::new(
            manager::ArtifactManagerImpl::new_with_default_priority_fn(backends),
        );

        join_handles.push(start_p2p(
            log,
            metrics_registry,
            rt_handle,
            node_id,
            subnet_id,
            transport_config,
            registry_client,
            consensus_pool_cache,
            artifact_manager,
            advert_rx,
            tls_handshake,
        ));
    }
    (ingress_pool, ingress_sender, join_handles)
}

/// The function creates the Consensus stack (including all Consensus clients)
/// and starts the artifact manager event loop for each client.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn start_consensus(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
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
    local_store_time_reader: Arc<dyn LocalStoreCertifiedTimeReader>,
    registry_poll_delay_duration_ms: u64,
    advert_tx: P2PSenders,
    canister_http_adapter_client: CanisterHttpAdapterClient,
    time_source: Arc<dyn TimeSource>,
) -> (P2PClients, Vec<Box<dyn JoinGuard>>, ArtifactPools) {
    let artifact_pools = init_artifact_pools(
        node_id,
        artifact_pool_config,
        metrics_registry,
        log,
        catch_up_package,
    );

    let mut join_handles = vec![];

    let consensus_pool_cache = consensus_pool.read().unwrap().get_cache();
    let consensus_time = consensus_pool.read().unwrap().get_consensus_time();
    let consensus_block_cache = consensus_pool.read().unwrap().get_block_cache();
    let replica_config = ReplicaConfig { node_id, subnet_id };
    let membership = Arc::new(Membership::new(
        consensus_pool_cache.clone(),
        Arc::clone(&registry_client),
        subnet_id,
    ));

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
        membership.clone(),
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

    let consensus_client = {
        let (consensus_setup, consensus_gossip) = consensus_setup(
            replica_config.clone(),
            Arc::clone(&registry_client),
            Arc::clone(&membership) as Arc<_>,
            Arc::clone(&consensus_crypto),
            Arc::clone(&ingress_manager) as Arc<_>,
            xnet_payload_builder,
            self_validating_payload_builder,
            canister_http_payload_builder,
            Arc::from(query_stats_payload_builder),
            Arc::clone(&artifact_pools.dkg_pool) as Arc<_>,
            Arc::clone(&artifact_pools.ecdsa_pool) as Arc<_>,
            Arc::clone(&dkg_key_manager) as Arc<_>,
            message_router,
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&time_source) as Arc<_>,
            malicious_flags.clone(),
            metrics_registry.clone(),
            log.clone(),
            local_store_time_reader,
            registry_poll_delay_duration_ms,
        );

        let consensus_gossip = Arc::new(consensus_gossip);
        let consensus_pool = Arc::clone(&consensus_pool);

        // Create the consensus client.
        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                consensus: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }

            P2PSenders {
                consensus: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();

                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };

        let (client, jh) = create_consensus_handlers(
            send_advert,
            consensus_setup,
            consensus_gossip.clone(),
            time_source.clone(),
            consensus_pool,
            metrics_registry.clone(),
        );

        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: consensus_gossip,
        }
    };

    let ingress_client = {
        let ingress_prioritizer = Arc::new(IngressPrioritizer::new(time_source.clone()));

        // Create the consensus client.
        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                ingress: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }

            P2PSenders {
                ingress: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();

                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };
        // Create the ingress client.
        let (client, jh) = create_ingress_handlers(
            send_advert,
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.ingress_pool),
            ingress_prioritizer.clone(),
            ingress_manager,
            metrics_registry.clone(),
            malicious_flags.clone(),
        );

        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: ingress_prioritizer,
        }
    };

    let certification_client = {
        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                certification: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }

            P2PSenders {
                certification: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();

                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };
        let (certifier, certifier_gossip) = certification_setup(
            replica_config,
            Arc::clone(&membership) as Arc<_>,
            Arc::clone(&certifier_crypto),
            Arc::clone(&state_manager) as Arc<_>,
            Arc::clone(&consensus_pool_cache) as Arc<_>,
            metrics_registry.clone(),
            log.clone(),
        );

        let certifier_gossip = Arc::new(certifier_gossip);

        // Create the certification client.
        let (client, jh) = create_certification_handlers(
            send_advert,
            certifier,
            certifier_gossip.clone(),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.certification_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: certifier_gossip,
        }
    };

    let dkg_client = {
        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                dkg: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }
            P2PSenders {
                dkg: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();

                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };
        // Create the DKG client.
        let dkg_gossip = Arc::new(dkg::DkgGossipImpl {});
        let (client, jh) = create_dkg_handlers(
            send_advert,
            dkg::DkgImpl::new(
                node_id,
                Arc::clone(&consensus_crypto),
                Arc::clone(&consensus_pool_cache),
                dkg_key_manager,
                metrics_registry.clone(),
                log.clone(),
            ),
            dkg_gossip.clone(),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.dkg_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: dkg_gossip,
        }
    };

    let ecdsa_client = {
        let finalized = consensus_pool_cache.finalized_block();
        let ecdsa_config =
            registry_client.get_ecdsa_config(subnet_id, registry_client.get_latest_version());
        info!(
            log,
            "ECDSA: finalized_height = {:?}, ecdsa_config = {:?}, \
                 DKG interval start = {:?}, is_summary = {}, has_ecdsa = {}",
            finalized.height(),
            ecdsa_config,
            finalized.payload.as_ref().dkg_interval_start_height(),
            finalized.payload.as_ref().is_summary(),
            finalized.payload.as_ref().as_ecdsa().is_some(),
        );

        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                ecdsa: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }
            P2PSenders {
                ecdsa: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };

        let ecdsa_gossip = Arc::new(ecdsa::EcdsaGossipImpl::new(
            subnet_id,
            Arc::clone(&consensus_block_cache),
            Arc::clone(&state_reader),
            metrics_registry.clone(),
        ));

        let (client, jh) = create_ecdsa_handlers(
            send_advert,
            ecdsa::EcdsaImpl::new(
                node_id,
                Arc::clone(&consensus_block_cache),
                Arc::clone(&consensus_crypto),
                Arc::clone(&state_reader),
                metrics_registry.clone(),
                log.clone(),
                malicious_flags,
            ),
            ecdsa_gossip.clone(),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.ecdsa_pool),
            metrics_registry.clone(),
        );

        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: ecdsa_gossip,
        }
    };

    let https_outcalls_client = {
        let send_advert: Box<dyn Fn(_) + Send> = match &advert_tx {
            P2PSenders {
                https_outcalls: Channel::New(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    advert_tx
                        .blocking_send(req)
                        .expect("Channel should not be closed");
                })
            }
            P2PSenders {
                https_outcalls: Channel::Old(advert_tx),
                ..
            } => {
                let advert_tx = advert_tx.clone();
                Box::new(move |req| {
                    if let ArtifactProcessorEvent::Artifact(advert) = req {
                        let _ = advert_tx.send(advert.advert.into());
                    }
                })
            }
        };

        let canister_http_gossip = Arc::new(CanisterHttpGossipImpl::new(
            Arc::clone(&consensus_pool_cache),
            Arc::clone(&state_reader),
            log.clone(),
        ));

        let (client, jh) = create_https_outcalls_handlers(
            send_advert,
            CanisterHttpPoolManagerImpl::new(
                Arc::clone(&state_reader),
                Arc::new(Mutex::new(canister_http_adapter_client)),
                Arc::clone(&consensus_crypto),
                Arc::clone(&membership),
                Arc::clone(&consensus_pool_cache),
                ReplicaConfig { subnet_id, node_id },
                Arc::clone(&registry_client),
                metrics_registry.clone(),
                log.clone(),
            ),
            canister_http_gossip.clone(),
            Arc::clone(&time_source) as Arc<_>,
            Arc::clone(&artifact_pools.canister_http_pool),
            metrics_registry.clone(),
        );
        join_handles.push(jh);
        P2PClientAndPrioFn {
            client_handle: client,
            priority_fn_producer: canister_http_gossip,
        }
    };

    let p2p_clients = P2PClients {
        consensus: consensus_client,
        certification: certification_client,
        dkg: dkg_client,
        ingress: ingress_client,
        ecdsa: ecdsa_client,
        https_outcalls: https_outcalls_client,
    };

    (p2p_clients, join_handles, artifact_pools)
}

fn init_artifact_pools(
    node_id: NodeId,
    config: ArtifactPoolConfig,
    metrics_registry: &MetricsRegistry,
    log: &ReplicaLogger,
    catch_up_package: CatchUpPackage,
) -> ArtifactPools {
    let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
        node_id,
        config.clone(),
        metrics_registry.clone(),
        log.clone(),
    )));

    let mut ecdsa_pool = EcdsaPoolImpl::new(
        config.clone(),
        log.clone(),
        metrics_registry.clone(),
        Box::new(ecdsa::EcdsaStatsImpl::new(metrics_registry.clone())),
    );
    ecdsa_pool.add_initial_dealings(&catch_up_package);
    let ecdsa_pool = Arc::new(RwLock::new(ecdsa_pool));

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
        ecdsa_pool,
        canister_http_pool,
    }
}
