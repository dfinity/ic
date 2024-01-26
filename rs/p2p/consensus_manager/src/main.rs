use std::{
    collections::{hash_map::DefaultHasher, HashSet},
    convert::Infallible,
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use either::Either;
use futures::{io::Read, StreamExt};
use ic_crypto_test_utils_tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_icos_sev::{ValidateAttestationError, ValidateAttestedStream};
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent,
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info, new_replica_logger_from_config, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_pprof::{Pprof, PprofCollector};
use ic_quic_transport::{DummyUdpSocket, SubnetTopology};
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, Priority, UnvalidatedArtifactMutation},
    crypto::CryptoHash,
    NodeId, RegistryVersion,
};
use ic_types_test_utils::ids::node_test_id;
use libp2p::{
    core::ConnectedPoint, gossipsub::IdentTopic, swarm::SwarmEvent, Multiaddr, PeerId, Swarm,
    SwarmBuilder,
};
use prometheus::{Histogram, IntCounter, TextEncoder};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    select,
    sync::watch,
};
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    server::{ClientCertVerified, ClientCertVerifier},
    Certificate, ClientConfig, PrivateKey, ServerConfig,
};
use tokio_util::time::DelayQueue;
// use tokio_util::time::DelayQueue;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TestArtifact;

type NodeIdAttribute = ();
// 24 bytes
// [message_id: [0..8], artifact_producer_node_id: [8..16], time_stamp: [16..24]]
type MessageId = Vec<u8>;

impl ArtifactKind for TestArtifact {
    // Does not matter
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    type PbMessage = Vec<u8>;
    type PbIdError = Infallible;
    type PbMessageError = Infallible;
    type PbAttributeError = Infallible;
    type PbFilterError = Infallible;

    type PbAttribute = NodeIdAttribute;
    type Attribute = NodeIdAttribute;

    type PbId = MessageId;
    type Id = MessageId;

    type Message = Vec<u8>;
    type PbFilter = ();
    type Filter = ();

    /// The function converts a TestArtifactMessage to an advert for a
    /// TestArtifact.
    fn message_to_advert(msg: &Self::Message) -> Advert<TestArtifact> {
        let id = msg[..24].into();
        // let id = msg[..16].into();
        let attribute = ();

        Advert {
            attribute,
            size: 1024 * 1024,
            id,
            integrity_hash: CryptoHash(vec![]),
        }
    }
}

impl ValidatedPoolReader<TestArtifact> for TestConsensus {
    fn contains(&self, _id: &<TestArtifact as ArtifactKind>::Id) -> bool {
        unimplemented!("Contains is not needed.")
    }
    fn get_validated_by_identifier(
        &self,
        id: &<TestArtifact as ArtifactKind>::Id,
    ) -> Option<<TestArtifact as ArtifactKind>::Message> {
        let mut id = id.clone();
        id.resize(self.message_size, 0);

        Some(id)
    }
    fn get_all_validated_by_filter(
        &self,
        _filter: &<TestArtifact as ArtifactKind>::Filter,
    ) -> Box<dyn Iterator<Item = <TestArtifact as ArtifactKind>::Message> + '_> {
        Box::new(std::iter::empty())
    }
}

impl PriorityFnAndFilterProducer<TestArtifact, TestConsensus> for TestConsensus {
    /// Evaluates to drop iff this node produced it originally or it is older than `RELAY_LIFETIME`
    fn get_priority_function(
        &self,
        _pool: &TestConsensus,
    ) -> ic_types::artifact::PriorityFn<
        <TestArtifact as ArtifactKind>::Id,
        <TestArtifact as ArtifactKind>::Attribute,
    > {
        let node_id = self.node_id;
        let log = self.log.clone();
        Box::new(move |id, _attribute| {
            // let message_id = u64::from_le_bytes(id[..8].try_into().unwrap());
            let artifact_producer_node_id = u64::from_le_bytes(id[8..16].try_into().unwrap());
            let message_is_relayed_back = artifact_producer_node_id == node_id;

            if message_is_relayed_back {
                Priority::Drop
            } else {
                Priority::Fetch
            }
            // let expiry_time_secs = u64::from_le_bytes(id[16..24].try_into().unwrap());

            // let expiry_time = UNIX_EPOCH
            //     .checked_add(Duration::from_secs(expiry_time_secs))
            //     .unwrap();

            // if expiry_time <= SystemTime::now() {
            //     Priority::Drop
            // } else {
            //     Priority::Fetch
            // }
        })
    }
    fn get_filter(&self) -> <TestArtifact as ArtifactKind>::Filter {
        <TestArtifact as ArtifactKind>::Filter::default()
    }
}

#[derive(Clone)]
pub struct TestConsensus {
    log: ReplicaLogger,
    message_size: usize,
    node_id: u64,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    id: u64,

    #[arg(long)]
    message_size: usize,

    #[arg(long)]
    message_rate: u64,

    #[arg(long)]
    port: u16,

    #[arg(long)]
    metrics_port: u16,

    #[arg(long)]
    libp2p: bool,

    #[arg(long)]
    relaying: bool,

    #[arg(long, value_delimiter = ' ', num_args = 1..)]
    peers_addrs: Vec<SocketAddr>,
}

struct Metrics {
    received_bytes: IntCounter,
    received_bytes_previous: AtomicU64,

    received_artifact_count: IntCounter,
    received_artifact_count_previous: AtomicU64,

    message_latency: Histogram,

    sent_artifacts: IntCounter,
    sent_artifacts_last: AtomicU64,
}

async fn load_generator(
    node_id: u64,
    log: ReplicaLogger,
    artifact_processor_rx: tokio::sync::mpsc::Sender<ArtifactProcessorEvent<TestArtifact>>,
    received_artifacts: crossbeam_channel::Receiver<UnvalidatedArtifactMutation<TestArtifact>>,
    message_rate: usize,
    relaying: bool,
    metrics: Arc<Metrics>,
    mut rps_rx: watch::Receiver<usize>,
) {
    let (tx, mut received_artifacts_rx) = tokio::sync::mpsc::channel(1000);

    let _join_handle = {
        let log = log.clone();

        std::thread::spawn(move || {
            while let Ok(message) = received_artifacts.recv() {
                tx.blocking_send(message).unwrap();
            }
            error!(log, "Workload thread exited");
        })
    };

    let mut purge_queue: DelayQueue<Advert<TestArtifact>> = DelayQueue::new();

    let mut produce_and_send_artifact = tokio::time::interval(
        Duration::from_secs(1)
            .checked_div(*rps_rx.borrow() as u32)
            .unwrap_or(Duration::from_secs(1000000)),
    );

    // Calculated such that not exceed 20000 active adverts
    // let removal_delay_secs = 20000 / message_rate as u64;
    // let ggggggggggggg = Duration::from_secs(removal_delay_secs);
    // info!(log, "Using removal delay of {removal_delay_secs}s");

    info!(
        log,
        "Generating event every {:?}",
        produce_and_send_artifact.period()
    );
    let mut log_interval = tokio::time::interval(Duration::from_secs(30));

    let mut received_bytes = 0;
    let mut received_artifact_count: u64 = 0;
    let mut sent_artifacts: u64 = 0;

    loop {
        select! {
            // Incoming Artifact from peers
            Some(artifact) = received_artifacts_rx.recv()=> {
                match artifact {
                    UnvalidatedArtifactMutation::<TestArtifact>::Insert((message, _peer)) => {

                        received_artifact_count += 1;
                        received_bytes += message.len();
                        metrics
                            .received_bytes
                            .inc_by(message.len() as u64);
                        metrics.received_artifact_count.inc();

                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                        let latency = now - Duration::from_secs_f64(f64::from_le_bytes(message[16..24].try_into().unwrap()));
                        metrics.message_latency.observe(latency.as_secs_f64());

                        if relaying {
                            // purge_queue.insert(TestArtifact::message_to_advert(&message), Duration::from_secs(60));
                            match artifact_processor_rx.send(ArtifactProcessorEvent::Advert((TestArtifact::message_to_advert(&message),false))).await {
                                Ok(_) => {},
                                Err(e) => {
                                    error!(log, "Artifact processor failed to send relay: {:?}", e);
                                }
                            };
                        }
                    }
                    _ => {
                    }
                }
            }
            Ok(()) = rps_rx.changed() => {
                produce_and_send_artifact = tokio::time::interval(
                    Duration::from_secs(1)
                        .checked_div(*rps_rx.borrow() as u32)
                        .unwrap_or(Duration::from_secs(u64::MAX)),
                );
                info!(
                    log,
                    "Generating event every {:?}",
                    produce_and_send_artifact.period()
                );
            }
            // Outgoing Artifact to peers
            _ = produce_and_send_artifact.tick() => {

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

                let mut id = Vec::with_capacity(16);
                id.extend_from_slice(&sent_artifacts.to_le_bytes());
                id.extend_from_slice(&node_id.to_le_bytes());
                id.extend_from_slice(&now.to_le_bytes());
                metrics.sent_artifacts.inc();

                // purge_queue.insert(TestArtifact::message_to_advert(&id), Duration::from_secs(60));

                match artifact_processor_rx
                    .send(ArtifactProcessorEvent::Advert((TestArtifact::message_to_advert(&id),true)))
                    .await {
                        Ok(_) => {},
                        Err(e) => {
                            error!(log, "Artifact processor failed to send advert: {:?}", e);
                        }

                    };

                sent_artifacts += 1;

            }
            _ = log_interval.tick() => {
                info!(log, "Sent artifacts total {}", metrics.sent_artifacts.get());
                info!(log, "Received artifacts total {}", metrics.received_artifact_count.get());
            }
            Some(n) = purge_queue.next() => {
                let _ = artifact_processor_rx.send(ArtifactProcessorEvent::Purge(n.into_inner().id)).await.unwrap();
            }
        }
    }
}

async fn metrics_handler(
    State(metrics): State<(
        Arc<Mutex<prometheus_client::registry::Registry>>,
        MetricsRegistry,
    )>,
) -> String {
    let encoder = TextEncoder::new();
    let mut encoded_metrics1 = encoder
        .encode_to_string(&metrics.1.prometheus_registry().gather())
        .unwrap();

    let mut buffer = String::new();
    let p_metrics = metrics.0.lock().unwrap();
    prometheus_client::encoding::text::encode(&mut buffer, &p_metrics).unwrap();
    encoded_metrics1.push_str(&buffer);
    encoded_metrics1
}

async fn libp2p_metrics_handler(
    State(metrics): State<Arc<Mutex<prometheus_client::registry::Registry>>>,
) -> String {
    let mut buffer = String::new();
    let metrics = metrics.lock().unwrap();
    prometheus_client::encoding::text::encode(&mut buffer, &metrics).unwrap();

    buffer
}

async fn pprof_handler(State(collector): State<Arc<Pprof>>) -> impl IntoResponse {
    let flame = collector
        .flamegraph(Duration::from_secs(5), 250)
        .await
        .unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderValue::from_static("image/svg+xml"),
        )],
        flame,
    )
}

async fn cm_metrics_handler(State(metrics): State<MetricsRegistry>) -> String {
    let encoder = TextEncoder::new();
    let metrics = encoder
        .encode_to_string(&metrics.prometheus_registry().gather())
        .unwrap();
    metrics
}

async fn interval_handler(State(w): State<Arc<tokio::sync::watch::Sender<usize>>>, msg: String) {
    let rps = msg.parse::<usize>().unwrap();
    w.send(rps);
}

fn peerid_to_nodeid(p: PeerId) -> NodeId {
    let s = p.to_bytes().into_iter().fold(0_u64, |mut acc, x| {
        acc += x as u64;
        acc
    });
    node_test_id(s)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // TODO: some input verification
    let rt_handle = tokio::runtime::Handle::current();
    let metrics_reg = MetricsRegistry::default();

    let sent_artifacts = metrics_reg.int_counter("load_generator_sent_artifacts", "TODO");
    let received_artifacts = metrics_reg.int_counter("load_generator_received_artifacts", "TODO");
    let received_artifacts_bytes =
        metrics_reg.int_counter("load_generator_received_artifacts_bytes", "TODO");
    let message_latency = metrics_reg.histogram(
        "load_generator_message_latency",
        "TODO",
        decimal_buckets(-2, 0),
    );

    let metrics = Arc::new(Metrics {
        received_bytes: received_artifacts_bytes,
        sent_artifacts,
        received_artifact_count: received_artifacts,
        message_latency,
        received_bytes_previous: AtomicU64::default(),
        received_artifact_count_previous: AtomicU64::default(),
        sent_artifacts_last: AtomicU64::default(),
    });

    let (log, _async_log_guard) =
        new_replica_logger_from_config(&ic_config::logger::Config::default());

    let (artifact_processor_tx, artifact_processor_rx) = tokio::sync::mpsc::channel(100000);
    let (cb_tx, cb_rx) = crossbeam_channel::unbounded();

    let test_consensus = TestConsensus {
        log: log.clone(),
        message_size: args.message_size,
        node_id: args.id,
    };
    let transport_addr: SocketAddr =
        (IpAddr::from_str("0.0.0.0").expect("Invalid IP"), args.port).into();

    let mut peers_addrs = args.peers_addrs;
    peers_addrs.insert(args.id as usize, transport_addr);

    let registry = Arc::new(Mutex::new(prometheus_client::registry::Registry::default()));

    if args.libp2p {
        start_libp2p(
            log.clone(),
            rt_handle.clone(),
            args.id,
            peers_addrs,
            transport_addr,
            test_consensus,
            cb_tx,
            artifact_processor_rx,
            registry.clone(),
        );
    } else {
        println!("CONSENSUS_MANAGRE");
        start_cm(
            log.clone(),
            rt_handle.clone(),
            args.id,
            peers_addrs,
            transport_addr,
            test_consensus,
            cb_tx,
            artifact_processor_rx,
            metrics_reg.clone(),
        );
    }

    let (rps_tx, rps_rx) = tokio::sync::watch::channel(0);

    rt_handle.spawn(load_generator(
        args.id,
        log.clone(),
        artifact_processor_tx,
        cb_rx,
        args.message_rate as usize,
        args.relaying,
        metrics.clone(),
        rps_rx,
    ));

    let metrics_address: SocketAddr = (
        IpAddr::from_str("0.0.0.0").expect("Invalid IP"),
        args.metrics_port,
    )
        .into();

    let metric_listener = tokio::net::TcpListener::bind(metrics_address)
        .await
        .expect("Unable to bind metrics listener.");
    let pprof = Arc::new(Pprof);

    let metrics_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state((registry.clone(), metrics_reg.clone()))
        .route("/libp2pmetrics", get(libp2p_metrics_handler))
        .with_state(registry)
        .route("/setrate", post(interval_handler))
        .with_state(Arc::new(rps_tx))
        .route("/cmmetrics", get(cm_metrics_handler))
        .with_state(metrics_reg)
        .route("/flamegraph", get(pprof_handler))
        .with_state(pprof);

    axum::serve(metric_listener, metrics_router).await.unwrap();
}

fn start_cm(
    log: ReplicaLogger,
    rt_handle: Handle,
    id: u64,
    peers_addrs: Vec<SocketAddr>,
    transport_addr: SocketAddr,
    test_consensus: TestConsensus,
    cb_tx: crossbeam_channel::Sender<UnvalidatedArtifactMutation<TestArtifact>>,
    mut ap_rx: tokio::sync::mpsc::Receiver<ArtifactProcessorEvent<TestArtifact>>,
    metrics: MetricsRegistry,
) {
    // generate deterministic crypto based on id
    let mut seeded_rng = ChaCha20Rng::seed_from_u64(id);
    let node_id = node_test_id(id);
    let cert = CertWithPrivateKey::builder()
        .cn(node_id.to_string())
        .build_ed25519(&mut seeded_rng);

    let mut new_p2p_consensus = ic_consensus_manager::ConsensusManagerBuilder::new(
        log.clone(),
        rt_handle.clone(),
        metrics.clone(),
    );
    let mut topology: Vec<(NodeId, SocketAddr)> = peers_addrs
        .into_iter()
        .enumerate()
        .map(|(id, v)| {
            let node_id = node_test_id(id as u64);
            (node_id, v)
        })
        .collect();
    let (tx, watcher) =
        tokio::sync::watch::channel(SubnetTopology::new(Vec::new(), 1.into(), 2.into()));

    new_p2p_consensus.add_client(
        ap_rx,
        Arc::new(RwLock::new(test_consensus.clone())) as Arc<_>,
        Arc::new(test_consensus.clone()) as Arc<_>,
        cb_tx,
    );

    info!(log, "Running on {:?} with id {}", transport_addr, node_id);
    info!(log, "Connecting to {:?}", watcher);
    let tls = TlsConfigImpl {
        cert: Certificate(cert.cert_der()),
        private: PrivateKey(cert.key_pair().serialize_for_rustls()),
    };
    let quic_transport = Arc::new(ic_quic_transport::QuicTransport::start(
        &log,
        &metrics,
        &rt_handle,
        Arc::new(tls) as Arc<_>,
        Arc::new(MockReg) as Arc<_>,
        Arc::new(SevImpl) as Arc<_>,
        node_id,
        watcher.clone(),
        Either::<_, DummyUdpSocket>::Left(transport_addr),
        new_p2p_consensus.router(),
    ));
    new_p2p_consensus.run(quic_transport, watcher);

    let _ = tx
        .send(SubnetTopology::new(topology, 1.into(), 2.into()))
        .unwrap();
}

fn start_libp2p(
    log: ReplicaLogger,
    rt_handle: Handle,
    id: u64,
    peers_addrs: Vec<SocketAddr>,
    transport_addr: SocketAddr,
    pool: TestConsensus,
    cb_tx: crossbeam_channel::Sender<UnvalidatedArtifactMutation<TestArtifact>>,
    mut ap_rx: tokio::sync::mpsc::Receiver<ArtifactProcessorEvent<TestArtifact>>,
    metrics_registry: Arc<Mutex<prometheus_client::registry::Registry>>,
) {
    let sk: [u8; 32] = [id as u8; 32];
    let libp2p_sk = libp2p::identity::ed25519::SecretKey::try_from_bytes(sk).unwrap();
    let libp2p_kp = libp2p::identity::ed25519::Keypair::from(libp2p_sk);
    let node_id = peerid_to_nodeid(PeerId::from_public_key(&libp2p::identity::PublicKey::from(
        libp2p_kp.public(),
    )));
    let peer_id = PeerId::from_public_key(&libp2p::identity::PublicKey::from(libp2p_kp.public()));

    let mut topology: Vec<(NodeId, PeerId, SocketAddr)> = peers_addrs
        .into_iter()
        .enumerate()
        .map(|(id, v)| {
            let sk: [u8; 32] = [id as u8; 32];
            let libp2p_sk = libp2p::identity::ed25519::SecretKey::try_from_bytes(sk).unwrap();
            let libp2p_kp = libp2p::identity::ed25519::Keypair::from(libp2p_sk);
            let node_id = peerid_to_nodeid(PeerId::from_public_key(
                &libp2p::identity::PublicKey::from(libp2p_kp.public()),
            ));
            (
                node_id,
                PeerId::from_public_key(&libp2p::identity::PublicKey::from(libp2p_kp.public())),
                v,
            )
        })
        .collect();

    info!(
        log,
        "Running libp2p on {:?} with id {} {:?}", transport_addr, node_id, peer_id,
    );

    let mut metrics_registry = metrics_registry.lock().unwrap();
    let mut swarm = SwarmBuilder::with_existing_identity(libp2p_kp.clone().into())
        .with_tokio()
        .with_quic_config(|mut cfg| {
            // ms
            cfg.max_idle_timeout = 1_000_000;
            cfg.max_connection_data = 1_000_000_000;
            cfg.max_concurrent_stream_limit = 1000;
            cfg.handshake_timeout = Duration::from_secs(100000);
            cfg
        })
        // .with_tcp(
        //     libp2p::tcp::Config::default(),
        //     libp2p::noise::Config::new,
        //     libp2p::yamux::Config::default,
        // )
        // .unwrap()
        .with_bandwidth_metrics(&mut metrics_registry)
        .with_behaviour(|_| MainBehaviour {
            gossip_sub: libp2p::gossipsub::Behaviour::new_with_metrics(
                libp2p::gossipsub::MessageAuthenticity::Signed(libp2p_kp.clone().into()),
                libp2p::gossipsub::ConfigBuilder::default()
                    .max_transmit_size(20 * 1024 * 1024)
                    .published_message_ids_cache_time(Duration::from_secs(180))
                    .flood_publish(true)
                    // .max_ihave_length(30000)
                    // .mesh_outbound_min(1)
                    // .mesh_n_low(2)
                    // .mesh_n(3)
                    // .mesh_n_high(4)
                    .message_id_fn(|x| libp2p::gossipsub::MessageId(x.data[0..24].to_vec()))
                    .validate_messages()
                    .build()
                    .unwrap(),
                &mut metrics_registry,
                libp2p::gossipsub::MetricsConfig::default(),
            )
            .unwrap(),
        })
        .unwrap()
        .with_swarm_config(|mut cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    rt_handle.spawn(async move {
        let ip_addr = match transport_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(v6) => panic!("AH"),
        };
        let multiaddr = Multiaddr::empty()
            .with(libp2p::multiaddr::Protocol::Ip4(ip_addr))
            // .with(libp2p::multiaddr::Protocol::Tcp(transport_addr.port()));
            .with(libp2p::multiaddr::Protocol::Udp(transport_addr.port()))
            .with(libp2p::multiaddr::Protocol::QuicV1);
        info!(log, "Listenting on my multi {:?}", multiaddr);
        swarm.listen_on(multiaddr).unwrap();

        swarm
            .behaviour_mut()
            .gossip_sub
            .subscribe(&IdentTopic::new("exp"))
            .unwrap();

        fn handle_swarm_event(
            log: &ReplicaLogger,
            swarm: &mut Swarm<MainBehaviour>,
            topology: &Vec<(NodeId, PeerId, SocketAddr)>,
            event: SwarmEvent<MainBehaviourEvent>,
            cb_tx: &crossbeam_channel::Sender<UnvalidatedArtifactMutation<TestArtifact>>,
        ) {
            if !matches!(event, SwarmEvent::Behaviour(_)) {
                info!(log, "libp2p event {:?}", event);
            }
            match event {
                SwarmEvent::Behaviour(MainBehaviourEvent::GossipSub(
                    libp2p::gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    },
                )) => match message.topic.into_string() {
                    x if x == "exp" => {
                        let peer_id = peerid_to_nodeid(propagation_source);
                        let msg = message.data;
                        cb_tx
                            .send(UnvalidatedArtifactMutation::Insert((msg, peer_id)))
                            .unwrap();
                    }
                    _ => {
                        unreachable!()
                    }
                },
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                    cause,
                } => {}
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                } => {}
                _ => {
                    // todo!()
                }
            }
        }

        async fn handle_advert_send(
            log: &ReplicaLogger,
            swarm: &mut Swarm<MainBehaviour>,
            msg: ArtifactProcessorEvent<TestArtifact>,
            pool: &TestConsensus,
        ) {
            match msg {
                ArtifactProcessorEvent::Advert((advert,_)) => {
                    let id = advert.id.clone();
                    let pool = pool.clone();
                    let artifact =
                        tokio::task::spawn_blocking(move || pool.get_validated_by_identifier(&id))
                            .await;

                    let a = match artifact {
                        Ok(Some(artifact)) => artifact,
                        _ => return,
                    };

                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossip_sub
                        .publish(IdentTopic::new("exp"), a)
                    {
                        info!(log, "Publish err {e:?}");
                    }
                }
                _ => {}
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            select! {
                _ = interval.tick() => {
                    info!(log, "NUM Connected peers {} {} {}", swarm.connected_peers().count(), swarm.behaviour().gossip_sub.all_peers().count(), swarm.behaviour().gossip_sub.all_mesh_peers().count());
                    let connected: HashSet<_> = swarm.connected_peers().cloned().collect();
                    for (n,p,s) in &topology {
                        if !connected.contains(p) && n != &node_id{
                            let ip_addr = match s {
                                SocketAddr::V4(v4) => *v4.ip(),
                                SocketAddr::V6(v6) => panic!("AH"),
                            };
                    info!(log, "CONNECTING");
                            swarm
                                .dial(
                                    Multiaddr::empty()
                                        .with(libp2p::multiaddr::Protocol::Ip4(ip_addr))
                                        // .with(libp2p::multiaddr::Protocol::Tcp(transport_addr.port()))
                                        .with(libp2p::multiaddr::Protocol::Udp(transport_addr.port()))
                                        .with(libp2p::multiaddr::Protocol::QuicV1)
                                )
                                .unwrap()
                        }

                    }

                }
                Some(event) = swarm.next() => {
                    handle_swarm_event(&log, &mut swarm, &topology, event, &cb_tx);
                }
                Some(msg) = ap_rx.recv(), if swarm.connected_peers().count() > 0 => {
                    handle_advert_send(&log, &mut swarm, msg, &pool).await;
                }
            }
        }
    });
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct MainBehaviour {
    gossip_sub: libp2p::gossipsub::Behaviour,
}

struct SevImpl;

#[async_trait::async_trait]
impl<S> ValidateAttestedStream<S> for SevImpl
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn perform_attestation_validation(
        &self,
        stream: S,
        _peer: NodeId,
        _registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        Ok(stream)
    }
}

struct TlsConfigImpl {
    pub cert: Certificate,
    pub private: PrivateKey,
}

impl TlsConfig for TlsConfigImpl {
    fn server_config_without_client_auth(
        &self,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<ServerConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        todo!()
    }
    fn server_config(
        &self,
        _allowed_clients: ic_crypto_tls_interfaces::SomeOrAllNodes,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<ServerConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        Ok(ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(NoClientAuth))
            .with_single_cert(vec![self.cert.clone()], self.private.clone())
            .unwrap())
    }
    fn client_config(
        &self,
        _server: NodeId,
        _registry_version: ic_types::RegistryVersion,
    ) -> Result<ClientConfig, ic_crypto_tls_interfaces::TlsConfigError> {
        Ok(ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoServerAuth))
            .with_client_auth_cert(vec![self.cert.clone()], self.private.clone())
            .unwrap())
    }
}

struct NoClientAuth;

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn client_auth_root_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::Certificate,
        _intermediates: &[tokio_rustls::rustls::Certificate],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::server::ClientCertVerified, tokio_rustls::rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
}

struct NoServerAuth;

impl ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

struct MockReg;

impl RegistryClient for MockReg {
    fn get_latest_version(&self) -> ic_types::RegistryVersion {
        1.into()
    }
    fn get_versioned_value(
        &self,
        _key: &str,
        _version: ic_types::RegistryVersion,
    ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
        todo!()
    }
    fn get_key_family(
        &self,
        _key_prefix: &str,
        _version: ic_types::RegistryVersion,
    ) -> Result<Vec<String>, ic_types::registry::RegistryClientError> {
        todo!()
    }
    fn get_value(
        &self,
        _key: &str,
        _version: ic_types::RegistryVersion,
    ) -> ic_interfaces_registry::RegistryClientResult<Vec<u8>> {
        todo!()
    }
    fn get_version_timestamp(
        &self,
        _registry_version: ic_types::RegistryVersion,
    ) -> Option<ic_types::Time> {
        todo!()
    }
}
