use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{any, get},
    Router,
};
use clap::Parser;
use either::Either;
use futures::StreamExt;
use ic_crypto_test_utils_tls::x509_certificates::CertWithPrivateKey;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_icos_sev::{ValidateAttestationError, ValidateAttestedStream};
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent,
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info, new_replica_logger_from_config, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_quic_transport::{DummyUdpSocket, SubnetTopology};
use ic_types::{
    artifact::{Advert, ArtifactKind, ArtifactTag, Priority, UnvalidatedArtifactMutation},
    crypto::CryptoHash,
    NodeId, RegistryVersion,
};
use ic_types_test_utils::ids::node_test_id;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select,
};
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    server::{ClientCertVerified, ClientCertVerifier},
    Certificate, ClientConfig, PrivateKey, ServerConfig,
};
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
        // let id = u64::from_le_bytes(msg[..24].try_into().unwrap());
        let id = msg[..16].into();
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
    relaying: bool,

    #[arg(long, value_delimiter = ' ', num_args = 1..)]
    peers_addrs: Vec<SocketAddr>,
}

#[derive(Default)]
struct Metrics {
    received_bytes: AtomicU64,
    received_bytes_previous: AtomicU64,

    received_artifact_count: AtomicU64,
    received_artifact_count_previous: AtomicU64,

    sent_artifacts: AtomicU64,
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

    // let mut purge_queue: DelayQueue<Advert<TestArtifact>> = DelayQueue::new();

    let mut produce_and_send_artifact = tokio::time::interval(
        Duration::from_secs(1)
            .checked_div(message_rate as u32)
            .unwrap(),
    );

    // Calculated such that not exceed 20000 active adverts
    let removal_delay_secs = 20000 / message_rate as u64;
    let removal_delay = Duration::from_secs(removal_delay_secs);
    info!(log, "Using removal delay of {removal_delay_secs}s");

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

                        if relaying {
                            // let expiry_time_secs = u64::from_le_bytes(message[16..24].try_into().unwrap());

                            // let removal_delay = UNIX_EPOCH
                            //     .checked_add(Duration::from_secs(expiry_time_secs))
                            //     .unwrap()
                            //     .elapsed();

                            // if let Ok(removal_delay) = removal_delay {
                                // purge_queue.insert(TestArtifact::message_to_advert(&message), removal_delay);
                                match artifact_processor_rx.send(ArtifactProcessorEvent::Advert(TestArtifact::message_to_advert(&message))).await {
                                    Ok(_) => {},
                                    Err(e) => {
                                        error!(log, "Artifact processor failed to send relay: {:?}", e);
                                    }
                                };
                            // }
                        }
                    }
                    _ => {
                    }
                }
            }
            // Outgoing Artifact to peers
            _ = produce_and_send_artifact.tick() => {

                // let expiry_time = SystemTime::now().checked_add(removal_delay).unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();

                let mut id = Vec::with_capacity(16);
                id.extend_from_slice(&sent_artifacts.to_le_bytes());
                id.extend_from_slice(&node_id.to_le_bytes());
                // id.extend_from_slice(&expiry_time.to_le_bytes());

                // purge_queue.insert(TestArtifact::message_to_advert(&id), removal_delay);

                match artifact_processor_rx
                    .send(ArtifactProcessorEvent::Advert(TestArtifact::message_to_advert(&id)))
                    .await {
                        Ok(_) => {},
                        Err(e) => {
                            error!(log, "Artifact processor failed to send advert: {:?}", e);
                        }

                    };

                sent_artifacts += 1;

            }
            _ = log_interval.tick() => {
                info!(log, "Sent artifacts total {}", sent_artifacts as u64 - metrics.sent_artifacts.load(Relaxed));
                info!(log, "Rate of message sent {}", (sent_artifacts as u64 - metrics.sent_artifacts.load(Relaxed))/30);
                info!(log, "Rate of messages received {}", (received_artifact_count as u64 - metrics.received_artifact_count.load(Relaxed))/30);
                info!(log, "Rate of bytes received {}", (received_bytes as u64 - metrics.received_bytes.load(Relaxed))/30);
            }
            // Some(n) = purge_queue.next() => {
            //     let _ = artifact_processor_rx.send(ArtifactProcessorEvent::Purge(n.into_inner().id)).await.unwrap();
            // }
        }
        metrics
            .received_bytes
            .store(received_bytes.try_into().unwrap(), Relaxed);

        metrics
            .received_artifact_count
            .store(received_artifact_count, Relaxed);

        metrics.sent_artifacts.store(sent_artifacts, Relaxed);
    }
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> String {
    format!(
        "{}, {}, {}",
        metrics.received_bytes.load(Relaxed),
        metrics.received_artifact_count.load(Relaxed),
        metrics.sent_artifacts.load(Relaxed)
    )
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // generate deterministic crypto based on id
    let mut seeded_rng = ChaCha20Rng::seed_from_u64(args.id);
    let node_id_u64 = seeded_rng.gen_range(0..u64::MAX);
    let node_id = node_test_id(node_id_u64);
    let cert = CertWithPrivateKey::builder()
        .cn(node_id.to_string())
        .build_ed25519(&mut seeded_rng);

    // TODO: some input verification

    let rt_handle = tokio::runtime::Handle::current();
    let metrics = Arc::new(Metrics::default());

    let (log, _async_log_guard) =
        new_replica_logger_from_config(&ic_config::logger::Config::default());

    let mut new_p2p_consensus = ic_consensus_manager::ConsensusManagerBuilder::new(
        log.clone(),
        rt_handle.clone(),
        MetricsRegistry::default(),
    );

    let (artifact_processor_tx, artifact_processor_rx) = tokio::sync::mpsc::channel(100000);
    let (cb_tx, cb_rx) = crossbeam_channel::unbounded();

    let test_consensus = TestConsensus {
        log: log.clone(),
        message_size: args.message_size,
        node_id: node_id_u64,
    };

    new_p2p_consensus.add_client(
        artifact_processor_rx,
        Arc::new(RwLock::new(test_consensus.clone())) as Arc<_>,
        Arc::new(test_consensus.clone()) as Arc<_>,
        cb_tx,
    );
    let transport_addr: SocketAddr =
        (IpAddr::from_str("0.0.0.0").expect("Invalid IP"), args.port).into();

    let mut peers_addrs = args.peers_addrs;
    peers_addrs.insert(args.id as usize, transport_addr);

    let mut topology: Vec<(NodeId, SocketAddr)> = peers_addrs
        .into_iter()
        .enumerate()
        .map(|(id, v)| {
            let mut seeded_rng = ChaCha20Rng::seed_from_u64(id as u64);
            let node_id = node_test_id(seeded_rng.gen_range(0..u64::MAX));
            (node_id, v)
        })
        .collect();
    let (tx, watcher) =
        tokio::sync::watch::channel(SubnetTopology::new(Vec::new(), 1.into(), 2.into()));

    error!(log, "test error");

    info!(log, "Running on {:?} with id {}", transport_addr, node_id);
    info!(log, "Connecting to {:?}", watcher);
    let tls = TlsConfigImpl {
        cert: Certificate(cert.cert_der()),
        private: PrivateKey(cert.key_pair().serialize_for_rustls()),
    };
    let quic_transport = Arc::new(ic_quic_transport::QuicTransport::start(
        &log,
        &MetricsRegistry::default(),
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

    rt_handle.spawn(load_generator(
        node_id_u64,
        log.clone(),
        artifact_processor_tx,
        cb_rx,
        args.message_rate as usize,
        args.relaying,
        metrics.clone(),
    ));

    let _ = tx
        .send(SubnetTopology::new(topology, 1.into(), 2.into()))
        .unwrap();

    let metrics_address: SocketAddr = (
        IpAddr::from_str("0.0.0.0").expect("Invalid IP"),
        args.metrics_port,
    )
        .into();

    let metric_listener = tokio::net::TcpListener::bind(metrics_address)
        .await
        .expect("Unable to bind metrics listener.");

    let metrics_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);

    axum::serve(metric_listener, metrics_router).await.unwrap();
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
