use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ethnum::u256;
use ic_bn_lib_common::traits::Run;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_registry_client::client::{RegistryClient, ThresholdSigPublicKey};
use ic_registry_client_helpers::{
    api_boundary_node::ApiBoundaryNodeRegistry,
    crypto::CryptoRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_replicator::RegistryReplicator;
use ic_registry_subnet_type::SubnetType;
use ic_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use rand::seq::SliceRandom;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use url::{ParseError, Url};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    errors::ErrorCause,
    firewall::{FirewallGenerator, SystemdReloader},
    http::RequestType,
    metrics::{MetricParamsSnapshot, WithMetricsSnapshot},
    persist::principal_to_u256,
};

#[derive(Clone, Debug)]
pub struct Node {
    pub id: Principal,
    pub subnet_id: Principal,
    pub subnet_type: SubnetType,
    pub addr: IpAddr,
    pub port: u16,
    pub tls_certificate: Vec<u8>,
    pub avg_latency_secs: f64,
}

// Lightweight Eq, just compare principals
// If one ever needs a deep comparison - this needs to be removed and #[derive(Eq)] used
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Node {}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{:?}]:{:?}", self.addr, self.port)
    }
}

impl Node {
    pub fn build_url(
        &self,
        request_type: RequestType,
        principal: Principal,
    ) -> Result<Url, ParseError> {
        let node_id = &self.id;
        let node_port = &self.port;
        match request_type {
            RequestType::QueryV2 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v2/canister/{principal}/query",
            )),
            RequestType::QueryV3 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v3/canister/{principal}/query",
            )),
            RequestType::CallV2 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v2/canister/{principal}/call",
            )),
            RequestType::CallV3 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v3/canister/{principal}/call",
            )),
            RequestType::CallV4 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v4/canister/{principal}/call",
            )),
            RequestType::ReadStateV2 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v2/canister/{principal}/read_state",
            )),
            RequestType::ReadStateV3 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v3/canister/{principal}/read_state",
            )),
            RequestType::ReadStateSubnetV2 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v2/subnet/{principal}/read_state",
            )),
            RequestType::ReadStateSubnetV3 => Url::from_str(&format!(
                "https://{node_id}:{node_port}/api/v3/subnet/{principal}/read_state",
            )),
            // Some generic error for the requests that shouldn't end up here
            RequestType::Unknown | RequestType::Status => Err(ParseError::Overflow),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApiBoundaryNode {
    pub _id: Principal,
    pub _addr: IpAddr,
    pub _port: u16,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanisterRange {
    pub start: Principal,
    pub end: Principal,
}

impl CanisterRange {
    /// Calculates the length of the range
    pub fn len(&self) -> u256 {
        (principal_to_u256(&self.end) - principal_to_u256(&self.start)) + 1
    }

    /// Returns a list of canister IDs in this range in u256 format
    pub fn canisters(&self) -> Vec<u256> {
        let mut x = principal_to_u256(&self.start);
        let end = principal_to_u256(&self.end);

        let mut r = Vec::with_capacity((end - x).as_usize() + 1);
        while x <= end {
            r.push(x);
            x += 1;
        }

        r
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Subnet {
    pub id: Principal,
    pub subnet_type: SubnetType,
    pub ranges: Vec<CanisterRange>,
    pub nodes: Vec<Arc<Node>>,
    pub replica_version: String,
}

impl Subnet {
    pub fn pick_random_nodes(&self, n: usize) -> Result<Vec<Arc<Node>>, ErrorCause> {
        let nodes = self
            .nodes
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect::<Vec<_>>();

        if nodes.is_empty() {
            return Err(ErrorCause::NoHealthyNodes);
        }

        Ok(nodes)
    }

    // max acceptable number of malicious nodes in a subnet
    pub fn fault_tolerance_factor(&self) -> usize {
        (self.nodes.len() - 1) / 3
    }

    pub fn pick_n_out_of_m_closest(
        &self,
        n: usize,
        m: usize,
    ) -> Result<Vec<Arc<Node>>, ErrorCause> {
        // nodes should already be sorted by latency after persist() invocation
        let m = m.min(self.nodes.len());
        let nodes = &self.nodes[0..m];

        let picked_nodes = nodes
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect::<Vec<_>>();

        if picked_nodes.is_empty() {
            return Err(ErrorCause::NoHealthyNodes);
        }

        Ok(picked_nodes)
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

// TODO remove after decentralization and clean up all loose ends
pub struct SnapshotPersister {
    generator: FirewallGenerator,
    reloader: SystemdReloader,
}

impl SnapshotPersister {
    pub fn new(generator: FirewallGenerator, reloader: SystemdReloader) -> Self {
        Self {
            generator,
            reloader,
        }
    }

    pub fn persist(&self, s: RegistrySnapshot) -> Result<(), Error> {
        self.generator.generate(s)?;
        self.reloader.reload()
    }
}

pub trait Snapshot: Send + Sync {
    fn snapshot(&self) -> Result<SnapshotResult, Error>;
}

#[derive(Clone, Debug)]
pub struct RegistrySnapshot {
    pub version: u64,
    pub timestamp: u64,
    pub nns_public_key: Vec<u8>,
    pub subnets: Vec<Subnet>,
    pub nodes: HashMap<String, Arc<Node>>,
    pub api_bns: Vec<ApiBoundaryNode>,
}

pub struct SnapshotInfo {
    pub version: u64,
    pub subnets: usize,
    pub nodes: usize,
}

pub struct SnapshotInfoPublished {
    pub timestamp: u64,
    pub old: Option<SnapshotInfo>,
    pub new: SnapshotInfo,
}

pub enum SnapshotResult {
    NoNewVersion,
    NotOldEnough(u64),
    Published(SnapshotInfoPublished),
}

#[derive(derive_new::new)]
pub struct Snapshotter {
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    channel_notify: watch::Sender<Option<Arc<RegistrySnapshot>>>,
    registry_client: Arc<dyn RegistryClient>,
    #[new(default)]
    registry_version_available: Mutex<Option<RegistryVersion>>,
    #[new(default)]
    registry_version_published: Mutex<Option<RegistryVersion>>,
    #[new(value = "Mutex::new(Instant::now())")]
    last_version_change: Mutex<Instant>,
    min_version_age: Duration,
    #[new(default)]
    persister: Option<SnapshotPersister>,
}

impl Snapshotter {
    pub fn set_persister(&mut self, persister: SnapshotPersister) {
        self.persister = Some(persister);
    }

    fn get_api_boundary_nodes(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<ApiBoundaryNode>, Error> {
        let node_ids = self
            .registry_client
            .get_api_boundary_node_ids(version)
            .context("unable to get API BN node ids")?;

        let nodes = node_ids
            .into_iter()
            .map(|x| -> Result<_, Error> {
                let node = self
                    .registry_client
                    .get_node_record(x, version)
                    .context("unable to get node record")?
                    .context("node not available")?;

                let http_endpoint = node.http.context("http endpoint not available")?;

                Ok(ApiBoundaryNode {
                    _id: x.get().0,
                    _addr: IpAddr::from_str(http_endpoint.ip_addr.as_str())
                        .context("unable to parse IP address")?,
                    _port: http_endpoint.port as u16,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(nodes)
    }

    // Creates a snapshot of the registry for given version
    fn get_snapshot(&self, version: RegistryVersion) -> Result<RegistrySnapshot, Error> {
        // Get routing table with canister ranges
        let routing_table = self
            .registry_client
            .get_routing_table(version)
            .context("failed to get routing table")? // Result
            .context("routing table not available")?; // Option

        let nns_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .context("failed to get root subnet id")? // Result
            .context("root subnet id not available")?; // Option

        let nns_public_key = self
            .registry_client
            .get_threshold_signing_public_key_for_subnet(nns_subnet_id, version)
            .context("failed to get NNS public key")? // Result
            .context("NNS public key is not available")?; // Option

        let timestamp = self
            .registry_client
            .get_version_timestamp(version)
            .context("Version timestamp is not available")? // Option
            .as_secs_since_unix_epoch();

        // Generate a temporary hash table with subnet_id to canister ranges mapping for later reference
        let mut ranges_by_subnet = HashMap::new();
        for (range, subnet_id) in routing_table {
            let range = CanisterRange {
                start: range.start.get_ref().0,
                end: range.end.get_ref().0,
            };

            ranges_by_subnet
                .entry(subnet_id.as_ref().0)
                .and_modify(|x: &mut Vec<CanisterRange>| x.push(range.clone())) // Make compiler happy
                .or_insert_with(|| vec![range]);
        }

        // Hash to hold node_id->node mapping
        let mut nodes_map = HashMap::new();

        // List of all subnet's IDs
        let subnet_ids = self
            .registry_client
            .get_subnet_ids(version)
            .context("failed to get subnet ids")? // Result
            .context("subnet ids not available")?; // Option

        // Fetch a list of API BNs
        let api_bns = self
            .get_api_boundary_nodes(version)
            .context("unable to get API BNs")?;

        let subnets = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                let subnet = self
                    .registry_client
                    .get_subnet_record(subnet_id, version)
                    .context("failed to get subnet")? // Result
                    .context("subnet not available")?; // Option

                let node_ids = self
                    .registry_client
                    .get_node_ids_on_subnet(subnet_id, version)
                    .context("failed to get node ids")? // Result
                    .context("node ids not available")?; // Option

                let replica_version = self
                    .registry_client
                    .get_replica_version(subnet_id, version)
                    .context("failed to get replica version")? // Result
                    .context("replica version not available")?; // Option

                // If this fails then the libraries are in despair, better to die here
                let subnet_type = SubnetType::try_from(subnet.subnet_type()).unwrap();

                let mut nodes = node_ids
                    .into_iter()
                    .map(|node_id| {
                        let transport_info = self
                            .registry_client
                            .get_node_record(node_id, version)
                            .context("failed to get node record")? // Result
                            .context("transport info not available")?; // Option

                        let http_endpoint =
                            transport_info.http.context("http endpoint not available")?;

                        let cert = self
                            .registry_client
                            .get_tls_certificate(node_id, version)
                            .context("failed to get tls certificate")? // Result
                            .context("tls certificate not available")?; // Option

                        // Try to parse certificate
                        X509Certificate::from_der(cert.certificate_der.as_slice())
                            .context("Unable to parse TLS certificate")?;

                        let node = Node {
                            // init to max, this value is updated with running health checks
                            avg_latency_secs: f64::MAX,
                            id: node_id.as_ref().0,
                            subnet_id: subnet_id.as_ref().0,
                            subnet_type,
                            addr: IpAddr::from_str(http_endpoint.ip_addr.as_str())
                                .context("unable to parse IP address")?,
                            port: http_endpoint.port as u16, // Port is u16 anyway
                            tls_certificate: cert.certificate_der,
                        };
                        let node = Arc::new(node);

                        nodes_map.insert(node.id.to_string(), node.clone());

                        Ok::<Arc<Node>, Error>(node)
                    })
                    .collect::<Result<Vec<Arc<Node>>, Error>>()
                    .context("unable to get nodes")?;

                nodes.sort_by_key(|x| x.id);

                let ranges = ranges_by_subnet
                    .remove(&subnet_id.as_ref().0)
                    .context("unable to find ranges")?;

                let subnet = Subnet {
                    id: subnet_id.as_ref().0,
                    subnet_type,
                    ranges,
                    nodes,
                    replica_version: replica_version.to_string(),
                };

                Ok::<Subnet, Error>(subnet)
            })
            .collect::<Result<Vec<Subnet>, Error>>()
            .context("unable to get subnets")?;

        let der_encoded_nns_key = threshold_sig_public_key_to_der(nns_public_key)
            .context("failed to convert NNS key to DER")?;

        Ok(RegistrySnapshot {
            version: version.get(),
            timestamp,
            nns_public_key: der_encoded_nns_key,
            subnets,
            nodes: nodes_map,
            api_bns,
        })
    }
}

impl Snapshot for Snapshotter {
    fn snapshot(&self) -> Result<SnapshotResult, Error> {
        // Fetch latest available registry version
        let version = self.registry_client.get_latest_version();

        let mut registry_version_available = self.registry_version_available.lock().unwrap();
        let mut last_version_change = self.last_version_change.lock().unwrap();
        let mut registry_version_published = self.registry_version_published.lock().unwrap();

        if *registry_version_available != Some(version) {
            *registry_version_available = Some(version);
            *last_version_change = Instant::now();
        }

        // If we have just started and have no snapshot published then we
        // need to make sure that the registry client has caught up with
        // the latest version before going online.
        if self.published_registry_snapshot.load().is_none() {
            // We check that the versions stop progressing for some period of time
            // and only then allow the initial publishing.
            if last_version_change.elapsed() < self.min_version_age {
                return Ok(SnapshotResult::NotOldEnough(version.get()));
            }
        }

        // Check if we already have this version published
        if *registry_version_published == Some(version) {
            return Ok(SnapshotResult::NoNewVersion);
        }

        // Otherwise create a snapshot
        let snapshot = self.get_snapshot(version)?;

        let result = SnapshotInfoPublished {
            timestamp: snapshot.timestamp,

            old: self
                .published_registry_snapshot
                .load()
                .as_ref()
                .map(|x| SnapshotInfo {
                    version: x.version,
                    subnets: x.subnets.len(),
                    nodes: x.nodes.len(),
                }),

            new: SnapshotInfo {
                version: version.get(),
                subnets: snapshot.subnets.len(),
                nodes: snapshot.nodes.len(),
            },
        };

        // Publish the new snapshot
        let snapshot_arc = Arc::new(snapshot.clone());
        self.published_registry_snapshot
            .store(Some(snapshot_arc.clone()));
        *registry_version_published = Some(version);
        self.channel_notify.send_replace(Some(snapshot_arc));

        // Persist the firewall rules if configured
        if let Some(v) = &self.persister {
            v.persist(snapshot)?;
        }

        Ok(SnapshotResult::Published(result))
    }
}

#[async_trait]
impl<T: Snapshot> Run for WithMetricsSnapshot<T> {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        let r = self.0.snapshot()?;

        match r {
            SnapshotResult::Published(v) => {
                warn!(
                    action = "snapshot",
                    version_old = v.old.as_ref().map(|x| x.version),
                    version_new = v.new.version,
                    nodes_old = v.old.as_ref().map(|x| x.nodes),
                    nodes_new = v.new.nodes,
                    subnets_old = v.old.as_ref().map(|x| x.subnets),
                    subnets_new = v.new.subnets,
                    "New registry snapshot published"
                );

                let MetricParamsSnapshot { version, timestamp } = &self.1;
                version.set(v.new.version as i64);
                timestamp.set(v.timestamp as i64);
            }

            SnapshotResult::NotOldEnough(v) => debug!(
                action = "snapshot",
                "Snapshot {v} is not old enough, not publishing"
            ),

            SnapshotResult::NoNewVersion => {}
        }

        Ok(())
    }
}

/// Wrapper for registry replicator to run it as Task
#[derive(derive_new::new)]
pub struct RegistryReplicatorRunner(RegistryReplicator, Vec<Url>, Option<ThresholdSigPublicKey>);

#[async_trait]
impl Run for RegistryReplicatorRunner {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.0
            .start_polling(self.1.clone(), self.2, token)
            .await
            .context("unable to start polling Registry")?
            .await; // This terminates when `token` is cancelled

        Ok(())
    }
}

// Forked functions from ic-test-utilities to avoid depending on that crate
pub fn subnet_test_id(i: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(i))
}

pub fn node_test_id(i: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(i))
}

pub fn generate_stub_snapshot(subnets: Vec<Subnet>) -> RegistrySnapshot {
    let nodes = subnets
        .iter()
        .flat_map(|x| x.nodes.iter())
        .map(|x| (x.id.to_string(), x.clone()))
        .collect::<HashMap<_, _>>();

    RegistrySnapshot {
        version: 0,
        timestamp: 0,
        nns_public_key: vec![],
        subnets,
        nodes,
        api_bns: vec![],
    }
}

pub fn generate_stub_subnet(nodes: Vec<SocketAddr>) -> Subnet {
    let subnet_id = subnet_test_id(0).get().0;

    let nodes = nodes
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            Arc::new(Node {
                // init to max, this value is updated with running health checks
                avg_latency_secs: f64::MAX,
                id: node_test_id(i as u64).get().0,
                subnet_type: SubnetType::Application,
                subnet_id,
                addr: x.ip(),
                port: x.port(),
                tls_certificate: vec![],
            })
        })
        .collect::<Vec<_>>();

    // Catch-all canister id range
    let range = CanisterRange {
        start: Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        end: Principal::from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    };

    Subnet {
        id: subnet_id,
        subnet_type: SubnetType::Application,
        ranges: vec![range],
        nodes,
        replica_version: "".into(),
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_utils::{
        create_fake_registry_client, valid_tls_certificate_and_validation_time,
    };
    use ic_registry_routing_table::CanisterIdRange;

    #[allow(clippy::type_complexity)]
    pub fn test_registry_snapshot(
        subnets: usize,
        nodes_per_subnet: usize,
    ) -> (
        RegistrySnapshot,
        Vec<(NodeId, String)>,
        Vec<(SubnetId, CanisterIdRange)>,
    ) {
        let snapshot = Arc::new(ArcSwapOption::empty());

        let (reg, nodes, ranges) = create_fake_registry_client(subnets, nodes_per_subnet, None);
        let reg = Arc::new(reg);

        let (channel_send, _) = watch::channel(None);
        let snapshotter = Snapshotter::new(snapshot.clone(), channel_send, reg, Duration::ZERO);
        snapshotter.snapshot().unwrap();

        (
            snapshot.load_full().unwrap().as_ref().clone(),
            nodes,
            ranges,
        )
    }

    #[tokio::test]
    async fn test_routing_table() -> Result<(), Error> {
        let (snapshot, nodes, ranges) = test_registry_snapshot(4, 1);

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.subnets.len(), 4);

        for i in 0..snapshot.subnets.len() {
            let sn = &snapshot.subnets[i];
            assert_eq!(sn.id.to_string(), ranges[i].0.to_string());

            assert_eq!(sn.ranges.len(), 1);
            assert_eq!(
                sn.ranges[0].start.to_string(),
                ranges[i].1.start.to_string()
            );
            assert_eq!(sn.ranges[0].end.to_string(), ranges[i].1.end.to_string());

            assert_eq!(sn.nodes.len(), 1);
            assert_eq!(sn.nodes[0].id.to_string(), nodes[i].0.to_string());
            assert_eq!(sn.nodes[0].addr.to_string(), nodes[i].1);

            assert_eq!(
                sn.nodes[0].tls_certificate,
                valid_tls_certificate_and_validation_time()
                    .0
                    .certificate_der,
            );
        }

        Ok(())
    }
}
