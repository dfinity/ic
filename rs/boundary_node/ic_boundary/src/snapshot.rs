use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ic_registry_client::client::RegistryClient;
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_subnet_type::SubnetType;
use ic_types::RegistryVersion;
use tracing::info;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    core::Run,
    firewall::{FirewallGenerator, SystemdReloader},
};

// Some magical prefix that the public key should have
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: Principal,
    pub subnet_id: Principal,
    pub subnet_type: SubnetType,
    pub addr: IpAddr,
    pub port: u16,
    pub tls_certificate: Vec<u8>,
    pub replica_version: String,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{:?}]:{:?}", self.addr, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanisterRange {
    pub start: Principal,
    pub end: Principal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    pub id: Principal,
    pub subnet_type: SubnetType,
    pub ranges: Vec<CanisterRange>,
    pub nodes: Vec<Node>,
    pub replica_version: String,
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

    pub async fn persist(&self, s: RegistrySnapshot) -> Result<(), Error> {
        self.generator.generate(s)?;
        self.reloader.reload().await
    }
}

#[derive(Debug, Clone)]
pub struct RegistrySnapshot {
    pub registry_version: u64,
    pub nns_subnet_id: Principal,
    pub nns_public_key: Vec<u8>,
    pub subnets: Vec<Subnet>,
    // Hash map for a faster lookup by DNS resolver
    pub nodes: HashMap<String, Node>,
}

pub struct Runner {
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    registry_client: Arc<dyn RegistryClient>,
    registry_version_available: Option<RegistryVersion>,
    registry_version_published: Option<RegistryVersion>,
    last_version_change: Instant,
    min_version_age: Duration,
    persister: Option<SnapshotPersister>,
}

impl Runner {
    pub fn new(
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
        registry_client: Arc<dyn RegistryClient>,
        min_version_age: Duration,
    ) -> Self {
        Self {
            published_registry_snapshot,
            registry_client,
            registry_version_published: None,
            registry_version_available: None,
            last_version_change: Instant::now(),
            min_version_age,
            persister: None,
        }
    }

    pub fn set_persister(&mut self, persister: SnapshotPersister) {
        self.persister = Some(persister);
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
            .context("NNS public is key not available")?; // Option

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

                let nodes = node_ids
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

                        let node_route = Node {
                            id: node_id.as_ref().0,
                            subnet_id: subnet_id.as_ref().0,
                            subnet_type,
                            addr: IpAddr::from_str(http_endpoint.ip_addr.as_str())
                                .context("unable to parse IP address")?,
                            port: http_endpoint.port as u16, // Port is u16 anyway
                            tls_certificate: cert.certificate_der,
                            replica_version: replica_version.to_string(),
                        };

                        nodes_map.insert(node_route.id.to_string(), node_route.clone());
                        let out: Result<Node, Error> = Ok(node_route);
                        out
                    })
                    .collect::<Result<Vec<Node>, Error>>()
                    .context("unable to get nodes")?;

                let ranges = ranges_by_subnet
                    .remove(&subnet_id.as_ref().0)
                    .context("unable to find ranges")?;

                let subnet_route = Subnet {
                    id: subnet_id.as_ref().0,
                    subnet_type,
                    ranges,
                    nodes,
                    replica_version: replica_version.to_string(),
                };

                let out: Result<Subnet, Error> = Ok(subnet_route);
                out
            })
            .collect::<Result<Vec<Subnet>, Error>>()
            .context("unable to get subnets")?;

        let mut nns_key_with_prefix = DER_PREFIX.to_vec();
        nns_key_with_prefix.extend_from_slice(&nns_public_key.into_bytes());

        Ok(RegistrySnapshot {
            registry_version: version.get(),
            nns_subnet_id: nns_subnet_id.get().0,
            nns_public_key: nns_key_with_prefix,
            subnets,
            nodes: nodes_map,
        })
    }
}

#[async_trait]
impl Run for Runner {
    async fn run(&mut self) -> Result<(), Error> {
        // Fetch latest available registry version
        let version = self.registry_client.get_latest_version();

        if self.registry_version_available != Some(version) {
            self.registry_version_available = Some(version);
            self.last_version_change = Instant::now();
        }

        // If we have just started and have no snapshot published then we
        // need to make sure that the registry client has caught up with
        // the latest version before going online.
        if self.published_registry_snapshot.load().is_none() {
            // We check that the versions stop progressing for some period of time
            // and only then allow the initial publishing.
            if self.last_version_change.elapsed() < self.min_version_age {
                info!(
                    action = "snapshot",
                    "Snapshot {version} is not old enough, not publishing"
                );
                return Ok(());
            }
        }

        // Check if we already have this version published
        if self.registry_version_published == Some(version) {
            return Ok(());
        }

        // Otherwise create a snapshot & publish it
        let snapshot = self.get_snapshot(version)?;

        self.published_registry_snapshot
            .store(Some(Arc::new(snapshot.clone())));

        info!(
            action = "snapshot",
            version_old = self.registry_version_published.map(|x| x.get()),
            version_new = version.get(),
            nodes = snapshot.nodes.len(),
            subnets = snapshot.subnets.len(),
            "New registry snapshot published"
        );

        self.registry_version_published = Some(version);

        // Persist the firewall rules if configured
        if let Some(v) = &self.persister {
            v.persist(snapshot).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test;
