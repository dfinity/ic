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
use std::{collections::HashMap, fmt, net::IpAddr, str::FromStr, sync::Arc};
use tracing::info;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    core::Run,
    firewall::{FirewallGenerator, SystemdReloader},
};

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
    pub subnets: Vec<Subnet>,
    // Hash map for a faster lookup by DNS resolver
    pub nodes: HashMap<String, Node>,
}

pub struct Runner {
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    registry_client: Arc<dyn RegistryClient>,
    registry_version: Option<RegistryVersion>,
    persister: Option<SnapshotPersister>,
}

impl Runner {
    pub fn new(
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
        registry_client: Arc<dyn RegistryClient>,
    ) -> Self {
        Self {
            published_registry_snapshot,
            registry_client,
            registry_version: None,
            persister: None,
        }
    }

    pub fn set_persister(&mut self, persister: SnapshotPersister) {
        self.persister = Some(persister);
    }

    // Creates a snapshot of the registry for given version
    fn get_snapshot(&mut self, version: RegistryVersion) -> Result<RegistrySnapshot, Error> {
        // Get routing table with canister ranges
        let routing_table = self
            .registry_client
            .get_routing_table(version)
            .context("failed to get routing table")? // Result
            .context("routing table not available")?; // Option

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

        Ok(RegistrySnapshot {
            registry_version: version.get(),
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

        // Check if we already have this version published
        if self.registry_version == Some(version) {
            return Ok(());
        }

        // Otherwise create a snapshot & publish it
        let rt = self.get_snapshot(version)?;

        self.published_registry_snapshot
            .store(Some(Arc::new(rt.clone())));

        self.registry_version = Some(version);

        info!(
            version_old = self.registry_version.map(|x| x.get()),
            version_new = version.get(),
            "New registry snapshot published",
        );

        // Persist the firewall rules if configured
        if let Some(v) = &self.persister {
            v.persist(rt).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test;
