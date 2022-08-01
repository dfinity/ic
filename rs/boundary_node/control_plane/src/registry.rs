use std::sync::Arc;

use anyhow::{Context, Error};
use async_trait::async_trait;
use ic_crypto_utils_basic_sig::conversions::pem::der_to_pem;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl, RegistryDataProvider};
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use serde::Serialize;

#[async_trait]
pub trait CreateRegistryClient: Send + Sync {
    async fn create_registry_client(&mut self) -> Result<RegistryClientImpl, Error>;
}

pub struct CreateRegistryClientImpl {
    registry_data_provider: Arc<dyn RegistryDataProvider>,
}

impl CreateRegistryClientImpl {
    pub fn new(registry_data_provider: Arc<dyn RegistryDataProvider>) -> Self {
        Self {
            registry_data_provider,
        }
    }
}

#[async_trait]
impl CreateRegistryClient for CreateRegistryClientImpl {
    async fn create_registry_client(&mut self) -> Result<RegistryClientImpl, Error> {
        let registry_client = RegistryClientImpl::new(self.registry_data_provider.clone(), None);

        registry_client
            .try_polling_latest_version(100)
            .context("failed to poll latest version")?;

        registry_client
            .fetch_and_start_polling()
            .context("failed to poll registry")?;

        Ok(registry_client)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub node_id: String,
    pub socket_addr: String,
    pub tls_certificate_pem: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subnet {
    pub subnet_id: String,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanisterRange {
    pub subnet_id: String,
    pub start_canister_id: String,
    pub end_canister_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutingTable {
    pub registry_version: u64,
    pub nns_subnet_id: String,
    pub canister_routes: Vec<CanisterRange>,
    pub subnets: Vec<Subnet>,
}

#[async_trait]
pub trait Snapshot: Send + Sync {
    async fn snapshot(&mut self) -> Result<RoutingTable, Error>;
}

pub struct Snapshotter<T: RegistryClient> {
    registry_client: T,
}

impl<T: RegistryClient> Snapshotter<T> {
    pub fn new(registry_client: T) -> Self {
        Self { registry_client }
    }
}

#[async_trait]
impl<T: RegistryClient> Snapshot for Snapshotter<T> {
    async fn snapshot(&mut self) -> Result<RoutingTable, Error> {
        let version = self.registry_client.get_latest_version();

        let root_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .context("failed to get root subnet id")? // Result
            .context("root subnet id not available")?; // Option

        let subnet_ids = self
            .registry_client
            .get_subnet_ids(version)
            .context("failed to get subnet ids")? // Result
            .context("subnet ids not available")?; // Option

        let subnets = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                let node_ids = self
                    .registry_client
                    .get_node_ids_on_subnet(subnet_id, version)
                    .context("failed to get node ids")? // Result
                    .context("node ids not available")?; // Option

                let nodes = node_ids
                    .into_iter()
                    .map(|node_id| {
                        let transport_info = self
                            .registry_client
                            .get_transport_info(node_id, version)
                            .context("failed to get transport info")? // Result
                            .context("transport info not available")?; // Option

                        let http_endpoint =
                            transport_info.http.context("http endpoint not available")?;

                        let socket_addr = format!(
                            "{}:{}",
                            normalize_ipv6_addr(http_endpoint.ip_addr),
                            http_endpoint.port
                        );

                        let cert = self
                            .registry_client
                            .get_tls_certificate(node_id, version)
                            .context("failed to get tls certificate")? // Result
                            .context("tls certificate not available")?; // Option

                        let tls_certificate_pem =
                            der_to_pem(cert.certificate_der.as_slice(), "CERTIFICATE");

                        let node_route = Node {
                            node_id: node_id.to_string(),
                            socket_addr,
                            tls_certificate_pem,
                        };

                        let out: Result<Node, Error> = Ok(node_route);
                        out
                    })
                    .collect::<Result<Vec<Node>, Error>>()
                    .context("failed to get node routes")?;

                let subnet_route = Subnet {
                    subnet_id: subnet_id.to_string(),
                    nodes,
                };

                let out: Result<Subnet, Error> = Ok(subnet_route);
                out
            })
            .collect::<Result<Vec<Subnet>, Error>>()
            .context("failed to get subnet routes")?;

        let routing_table = self
            .registry_client
            .get_routing_table(version)
            .context("failed to get routing table")? // Result
            .context("routing table not available")?; // Option

        let canister_ranges = routing_table
            .iter()
            .map(|(range, subnet_id)| CanisterRange {
                subnet_id: subnet_id.to_string(),
                start_canister_id: range.start.to_string(),
                end_canister_id: range.end.to_string(),
            })
            .collect::<Vec<CanisterRange>>();

        Ok(RoutingTable {
            registry_version: version.get(),
            nns_subnet_id: root_subnet_id.to_string(),
            canister_routes: canister_ranges,
            subnets,
        })
    }
}

fn is_ipv6_addr(addr: &str) -> bool {
    addr.contains(':')
}

fn is_ipv6_addr_normalized(addr: &str) -> bool {
    addr.contains('[')
}

fn normalize_ipv6_addr(addr: String) -> String {
    if !is_ipv6_addr(&addr) {
        return addr;
    }

    if is_ipv6_addr_normalized(&addr) {
        return addr;
    }

    format!("[{addr}]")
}
