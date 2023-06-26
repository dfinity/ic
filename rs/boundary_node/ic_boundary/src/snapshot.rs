use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ic_protobuf::registry::subnet::v1::SubnetType;

use ic_registry_client::client::{RegistryClient, RegistryDataProvider};
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};

use crate::Run;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: Principal,
    pub addr: String,
    pub port: u16,
    pub tls_certificate_der: Vec<u8>,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingTable {
    pub registry_version: u64,
    pub nns_subnet_id: Principal,
    pub subnets: Vec<Subnet>,
}

pub struct Runner<'a> {
    published_routing_table: &'a ArcSwapOption<RoutingTable>,
    registry_client: Arc<dyn RegistryClient>,
}

impl<'a> Runner<'a> {
    pub fn new(
        published_routing_table: &'a ArcSwapOption<RoutingTable>,
        registry_client: Arc<dyn RegistryClient>,
    ) -> Self {
        Self {
            published_routing_table,
            registry_client,
        }
    }

    fn get_routing_table(&mut self) -> Result<RoutingTable, Error> {
        let version = self.registry_client.get_latest_version();

        let root_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .context("failed to get root subnet id")? // Result
            .context("root subnet id not available")?; // Option

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
                    .context("failed to get subnet")?
                    .context("subnet not available")?;

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

                        let cert = self
                            .registry_client
                            .get_tls_certificate(node_id, version)
                            .context("failed to get tls certificate")? // Result
                            .context("tls certificate not available")?; // Option

                        let node_route = Node {
                            id: node_id.as_ref().0,
                            addr: http_endpoint.ip_addr,
                            port: http_endpoint.port as u16, // Port is u16 anyway
                            tls_certificate_der: cert.certificate_der,
                        };

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
                    subnet_type: subnet.subnet_type(),
                    ranges,
                    nodes,
                };

                let out: Result<Subnet, Error> = Ok(subnet_route);
                out
            })
            .collect::<Result<Vec<Subnet>, Error>>()
            .context("unable to get subnets")?;

        Ok(RoutingTable {
            registry_version: version.get(),
            nns_subnet_id: root_subnet_id.as_ref().0,
            subnets,
        })
    }
}

#[async_trait]
impl<'a> Run for Runner<'a> {
    async fn run(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test;
