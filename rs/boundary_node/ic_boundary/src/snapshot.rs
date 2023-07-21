use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use hyper::client::connect::dns::Name;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_registry_client::client::{RegistryClient, RegistryDataProvider};
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_types::replica_version::ReplicaVersion;
use reqwest::dns::{Addrs, Resolve, Resolving};
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, CertificateError, Error as RustlsError, ServerName,
};
use tracing::warn;
use x509_parser::{certificate::X509Certificate, prelude::FromDer, time::ASN1Time};

use crate::Run;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: Principal,
    pub subnet_id: Principal,
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

#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub registry_version: u64,
    pub nns_subnet_id: Principal,
    pub subnets: Vec<Subnet>,
    // Hash map for a faster lookup by DNS resolver
    pub nodes: HashMap<String, Node>,
}

pub struct Runner {
    published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
    registry_client: Arc<dyn RegistryClient>,
}

impl Runner {
    pub fn new(
        published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
        registry_client: Arc<dyn RegistryClient>,
    ) -> Self {
        Self {
            published_routing_table,
            registry_client,
        }
    }

    // Constructs a routing table based on registry
    fn get_routing_table(&mut self) -> Result<RoutingTable, Error> {
        let version = self.registry_client.get_latest_version();

        // Get NNS subnet ID
        // TODO What do we need it for?
        let root_subnet_id = self
            .registry_client
            .get_root_subnet_id(version)
            .context("failed to get root subnet id")? // Result
            .context("root subnet id not available")?; // Option

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

                        // Try to parse certificate
                        X509Certificate::from_der(cert.certificate_der.as_slice())
                            .context("Unable to parse TLS certificate")?;

                        let node_route = Node {
                            id: node_id.as_ref().0,
                            subnet_id: subnet_id.as_ref().0,
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
                    subnet_type: subnet.subnet_type(),
                    ranges,
                    nodes,
                    replica_version: replica_version.to_string(),
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
            nodes: nodes_map,
        })
    }
}

#[async_trait]
impl Run for Runner {
    async fn run(&mut self) -> Result<(), Error> {
        // Obtain routing table & publish it
        let rt = self.get_routing_table()?;
        self.published_routing_table.store(Some(Arc::new(rt)));
        Ok(())
    }
}

pub struct TlsVerifier {
    published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
}

impl TlsVerifier {
    pub fn new(published_routing_table: Arc<ArcSwapOption<RoutingTable>>) -> Self {
        Self {
            published_routing_table,
        }
    }
}

pub struct DnsResolver {
    published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
}

impl DnsResolver {
    pub fn new(published_routing_table: Arc<ArcSwapOption<RoutingTable>>) -> Self {
        Self {
            published_routing_table,
        }
    }
}

// Implement the certificate verifier which ensures that the certificate
// that was provided by node during TLS handshake matches its public key from the registry
// This trait is used by Rustls in reqwest under the hood
// We don't really check CommonName since the resolver makes sure we connect to the right IP
impl ServerCertVerifier for TlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Load a routing table if we have one
        let rt = self
            .published_routing_table
            .load_full()
            .ok_or_else(|| RustlsError::General("no routing table published".into()))?;

        // Look up a node in the routing table based on the hostname provided by rustls
        let node = match server_name {
            // Currently support only DnsName
            ServerName::DnsName(v) => {
                match rt.nodes.get(v.as_ref()) {
                    // If the requested node is not in the routing table
                    None => {
                        return Err(RustlsError::General(format!(
                            "Node '{}' not found in a routing table",
                            v.as_ref()
                        )));
                    }

                    // Found
                    Some(v) => v,
                }
            }

            // Unsupported for now, can be removed later if not needed at all
            ServerName::IpAddress(_) => return Err(RustlsError::UnsupportedNameType),

            // Enum is marked non_exhaustive
            &_ => return Err(RustlsError::UnsupportedNameType),
        };

        // Cert is parsed & checked when we read it from the registry - if we got here then it's correct
        // It's a zero-copy view over byte array
        // Storing X509Certificate directly in Node is problematic since it does not own the data
        let (_, node_cert) = X509Certificate::from_der(&node.tls_certificate).unwrap();

        // Parse the certificate provided by server
        let (_, provided_cert) = X509Certificate::from_der(&end_entity.0)
            .map_err(|x| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Verify the provided self-signed certificate using the public key from registry
        provided_cert
            .verify_signature(Some(&node_cert.tbs_certificate.subject_pki))
            .map_err(|x| RustlsError::InvalidCertificate(CertificateError::BadSignature))?;

        // Check if the certificate is valid at provided `now` time
        if !provided_cert.validity.is_valid_at(
            ASN1Time::from_timestamp(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            )
            .unwrap(),
        ) {
            return Err(RustlsError::InvalidCertificate(CertificateError::Expired));
        }

        Ok(ServerCertVerified::assertion())
    }
}

// Implement resolver based on the routing table
// It's used by reqwest to resolve node IDs to an IP address
impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // Load a routing table if we have one
        let rt = self.published_routing_table.load_full();

        if rt.is_none() {
            let err = Box::<dyn std::error::Error + Send + Sync>::from(
                "no routing table published".to_string(),
            );

            return Box::pin(futures_util::future::ready(Err(err)));
        }

        let rt = rt.unwrap();

        match rt.nodes.get(name.as_str()) {
            // If there's no node with given id - return future with error
            None => {
                let err = Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "Node '{name}' not found in routing table",
                ));

                Box::pin(futures_util::future::ready(Err(err)))
            }

            // Return future that resolves to an iterator with a node IP address
            Some(n) => {
                let addrs = vec![SocketAddr::new(n.addr, 0)]; // Port here is unused by reqwest
                let addrs: Addrs = Box::new(addrs.into_iter());

                Box::pin(futures_util::future::ready(Ok(addrs)))
            }
        }
    }
}

#[cfg(test)]
pub mod test;
