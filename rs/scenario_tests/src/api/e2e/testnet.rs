use ic_config::registry_client::DataProviderConfig;
use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_registry_client::client::{create_data_provider, RegistryClient, RegistryClientImpl};
use ic_registry_client_helpers::{
    node::NodeRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_routing_table::RoutingTable;
use ic_types::{registry::connection_endpoint::ConnectionEndpoint, NodeId, PrincipalId, SubnetId};
use std::{
    collections::BTreeMap, convert::TryFrom, net::SocketAddr, path::PathBuf, result::Result,
    sync::Arc,
};
use url::Url;

/// Trait providing helper methods for accessing subnets and nodes.
pub trait TestnetT {
    /// Sorted IDs of subnets on this testnet,
    fn subnet_ids(&self) -> Vec<SubnetId>;

    /// Sorted IDs of nodes on the given subnet,
    fn node_ids(&self, subnet_id: SubnetId) -> Vec<NodeId>;

    /// Url for the Public Api of node `node_id`.
    fn node_api_url(&self, node_id: NodeId) -> Url;

    /// Returns the subnet hosting the given `PrincipalId`, if any.
    fn route(&self, principal_id: PrincipalId) -> Option<SubnetId>;
}

#[derive(Debug)]
pub struct Testnet {
    subnet_ids: Vec<SubnetId>,
    subnets: BTreeMap<SubnetId, Subnet>,
    routing_table: RoutingTable,
}

#[derive(Default, Debug)]
struct Subnet {
    node_ids: Vec<NodeId>,
    nodes: BTreeMap<NodeId, Node>,
}

#[derive(Debug)]
struct Node {
    endpoint_url: Url,
}

pub fn registry_client(
    nns_url: &str,
    nns_public_key_path: Option<String>,
) -> Arc<impl RegistryClient> {
    let nns_url = Url::parse(nns_url).unwrap();
    let nns_public_key = nns_public_key_path.map(|path| {
        parse_threshold_sig_key(&PathBuf::from(&path)).expect("Unable to parse public key file")
    });
    let data_provider = create_data_provider(
        &DataProviderConfig::RegistryCanisterUrl(vec![nns_url]),
        nns_public_key,
    );
    let metrics_registry = MetricsRegistry::new();
    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(&metrics_registry),
    ));
    registry_client.try_polling_latest_version(100).unwrap();
    if let Err(e) = registry_client.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    }

    registry_client
}

/// Loads testnet topology from the latest version of the registry.
pub fn load_testnet_topology(
    registry_client: &Arc<impl RegistryClient>,
) -> Result<Testnet, String> {
    let mut subnets = BTreeMap::new();

    let registry_version = registry_client.get_latest_version();

    // Fetch all subnet IDs, propagate errors.
    let subnet_ids = registry_client
        .get_subnet_ids(registry_version)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();

    // No subnets is a problem.
    if subnet_ids.is_empty() {
        return Err("no subnets in registry".into());
    }

    let routing_table = registry_client
        .get_routing_table(registry_version)
        .map_err(|e| e.to_string())?
        .ok_or("no routing table record")?;

    let mut app_subnet_ids = Vec::new();
    for subnet_id in subnet_ids {
        let mut subnet = Subnet::default();

        let subnet_record = registry_client
            .get_subnet_record(subnet_id, registry_version)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        if subnet_record.subnet_type == SubnetType::System as i32 {
            // Skip NNS subnet.
            continue;
        }
        app_subnet_ids.push(subnet_id);
        // Fetch all node IDs for this subnet, propagate errors.
        let node_ids = registry_client
            .get_node_ids_on_subnet(subnet_id, registry_version)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();

        if node_ids.is_empty() {
            return Err(format!("subnet {} has no nodes", subnet_id));
        }
        subnet.node_ids = node_ids.clone();
        for node_id in node_ids {
            let node_record = registry_client
                .get_transport_info(node_id, registry_version)
                .map_err(|e| e.to_string())?
                .ok_or(format!("node {} has no transport info", node_id))?;

            let connection_endpoint = ConnectionEndpoint::try_from(
                node_record
                    .http
                    .clone()
                    .ok_or(format!("node {} has no HTTP connection endpoint", node_id))?,
            )
            .map_err(|e| {
                format!(
                    "failed to parse HTTP connection endpoint for node {}: {}",
                    node_id, e
                )
            })?;

            let addr = SocketAddr::from(&connection_endpoint);

            // Seen bogus registry entries where the connection endpoint exists
            // but is 0.0.0.0.
            if addr.ip().is_unspecified() {
                return Err(format!(
                    "unspecified HTTP connecton endpoint for node {}",
                    node_id
                ));
            }

            let endpoint_url = Url::parse(&format!("http://{}/", addr)).unwrap();

            subnet.nodes.insert(node_id, Node { endpoint_url });
        }
        subnets.insert(subnet_id, subnet);
    }

    Ok(Testnet {
        subnet_ids: app_subnet_ids,
        subnets,
        routing_table,
    })
}

impl TestnetT for Testnet {
    fn subnet_ids(&self) -> Vec<SubnetId> {
        self.subnet_ids.clone()
    }

    fn node_ids(&self, subnet_id: SubnetId) -> Vec<NodeId> {
        let node_ids: Vec<_> = self.subnets.get(&subnet_id).unwrap().node_ids.clone();
        assert!(!node_ids.is_empty(), "Subnet not found: {}", subnet_id);
        node_ids
    }

    fn node_api_url(&self, node_id: NodeId) -> Url {
        let node = self
            .subnets
            .values()
            .flat_map(|subnet| subnet.nodes.iter())
            .filter(|(id, _)| **id == node_id)
            .map(|(_, node)| node)
            .fold(None, |out, n| {
                assert!(out.is_none(), "Duplicate node {}", node_id);
                Some(n)
            })
            .unwrap_or_else(|| panic!("Node not found: {}", node_id));

        node.endpoint_url.clone()
    }

    fn route(&self, principal_id: PrincipalId) -> Option<SubnetId> {
        self.routing_table.route(principal_id)
    }
}
