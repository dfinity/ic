use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct NodeRoute {
    pub node_id: String,
    pub socket_addr: String,
    pub tls_certificate_pem: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SubnetRoute {
    pub subnet_id: String,
    pub nodes: Vec<NodeRoute>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct CanisterRoute {
    pub start_canister_id: String,
    pub end_canister_id: String,
    pub subnet_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Routes {
    pub registry_version: u64,
    pub nns_subnet_id: String,
    pub canister_routes: Vec<CanisterRoute>,
    pub subnets: Vec<SubnetRoute>,
}
