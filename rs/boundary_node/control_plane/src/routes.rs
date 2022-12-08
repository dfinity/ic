use std::collections::HashMap;

use candid::Principal;
use serde::Serialize;

use crate::registry::RoutingTable;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct RangeValue(String);

impl From<&Principal> for RangeValue {
    fn from(p: &Principal) -> Self {
        Self(hex::encode(p.as_slice()))
    }
}

struct Subnet {
    id: String,
    range_start: RangeValue,
    range_end: RangeValue,
}

#[derive(Serialize)]
pub struct Routes {
    canister_range_starts: Vec<String>,
    canister_range_ends: Vec<String>,
    canister_subnets: Vec<String>,
    nns_subnet_index: usize,
    subnet_types: HashMap<String, String>,
    subnet_node_ids: HashMap<String, Vec<String>>,
    subnet_nodes: HashMap<String, Vec<String>>,
}

impl From<&RoutingTable> for Routes {
    fn from(rt: &RoutingTable) -> Self {
        // Sort Subnets
        let mut subnets: Vec<Subnet> = rt
            .canister_routes
            .iter()
            .map(|r| Subnet {
                id: r.subnet_id.to_owned(),
                range_start: (&Principal::from_text(&r.start_canister_id).unwrap()).into(),
                range_end: (&Principal::from_text(&r.end_canister_id).unwrap()).into(),
            })
            .collect();

        subnets.sort_by(|a, b| a.range_start.cmp(&b.range_start));

        // Build Struct
        Self {
            // Canister-Range (Start)
            canister_range_starts: subnets
                .iter()
                .map(|subnet| subnet.range_start.0.to_owned())
                .collect(),

            // Canister-Range (End)
            canister_range_ends: subnets
                .iter()
                .map(|subnet| subnet.range_end.0.to_owned())
                .collect(),

            // Subnet IDs
            canister_subnets: subnets.iter().map(|subnet| subnet.id.to_owned()).collect(),

            // NNS Subnet Index
            nns_subnet_index: subnets
                .iter()
                .position(|subnet| subnet.id == rt.nns_subnet_id)
                .unwrap(),

            // Subnet Types
            subnet_types: rt
                .subnets
                .iter()
                .map(|subnet| (subnet.subnet_id.to_owned(), subnet.subnet_type.to_owned()))
                .collect(),

            // Node IDs
            subnet_node_ids: rt
                .subnets
                .iter()
                .map(|subnet| {
                    (
                        subnet.subnet_id.to_owned(),
                        subnet
                            .nodes
                            .iter()
                            .map(|node| node.node_id.to_owned())
                            .collect(),
                    )
                })
                .collect(),

            // Node Addresses
            subnet_nodes: rt
                .subnets
                .iter()
                .map(|subnet| {
                    (
                        subnet.subnet_id.to_owned(),
                        subnet
                            .nodes
                            .iter()
                            .map(|node| node.socket_addr.to_owned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}
