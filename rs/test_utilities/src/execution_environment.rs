use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_interfaces::execution_environment::RegistryExecutionSettings;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{NetworkTopology, NodeTopology, SubnetTopology};
use ic_types::{CanisterId, SubnetId};
use ic_types_test_utils::ids::node_test_id;
use maplit::btreemap;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};

/// A helper to create subnets.
pub fn generate_subnets(
    subnet_ids: Vec<SubnetId>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    own_subnet_size: usize,
) -> BTreeMap<SubnetId, SubnetTopology> {
    let mut result: BTreeMap<SubnetId, SubnetTopology> = Default::default();
    for subnet_id in subnet_ids {
        let mut subnet_type = SubnetType::System;
        let mut nodes = btreemap! {};
        if subnet_id == own_subnet_id {
            subnet_type = own_subnet_type;
            // Populate network_topology of own_subnet with fake nodes to simulate subnet_size.
            for i in 0..own_subnet_size {
                nodes.insert(
                    node_test_id(i as u64),
                    NodeTopology {
                        ip_address: "fake-ip-address".to_string(),
                        http_port: 1234,
                    },
                );
            }
        }
        result.insert(
            subnet_id,
            SubnetTopology {
                public_key: vec![1, 2, 3, 4],
                nodes,
                subnet_type,
                subnet_features: SubnetFeatures::default(),
                ecdsa_keys_held: BTreeSet::new(),
            },
        );
    }
    result
}

pub fn generate_network_topology(
    subnet_size: usize,
    own_subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    subnets: Vec<SubnetId>,
    routing_table: Option<RoutingTable>,
) -> NetworkTopology {
    NetworkTopology {
        nns_subnet_id,
        subnets: generate_subnets(subnets, own_subnet_id, own_subnet_type, subnet_size),
        routing_table: match routing_table {
            Some(routing_table) => Arc::new(routing_table),
            None => {
                Arc::new(RoutingTable::try_from(btreemap! {
                CanisterIdRange { start: CanisterId::from(0), end: CanisterId::from(CANISTER_IDS_PER_SUBNET - 1) } => own_subnet_id,
            }).unwrap())
            }
        },
        ..Default::default()
    }
}

pub fn test_registry_settings() -> RegistryExecutionSettings {
    RegistryExecutionSettings {
        max_number_of_canisters: 0x2000,
        provisional_whitelist: ProvisionalWhitelist::Set(BTreeSet::new()),
        max_ecdsa_queue_size: 20,
        subnet_size: SMALL_APP_SUBNET_MAX_SIZE,
    }
}
