use crate::{mutations::common::decode_registry_value, registry::Registry};

use std::{collections::BTreeMap, convert::TryFrom};

use ic_base_types::SubnetId;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue};
use prost::Message;

fn into_registry_mutation(routing_table: RoutingTable, mutation_type: i32) -> RegistryMutation {
    let routing_table = pb::RoutingTable::from(routing_table);
    let mut buf = vec![];
    routing_table.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type,
        key: make_routing_table_record_key().as_bytes().to_vec(),
        value: buf,
    }
}

impl Registry {
    /// Handle adding a subnet to the routing table.
    pub fn add_subnet_to_routing_table(
        &self,
        version: u64,
        subnet_id_to_add: SubnetId,
    ) -> RegistryMutation {
        let RegistryValue {
            value: routing_table_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(make_routing_table_record_key().as_bytes(), version)
            .unwrap();
        let mut routing_table = RoutingTable::try_from(decode_registry_value::<pb::RoutingTable>(
            routing_table_vec.clone(),
        ))
        .unwrap();
        routing_table_insert_subnet(&mut routing_table, subnet_id_to_add).unwrap();

        into_registry_mutation(routing_table, 1)
    }

    /// Handle removing a subnet from the routing table.  Marked as dead_code as
    /// the canister does not currently support removing subnets.
    #[allow(dead_code)]
    pub fn remove_subnet_from_routing_table(
        &self,
        version: u64,
        subnet_id_to_remove: SubnetId,
    ) -> RegistryMutation {
        let RegistryValue {
            value: routing_table_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(make_routing_table_record_key().as_bytes(), version)
            .unwrap();
        let routing_table = RoutingTable::try_from(decode_registry_value::<pb::RoutingTable>(
            routing_table_vec.clone(),
        ))
        .unwrap();

        let mut map = BTreeMap::new();
        for (canister_id_range, subnet_id) in routing_table.into_iter() {
            if subnet_id != subnet_id_to_remove {
                map.insert(canister_id_range, subnet_id);
            }
        }
        let routing_table = RoutingTable::new(map);

        into_registry_mutation(routing_table, 1)
    }
}
