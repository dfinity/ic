use crate::{mutations::common::decode_registry_value, registry::Registry};

use std::convert::TryFrom;

use ic_base_types::SubnetId;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_routing_table::{routing_table_insert_subnet, CanisterIdRange, RoutingTable};
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
    /// Decodes the routing table at the specified version.
    fn modify_routing_table(
        &self,
        version: u64,
        f: impl FnOnce(&mut RoutingTable),
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
        .expect("failed to decode the routing table from protobuf");
        f(&mut routing_table);
        into_registry_mutation(routing_table, 1)
    }

    /// Handle adding a subnet to the routing table.
    pub fn add_subnet_to_routing_table(
        &self,
        version: u64,
        subnet_id_to_add: SubnetId,
    ) -> RegistryMutation {
        self.modify_routing_table(version, |routing_table| {
            routing_table_insert_subnet(routing_table, subnet_id_to_add).unwrap();
        })
    }

    /// Handle removing a subnet from the routing table.
    pub fn remove_subnet_from_routing_table(
        &self,
        version: u64,
        subnet_id_to_remove: SubnetId,
    ) -> RegistryMutation {
        self.modify_routing_table(version, |routing_table| {
            routing_table.remove_subnet(subnet_id_to_remove);
        })
    }

    /// Makes a registry mutation that remaps the specified canister id range to
    /// another subnet.
    pub fn reroute_canister_range_mutation(
        &self,
        version: u64,
        canister_id_range: CanisterIdRange,
        destination: SubnetId,
    ) -> RegistryMutation {
        self.modify_routing_table(version, |routing_table| {
            routing_table.assign_range(canister_id_range, destination);
            routing_table.optimize();
        })
    }
}
