use crate::{mutations::common::decode_registry_value, registry::Registry};

use std::convert::TryFrom;

use ic_base_types::SubnetId;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{make_canister_migrations_record_key, make_routing_table_record_key};
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRange, CanisterIdRanges, CanisterMigrations,
    RoutingTable,
};
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue};
use prost::Message;

fn routing_table_into_registry_mutation(
    routing_table: RoutingTable,
    mutation_type: i32,
) -> RegistryMutation {
    let routing_table = pb::RoutingTable::from(routing_table);
    let mut buf = vec![];
    routing_table.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type,
        key: make_routing_table_record_key().as_bytes().to_vec(),
        value: buf,
    }
}

#[allow(dead_code)]
// The function will be used when canister migration mutation is fully supported in the future.
fn canister_migrations_into_registry_mutation(
    canister_migrations: CanisterMigrations,
    mutation_type: i32,
) -> RegistryMutation {
    let canister_migrations = pb::CanisterMigrations::from(canister_migrations);
    let mut buf = vec![];
    canister_migrations.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type,
        key: make_canister_migrations_record_key().as_bytes().to_vec(),
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
        routing_table_into_registry_mutation(routing_table, 1)
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

    /// Makes a registry mutation that remaps the specified canister ID range to
    /// another subnet.
    pub fn reroute_canister_range_mutation(
        &self,
        version: u64,
        canister_id_range: CanisterIdRange,
        destination: SubnetId,
    ) -> RegistryMutation {
        self.modify_routing_table(version, |routing_table| {
            // Note: The conversion from `CanisterIdRange` to `CanisterIdRanges` below is temporary.
            // In the following work, the mutation will also take `CanisterIdRanges` as input.
            let ranges = CanisterIdRanges::try_from(vec![canister_id_range])
                .expect("canister ID ranges are not well formed.");
            routing_table.assign_ranges(ranges, destination).unwrap();
            routing_table.optimize();
        })
    }
}
