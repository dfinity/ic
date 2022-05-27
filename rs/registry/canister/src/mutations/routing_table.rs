use crate::{common::LOG_PREFIX, mutations::common::decode_registry_value, registry::Registry};

use std::convert::TryFrom;

use ic_base_types::SubnetId;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{make_canister_migrations_record_key, make_routing_table_record_key};
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRanges, CanisterMigrations, RoutingTable,
};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
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

/// Returns the given `CanisterMigrations` as a registry mutation of the given type.
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
    /// Get the routing table or panic on error with a message.
    pub fn get_routing_table_or_panic(&self, version: u64) -> RoutingTable {
        let RegistryValue {
            value: routing_table_bytes,
            version: _,
            deletion_marker: _,
        } = self
            .get(make_routing_table_record_key().as_bytes(), version)
            .unwrap_or_else(|| panic!("{}routing table not found in the registry.", LOG_PREFIX));

        RoutingTable::try_from(decode_registry_value::<pb::RoutingTable>(
            routing_table_bytes.clone(),
        ))
        .expect("failed to decode the routing table from protobuf")
    }

    /// Applies the given mutation to the routing table at the specified version.
    fn modify_routing_table(
        &self,
        version: u64,
        f: impl FnOnce(&mut RoutingTable),
    ) -> RegistryMutation {
        let mut routing_table = self.get_routing_table_or_panic(version);
        f(&mut routing_table);
        routing_table_into_registry_mutation(routing_table, registry_mutation::Type::Update as i32)
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
    pub fn reroute_canister_ranges_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        destination: SubnetId,
    ) -> RegistryMutation {
        self.modify_routing_table(version, |routing_table| {
            routing_table
                .assign_ranges(canister_id_ranges, destination)
                .unwrap();
            routing_table.optimize();
        })
    }

    /// Retrieves the canister migrations if the key exists.
    pub fn get_canister_migrations(&self, version: u64) -> Option<CanisterMigrations> {
        self.get(make_canister_migrations_record_key().as_bytes(), version)
            .map(|registry_value| {
                CanisterMigrations::try_from(decode_registry_value::<pb::CanisterMigrations>(
                    registry_value.value.clone(),
                ))
                .expect("failed to decode the canister migrations from protobuf")
            })
    }

    /// Creates a mutation that applies the given change to `canister_mutations`
    /// at the specified version, creating the entry if it doesn't exist.
    fn modify_canister_migrations(
        &self,
        version: u64,
        f: impl FnOnce(&mut CanisterMigrations),
        mutation_type: i32,
    ) -> RegistryMutation {
        let mut canister_migrations = self.get_canister_migrations(version).unwrap_or_default();

        f(&mut canister_migrations);
        canister_migrations_into_registry_mutation(canister_migrations, mutation_type)
    }

    /// Makes a registry mutation that modifies the canister migrations.
    pub fn migrate_canister_ranges_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        source: SubnetId,
        destination: SubnetId,
    ) -> RegistryMutation {
        // The registry mutation type is set to `Upsert` so that the mutation is still valid
        // when canister migrations are not present in the registry.
        self.modify_canister_migrations(
            version,
            |canister_migrations| {
                canister_migrations
                    .insert_ranges(canister_id_ranges, source, destination)
                    .unwrap();
            },
            registry_mutation::Type::Upsert as i32,
        )
    }

    /// Makes a registry mutation that removes all provided entries from `canister_migrations`.
    pub fn remove_canister_migrations_mutation(
        &self,
        version: u64,
        canister_id_ranges: CanisterIdRanges,
        migration_trace: Vec<SubnetId>,
    ) -> RegistryMutation {
        // The registry mutation type is set to `Update` to prevent the removal
        // when canister migrations are not present in the registry.
        self.modify_canister_migrations(
            version,
            |canister_migrations| {
                canister_migrations
                    .remove_ranges(canister_id_ranges, migration_trace)
                    .unwrap();
            },
            registry_mutation::Type::Update as i32,
        )
    }
}
