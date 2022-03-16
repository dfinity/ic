use crate::deserialize_registry_value;
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{make_canister_migrations_record_key, make_routing_table_record_key};
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use ic_types::RegistryVersion;
use std::convert::TryFrom;

/// A trait that allows access to `RoutingTable`.  The expectation for the
/// forseeable future is that the `RoutingTable` will remain small enough so
/// that we can simply return the entire struct here.
pub trait RoutingTableRegistry {
    fn get_routing_table(&self, version: RegistryVersion) -> RegistryClientResult<RoutingTable>;
    fn get_canister_migrations(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<CanisterMigrations>;
}

impl<T: RegistryClient + ?Sized> RoutingTableRegistry for T {
    fn get_routing_table(&self, version: RegistryVersion) -> RegistryClientResult<RoutingTable> {
        let bytes = self.get_value(&make_routing_table_record_key(), version);
        deserialize_registry_value::<pb::RoutingTable>(bytes).map(|option_pb_routing_table| {
            option_pb_routing_table
                .map(|pb_routing_table| RoutingTable::try_from(pb_routing_table).unwrap())
        })
    }

    fn get_canister_migrations(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<CanisterMigrations> {
        let bytes = self.get_value(&make_canister_migrations_record_key(), version);
        deserialize_registry_value::<pb::CanisterMigrations>(bytes).map(
            |option_pb_canister_migrations| {
                option_pb_canister_migrations.map(|pb_canister_migrations| {
                    CanisterMigrations::try_from(pb_canister_migrations).unwrap()
                })
            },
        )
    }
}
