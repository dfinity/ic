use crate::deserialize_registry_value;
use ic_interfaces_registry::{
    RegistryClient,
    RegistryClientResult,
};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_keys::{
    make_canister_migrations_record_key,
    make_routing_table_record_key,
};
use ic_registry_routing_table::{
    CanisterIdRange,
    CanisterMigrations,
    RoutingTable,
};
use ic_types::{
    registry::RegistryClientError::DecodeError,
    RegistryVersion,
    SubnetId,
};
use std::convert::TryFrom;

/// A trait that allows access to `RoutingTable`.  The expectation for the
/// foreseeable future is that the `RoutingTable` will remain small enough so
/// that we can simply return the entire struct here.
pub trait RoutingTableRegistry {
    fn get_routing_table(&self, version: RegistryVersion) -> RegistryClientResult<RoutingTable>;
    fn get_subnet_canister_ranges(
        &self,
        version: RegistryVersion,
        sub: SubnetId,
    ) -> RegistryClientResult<Vec<CanisterIdRange>>;
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
                .map(|pb_routing_table| {
                    RoutingTable::try_from(pb_routing_table).map_err(|err| DecodeError {
                        error: format!("get_routing_table() failed with {}", err),
                    })
                })
                .transpose()
        })?
    }

    fn get_subnet_canister_ranges(
        &self,
        version: RegistryVersion,
        sub: SubnetId,
    ) -> RegistryClientResult<Vec<CanisterIdRange>> {
        let routing_table = self.get_routing_table(version)?;

        Ok(routing_table.map(|t| {
            t.iter()
                .filter(|(_, sub_id)| sub_id.get() == sub.get())
                .map(|(ran, _)| *ran)
                .collect()
        }))
    }

    fn get_canister_migrations(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<CanisterMigrations> {
        let bytes = self.get_value(&make_canister_migrations_record_key(), version);
        deserialize_registry_value::<pb::CanisterMigrations>(bytes).map(
            |option_pb_canister_migrations| {
                option_pb_canister_migrations
                    .map(|pb_canister_migrations| {
                        CanisterMigrations::try_from(pb_canister_migrations).map_err(|err| {
                            DecodeError {
                                error: format!("get_canister_migrations() failed with {}", err),
                            }
                        })
                    })
                    .transpose()
            },
        )?
    }
}
