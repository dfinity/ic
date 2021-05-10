use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_common::values::deserialize_registry_value;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_routing_table::RoutingTable;
use ic_types::RegistryVersion;
use std::convert::TryFrom;

/// A trait that allows access to `RoutingTable`.  The expectation for the
/// forseeable future is that the `RoutingTable` will remain small enough so
/// that we can simply return the entire struct here.
pub trait RoutingTableRegistry {
    fn get_routing_table(&self, version: RegistryVersion) -> RegistryClientResult<RoutingTable>;
}

impl<T: RegistryClient + ?Sized> RoutingTableRegistry for T {
    fn get_routing_table(&self, version: RegistryVersion) -> RegistryClientResult<RoutingTable> {
        let bytes = self.get_value(&make_routing_table_record_key(), version);
        deserialize_registry_value::<pb::RoutingTable>(bytes).map(|option_pb_routing_table| {
            option_pb_routing_table
                .map(|pb_routing_table| RoutingTable::try_from(pb_routing_table).unwrap())
        })
    }
}
