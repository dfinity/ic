use crate::invariants::common::{InvariantCheckError, RegistrySnapshot};

use std::convert::TryFrom;

use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::routing_table::v1::RoutingTable as pbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_routing_table::RoutingTable;

/// Routing table invariants hold if it is well formed
pub(crate) fn check_routing_table_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    get_routing_table(snapshot)
        .well_formed()
        .map_err(|e| InvariantCheckError {
            msg: format!("routing table is not well formed {:?}", e),
            source: None,
        })
}

// Return routing table from snapshot
fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
    match snapshot.get(make_routing_table_record_key().as_bytes()) {
        Some(routing_table_vec) => RoutingTable::try_from(decode_or_panic::<pbRoutingTable>(
            (*routing_table_vec).clone(),
        ))
        .unwrap(),
        None => panic!("No routing table in snapshot"),
    }
}
