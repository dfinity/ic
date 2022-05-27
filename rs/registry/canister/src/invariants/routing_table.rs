use crate::invariants::common::{InvariantCheckError, RegistrySnapshot};

use std::convert::TryFrom;

use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::routing_table::v1::{
    CanisterMigrations as pbCanisterMigrations, RoutingTable as pbRoutingTable,
};
use ic_registry_keys::{make_canister_migrations_record_key, make_routing_table_record_key};
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};

/// Routing table invariants hold if reading and conversion succeed.
pub(crate) fn check_routing_table_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    get_routing_table(snapshot);
    Ok(())
}

// Return routing table from snapshot
fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
    match snapshot.get(make_routing_table_record_key().as_bytes()) {
        Some(routing_table_bytes) => RoutingTable::try_from(decode_or_panic::<pbRoutingTable>(
            (*routing_table_bytes).clone(),
        ))
        .unwrap(),
        None => panic!("No routing table in snapshot"),
    }
}

/// Iff `canister_migrations` is present, check that its invariants hold if reading and conversion succeed.
pub(crate) fn check_canister_migrations_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    if let Some(canister_migrations_bytes) =
        snapshot.get(make_canister_migrations_record_key().as_bytes())
    {
        // Check if canister migrations are well formed.
        let canister_migrations =
            CanisterMigrations::try_from(decode_or_panic::<pbCanisterMigrations>(
                (*canister_migrations_bytes).clone(),
            ))
            .unwrap();

        let routing_table = get_routing_table(snapshot);
        // Check if each canister range is assigned to one of the subnets on the migration trace.
        // The subnet could be either the source before the migration or the destination after migration.
        for (canister_migrations_range, trace) in canister_migrations.iter() {
            match routing_table.lookup_entry(canister_migrations_range.start) {
                Some((routing_table_range, subnet_id)) => {
                    // The assertion should always hold otherwise `lookup_entry` won't return such an entry.
                    assert!(canister_migrations_range.start >= routing_table_range.start);
                    // The assigned subnet should be on the trace.
                    // The `canister_migrations_range` should be fully contained within the `routing_table_range`.
                    if !trace.contains(&subnet_id)
                        || canister_migrations_range.end > routing_table_range.end
                    {
                        return Err(InvariantCheckError {
                             msg: format!(
                                 "canister ID range {:?} in `canister_migrations` is not hosted by any subnet in trace {:?}.",
                                 canister_migrations_range,
                                 trace
                             ),
                             source: None,
                         });
                    }
                }
                None => {
                    return Err(InvariantCheckError {
                        msg: format!(
                            "canister ID range {:?} in `canister_migrations` is not hosted by any subnet in trace {:?}.",
                            canister_migrations_range,
                            trace
                        ),
                        source: None,
                    });
                }
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::invariants::routing_table::{
        check_canister_migrations_invariants, check_routing_table_invariants,
    };
    use ic_base_types::CanisterId;
    use ic_nns_common::registry::encode_or_panic;
    use ic_protobuf::registry::routing_table::v1::{
        CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
    };
    use ic_registry_keys::{make_canister_migrations_record_key, make_routing_table_record_key};
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_test_utilities::types::ids::subnet_test_id;
    use maplit::btreemap;
    use std::convert::TryFrom;

    #[test]
    fn nonexistent_canister_migrations_can_pass_invariants_check() {
        let mut snapshot = RegistrySnapshot::new();

        let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        snapshot.insert(key1.into_bytes(), value1);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());
    }

    #[test]
    fn empty_canister_migrations_can_pass_invariants_check() {
        let mut snapshot = RegistrySnapshot::new();

        let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        let key2 = make_canister_migrations_record_key();
        let value2 = encode_or_panic(&PbCanisterMigrations { entries: vec![] });

        snapshot.insert(key1.into_bytes(), value1);
        snapshot.insert(key2.into_bytes(), value2);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());
    }

    #[test]
    fn valid_canister_migrations_can_pass_invariants_check() {
        let mut snapshot = RegistrySnapshot::new();

        // The routing table before canister migration.
        let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        snapshot.insert(key1.into_bytes(), value1);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Prepare canister migrations by adding entries.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x10), end: CanisterId::from(0xff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        let key2 = make_canister_migrations_record_key();
        let value2 = encode_or_panic(&canister_migrations);

        snapshot.insert(key2.into_bytes(), value2);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Reassign ranges in routing table.
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xf) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x10), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key3 = make_routing_table_record_key();
        let value3 = encode_or_panic(&routing_table);
        snapshot.insert(key3.into_bytes(), value3);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Complete canister migrations by removing entries.
        let key4 = make_canister_migrations_record_key();
        let value4 = encode_or_panic(&PbCanisterMigrations { entries: vec![] });

        snapshot.insert(key4.into_bytes(), value4);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());
    }

    #[test]
    fn invalid_canister_migrations_preparation_invariants_check_error() {
        let mut snapshot = RegistrySnapshot::new();

        // The routing table before canister migration.
        let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        snapshot.insert(key1.into_bytes(), value1);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Prepare canister migrations by adding entries.
        // The canister ID range {0x200:0x2ff} in `canister_migrations` is hosted by subnet_3.
        // However subnet_3 is not on the trace thus the trace is invalid.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        let key2 = make_canister_migrations_record_key();
        let value2 = encode_or_panic(&canister_migrations);

        snapshot.insert(key2.into_bytes(), value2);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_err());
    }

    #[test]
    fn invalid_rerouting_canister_ranges_invariants_check_error() {
        let mut snapshot = RegistrySnapshot::new();

        // The routing table before canister migration.
        let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        // The canister migrations after preparation.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        let key2 = make_canister_migrations_record_key();
        let value2 = encode_or_panic(&canister_migrations);

        snapshot.insert(key1.into_bytes(), value1);
        snapshot.insert(key2.into_bytes(), value2);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // The new routing table after reassigning ranges.

        // Case 1: cannot find the entry containing `range.start` of canister migrations when looking up entries in the routing table,
        let mut new_snapshot = snapshot.clone();
        let new_routing_table_1 = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x1), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        let routing_table = PbRoutingTable::from(new_routing_table_1);
        let key3 = make_routing_table_record_key();
        let value3 = encode_or_panic(&routing_table);
        new_snapshot.insert(key3.into_bytes(), value3);

        assert!(check_routing_table_invariants(&new_snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&new_snapshot).is_err());

        // Case 2: find the entry containing `range.start` but the entry cannot fully cover the canister migration range {0x0:0xff}.
        let new_routing_table_2 = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0x1) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        let routing_table = PbRoutingTable::from(new_routing_table_2);
        let key4 = make_routing_table_record_key();
        let value4 = encode_or_panic(&routing_table);
        snapshot.insert(key4.into_bytes(), value4);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_err());
    }
}
