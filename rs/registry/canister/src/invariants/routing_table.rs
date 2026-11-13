use crate::invariants::common::{InvariantCheckError, RegistrySnapshot};

use std::convert::TryFrom;

use ic_base_types::CanisterId;
use ic_protobuf::registry::routing_table::v1::{
    CanisterMigrations as pbCanisterMigrations, RoutingTable as pbRoutingTable,
};
use ic_registry_keys::{
    CANISTER_RANGES_PREFIX, make_canister_migrations_record_key, make_canister_ranges_key,
};
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use prost::Message;

/// Checks that the routing table shards (the `canister_ranges_*` keys) are consistent:
///
/// * the canister IDs in the shard keys are strictly increasing;
/// * each shard is a valid routing table;
/// * no entry of a shard starts before the canister ID in the shard's key;
/// * no entry of a shard reaches the canister ID in the next shard's key.
///
/// Together, these imply that all shards concatenated form a valid routing table, since the
/// entries of each shard are confined to the canister IDs between the shard's key (inclusive) and
/// the next shard's key (exclusive). Hence, the concatenation is not validated separately, which
/// would mean converting every entry a second time.
pub(crate) fn check_routing_table_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut shards = get_routing_table_shards(snapshot).into_iter().peekable();

    while let Some((shard_key, shard)) = shards.next() {
        let next_shard_key = shards.peek().map(|(next_shard_key, _)| *next_shard_key);

        if let Some(next_shard_key) = next_shard_key
            && next_shard_key <= shard_key
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Routing table shard key {shard_key} is not smaller than the next shard key {next_shard_key}"
                ),
                source: None,
            });
        }

        let routing_table = RoutingTable::try_from(shard).map_err(|err| InvariantCheckError {
            msg: format!("Invalid routing table shard at key {shard_key}: {err}"),
            source: None,
        })?;

        if let Some((first_range, _)) = routing_table.iter().next()
            && first_range.start < shard_key
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Routing table shard at key {shard_key} contains an entry starting at {}",
                    first_range.start
                ),
                source: None,
            });
        }

        if let (Some((last_range, _)), Some(next_shard_key)) =
            (routing_table.iter().last(), next_shard_key)
            && last_range.end >= next_shard_key
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Routing table shard at key {shard_key} contains an entry ending at {}, which overlaps the next shard key {next_shard_key}",
                    last_range.end
                ),
                source: None,
            });
        }
    }

    Ok(())
}

// Return routing table from snapshot
fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
    // If there are shards, they should match the routing table record.
    let shards: Vec<pbRoutingTable> = get_routing_table_shards(snapshot)
        .into_iter()
        .map(|(_, routing_table)| routing_table)
        .collect();
    RoutingTable::try_from(shards).unwrap()
}

fn get_routing_table_shards(snapshot: &RegistrySnapshot) -> Vec<(CanisterId, pbRoutingTable)> {
    let start = make_canister_ranges_key(CanisterId::from_u64(0)).into_bytes();
    let end = make_canister_ranges_key(CanisterId::from_u64(u64::MAX)).into_bytes();
    let mut shards = vec![];
    for (key, value) in snapshot.range(start..=end) {
        let shard_key = key
            .strip_prefix(CANISTER_RANGES_PREFIX.as_bytes())
            .and_then(|key| hex::decode(key).ok())
            .and_then(|key| CanisterId::try_from(key).ok())
            .expect("invalid canister ranges key");
        let routing_table_proto = pbRoutingTable::decode(value.as_slice()).unwrap();
        shards.push((shard_key, routing_table_proto));
    }

    shards
}

/// Iff `canister_migrations` is present, check that its invariants hold if reading and conversion succeed.
pub(crate) fn check_canister_migrations_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    if let Some(canister_migrations_bytes) =
        snapshot.get(make_canister_migrations_record_key().as_bytes())
    {
        // Check if canister migrations are well formed.
        let canister_migrations_proto =
            pbCanisterMigrations::decode(canister_migrations_bytes.as_slice()).unwrap();
        let canister_migrations = CanisterMigrations::try_from(canister_migrations_proto).unwrap();

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
                                "canister ID range {canister_migrations_range:?} in `canister_migrations` is not hosted by any subnet in trace {trace:?}."
                            ),
                            source: None,
                        });
                    }
                }
                None => {
                    return Err(InvariantCheckError {
                        msg: format!(
                            "canister ID range {canister_migrations_range:?} in `canister_migrations` is not hosted by any subnet in trace {trace:?}."
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
    use ic_protobuf::registry::routing_table::v1::{
        CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
    };
    use ic_registry_keys::make_canister_migrations_record_key;
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;
    use std::convert::TryFrom;

    fn insert_routing_table_to_snapshot(
        routing_table: RoutingTable,
        snapshot: &mut RegistrySnapshot,
    ) {
        let routing_table = PbRoutingTable::from(routing_table);
        snapshot.insert(
            make_canister_ranges_key(CanisterId::from(0)).into_bytes(),
            routing_table.encode_to_vec(),
        );
    }

    #[test]
    fn nonexistent_canister_migrations_can_pass_invariants_check() {
        let mut snapshot = RegistrySnapshot::new();

        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        }).unwrap();
        insert_routing_table_to_snapshot(routing_table, &mut snapshot);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());
    }

    #[test]
    fn routing_table_range_must_not_span_shard_key() {
        let mut snapshot = RegistrySnapshot::new();
        let subnet_1 = subnet_test_id(1);
        let subnet_2 = subnet_test_id(2);

        let first_shard = RoutingTable::try_from(btreemap! {
            CanisterIdRange { start: CanisterId::from(0), end: CanisterId::from(199) } => subnet_1,
        })
        .unwrap();
        let second_shard = RoutingTable::try_from(btreemap! {
            CanisterIdRange { start: CanisterId::from(200), end: CanisterId::from(299) } => subnet_2,
        })
        .unwrap();

        snapshot.insert(
            make_canister_ranges_key(CanisterId::from(0)).into_bytes(),
            PbRoutingTable::from(first_shard).encode_to_vec(),
        );
        snapshot.insert(
            make_canister_ranges_key(CanisterId::from(100)).into_bytes(),
            PbRoutingTable::from(second_shard).encode_to_vec(),
        );

        let err = check_routing_table_invariants(&snapshot).unwrap_err();
        assert!(err.msg.contains("overlaps the next shard key"), "{err}");
    }

    #[test]
    fn routing_table_entry_must_not_start_before_its_shard_key() {
        let mut snapshot = RegistrySnapshot::new();
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange { start: CanisterId::from(99), end: CanisterId::from(199) } => subnet_test_id(1),
        })
        .unwrap();

        snapshot.insert(
            make_canister_ranges_key(CanisterId::from(100)).into_bytes(),
            PbRoutingTable::from(routing_table).encode_to_vec(),
        );

        let err = check_routing_table_invariants(&snapshot).unwrap_err();
        assert!(err.msg.contains("contains an entry starting"), "{err}");
    }

    #[test]
    fn empty_canister_migrations_can_pass_invariants_check() {
        let mut snapshot = RegistrySnapshot::new();

        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        }).unwrap();
        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            PbCanisterMigrations { entries: vec![] }.encode_to_vec(),
        );

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
        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Prepare canister migrations by adding entries.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x10), end: CanisterId::from(0xff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            canister_migrations.encode_to_vec(),
        );
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Reassign ranges in routing table.
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xf) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x10), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        }).unwrap();

        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Complete canister migrations by removing entries.
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            PbCanisterMigrations { entries: vec![] }.encode_to_vec(),
        );
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

        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // Prepare canister migrations by adding entries.
        // The canister ID range {0x200:0x2ff} in `canister_migrations` is hosted by subnet_3.
        // However subnet_3 is not on the trace thus the trace is invalid.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            canister_migrations.encode_to_vec(),
        );

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

        // The canister migrations after preparation.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);

        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            canister_migrations.encode_to_vec(),
        );
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_ok());

        // The new routing table after reassigning ranges.

        // Case 1: cannot find the entry containing `range.start` of canister migrations when looking up entries in the routing table,
        let new_routing_table_1 = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x1), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        insert_routing_table_to_snapshot(new_routing_table_1, &mut snapshot);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_err());

        // Case 2: find the entry containing `range.start` but the entry cannot fully cover the canister migration range {0x0:0xff}.
        let new_routing_table_2 = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0x1) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
            CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
        }).unwrap();

        insert_routing_table_to_snapshot(new_routing_table_2, &mut snapshot);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(check_canister_migrations_invariants(&snapshot).is_err());
    }
}
