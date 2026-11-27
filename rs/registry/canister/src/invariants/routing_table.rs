use crate::invariants::common::{InvariantCheckError, RegistrySnapshot};

use std::convert::TryFrom;

use ic_base_types::CanisterId;
use ic_protobuf::registry::routing_table::v1::{
    CanisterIdAllocation as pbCanisterIdAllocation, CanisterMigrations as pbCanisterMigrations,
    RoutingTable as pbRoutingTable,
};
use ic_registry_keys::{
    make_canister_id_allocation_key, make_canister_migrations_record_key, make_canister_ranges_key,
};
use ic_registry_routing_table::{CanisterMigrations, RoutingTable, canister_id_into_u64};
use prost::Message;

/// Routing table invariants hold if reading and conversion succeed.
///
/// Returns the routing table, so that other checks that need it (e.g.,
/// `check_canister_migrations_invariants`) do not have to decode it again.
pub(crate) fn check_routing_table_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<RoutingTable, InvariantCheckError> {
    let start = make_canister_ranges_key(CanisterId::from_u64(0)).into_bytes();
    let end = make_canister_ranges_key(CanisterId::from_u64(u64::MAX)).into_bytes();

    let mut shards = vec![];
    for (key, value) in snapshot.range(start..=end) {
        let shard =
            pbRoutingTable::decode(value.as_slice()).map_err(|err| InvariantCheckError {
                msg: format!(
                    "Unable to decode the routing table shard {}.",
                    String::from_utf8_lossy(key)
                ),
                source: Some(Box::new(err)),
            })?;
        shards.push(shard);
    }

    RoutingTable::try_from(shards).map_err(|err| InvariantCheckError {
        msg: "The routing table shards do not form a valid routing table.".to_string(),
        source: Some(Box::new(err)),
    })
}

/// Iff `canister_migrations` is present, check that its invariants hold if reading and conversion succeed.
pub(crate) fn check_canister_migrations_invariants(
    snapshot: &RegistrySnapshot,
    routing_table: &RoutingTable,
) -> Result<(), InvariantCheckError> {
    if let Some(canister_migrations_bytes) =
        snapshot.get(make_canister_migrations_record_key().as_bytes())
    {
        // Check if canister migrations are well formed.
        let canister_migrations_proto =
            pbCanisterMigrations::decode(canister_migrations_bytes.as_slice()).unwrap();
        let canister_migrations = CanisterMigrations::try_from(canister_migrations_proto).unwrap();

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

/// Checks the invariants of the `CanisterIdAllocation`.
///
/// The `CanisterIdAllocation` is meant to guarantee that no canister index at or above its
/// `next_unallocated_canister_index` has ever been allocated to a subnet. This function cannot
/// check that, since it only sees the current snapshot and the previous value, not the history.
/// What it does check is the following:
///
/// * Once present, it is never deleted.
/// * It never decreases. `previous_next_unallocated_canister_index` is its value before the
///   mutations being checked, if it was present.
/// * If present, every range in `routing_table` (the routing table in `snapshot`) ends below it,
///   i.e., every canister ID hosted by a subnet has been accounted for as allocated.
pub(crate) fn check_canister_id_allocation_invariants(
    snapshot: &RegistrySnapshot,
    routing_table: &RoutingTable,
    previous_next_unallocated_canister_index: Option<u64>,
) -> Result<(), InvariantCheckError> {
    // Enforce no deleting.
    let Some(bytes) = snapshot.get(make_canister_id_allocation_key().as_bytes()) else {
        if previous_next_unallocated_canister_index.is_some() {
            return Err(InvariantCheckError {
                msg: "The CanisterIdAllocation must not be deleted.".to_string(),
                source: None,
            });
        }
        return Ok(());
    };
    let next_unallocated_canister_index = pbCanisterIdAllocation::decode(bytes.as_slice())
        .map_err(|err| InvariantCheckError {
            msg: "Unable to decode the CanisterIdAllocation.".to_string(),
            source: Some(Box::new(err)),
        })?
        .next_unallocated_canister_index;

    // Enforce monotonic.
    if let Some(previous) = previous_next_unallocated_canister_index
        && next_unallocated_canister_index < previous
    {
        return Err(InvariantCheckError {
            msg: format!(
                "next_unallocated_canister_index of the CanisterIdAllocation must never \
                 decrease, but it would go from {previous} to {next_unallocated_canister_index}."
            ),
            source: None,
        });
    }

    // Enforce that the routing table only hosts allocated canister IDs. It suffices to check the
    // last range, since the ranges of a `RoutingTable` are sorted.
    if let Some((last_range, last_subnet_id)) = routing_table.iter().next_back()
        && canister_id_into_u64(last_range.end) >= next_unallocated_canister_index
    {
        return Err(InvariantCheckError {
            msg: format!(
                "The routing table hosts canister IDs at or above the \
                 next_unallocated_canister_index {next_unallocated_canister_index} of the \
                 CanisterIdAllocation: its last range is {last_range:?} (subnet {last_subnet_id})."
            ),
            source: None,
        });
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
    use ic_protobuf::proxy::ProxyDecodeError;
    use ic_protobuf::registry::routing_table::v1::{
        CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
    };
    use ic_registry_keys::make_canister_migrations_record_key;
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;
    use std::convert::TryFrom;

    fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
        check_routing_table_invariants(snapshot).unwrap()
    }

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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );
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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );
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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );

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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );

        // Reassign ranges in routing table.
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xf) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x10), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        }).unwrap();

        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );

        // Complete canister migrations by removing entries.
        snapshot.insert(
            make_canister_migrations_record_key().into_bytes(),
            PbCanisterMigrations { entries: vec![] }.encode_to_vec(),
        );
        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );
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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );

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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_err()
        );
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
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_ok()
        );

        // The new routing table after reassigning ranges.

        // Case 1: cannot find the entry containing `range.start` of canister migrations when looking up entries in the routing table,
        let new_routing_table_1 = RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x1), end: CanisterId::from(0xff) } => subnet_test_id(1),
        CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
    }).unwrap();

        insert_routing_table_to_snapshot(new_routing_table_1, &mut snapshot);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_err()
        );

        // Case 2: find the entry containing `range.start` but the entry cannot fully cover the canister migration range {0x0:0xff}.
        let new_routing_table_2 = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0x1) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
            CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
        }).unwrap();

        insert_routing_table_to_snapshot(new_routing_table_2, &mut snapshot);

        assert!(check_routing_table_invariants(&snapshot).is_ok());
        assert!(
            check_canister_migrations_invariants(&snapshot, &get_routing_table(&snapshot)).is_err()
        );
    }

    #[test]
    fn test_overlapping_routing_table_shards_fail_invariants_check() {
        // Step 1: Prepare the world: two shards whose ranges overlap.
        let mut snapshot = RegistrySnapshot::new();
        for (shard_key, start, end, subnet_id) in [
            (0x000, 0x000, 0x1ff, subnet_test_id(1)),
            (0x100, 0x100, 0x2ff, subnet_test_id(2)),
        ] {
            let range = CanisterIdRange {
                start: CanisterId::from(start),
                end: CanisterId::from(end),
            };
            let shard = RoutingTable::try_from(btreemap! { range => subnet_id }).unwrap();
            snapshot.insert(
                make_canister_ranges_key(CanisterId::from(shard_key)).into_bytes(),
                PbRoutingTable::from(shard).encode_to_vec(),
            );
        }

        // Step 2: Run the code under test.
        let result = check_routing_table_invariants(&snapshot);

        // Step 3: Verify result: an error, not a panic.
        let error = result.unwrap_err();

        // Step 3.1: The message blames the shards as a whole, since no single
        // shard is invalid on its own.
        assert!(
            error
                .msg
                .contains("routing table shards do not form a valid routing table"),
            "{}",
            error.msg
        );

        // Step 3.2: The source pinpoints the overlap: the second shard's range
        // starts at 0x100, before the first shard's range ends at 0x1ff.
        let source = error
            .source
            .as_ref()
            .expect("the error should have a source")
            .downcast_ref::<ProxyDecodeError>()
            .expect("the source should be a ProxyDecodeError");
        let ProxyDecodeError::Other(source_msg) = source else {
            panic!("expected ProxyDecodeError::Other, got {source:?}");
        };
        assert!(
            source_msg.contains("RoutingTableNotDisjoint"),
            "{source_msg}"
        );
        let overlap_start = format!("current start {}", CanisterId::from(0x100));
        assert!(source_msg.contains(&overlap_start), "{source_msg}");
    }

    #[test]
    fn test_undecodable_routing_table_shard_fails_invariants_check() {
        // Step 1: Prepare the world.
        let mut snapshot = RegistrySnapshot::new();
        let shard_key = make_canister_ranges_key(CanisterId::from(0));
        snapshot.insert(shard_key.clone().into_bytes(), b"not a protobuf".to_vec());

        // Step 2: Run the code under test.
        let result = check_routing_table_invariants(&snapshot);

        // Step 3: Verify result: an error naming the shard, not a panic.
        let error = result.unwrap_err();
        assert!(error.msg.contains("Unable to decode"), "{}", error.msg);
        assert!(error.msg.contains(&shard_key), "{}", error.msg);
        assert!(error.source.is_some());
    }

    fn insert_canister_id_allocation_to_snapshot(
        next_unallocated_canister_index: u64,
        snapshot: &mut RegistrySnapshot,
    ) {
        let canister_id_allocation = pbCanisterIdAllocation {
            next_unallocated_canister_index,
        };
        snapshot.insert(
            make_canister_id_allocation_key().into_bytes(),
            canister_id_allocation.encode_to_vec(),
        );
    }

    fn new_snapshot_with_routing_table_up_to_0x1ff() -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot::new();
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
        })
        .unwrap();
        insert_routing_table_to_snapshot(routing_table, &mut snapshot);
        snapshot
    }

    #[test]
    fn test_absent_canister_id_allocation_passes_invariants_check() {
        let snapshot = new_snapshot_with_routing_table_up_to_0x1ff();

        assert!(
            check_canister_id_allocation_invariants(
                &snapshot,
                &get_routing_table(&snapshot),
                /* previous_next_unallocated_canister_index = */ None
            )
            .is_ok()
        );
    }

    #[test]
    fn test_canister_id_allocation_covering_routing_table_passes_invariants_check() {
        let mut snapshot = new_snapshot_with_routing_table_up_to_0x1ff();
        // Above the routing table, e.g., because the subnet that held 0x200..=0x2ff was deleted.
        insert_canister_id_allocation_to_snapshot(0x300, &mut snapshot);

        assert!(
            check_canister_id_allocation_invariants(
                &snapshot,
                &get_routing_table(&snapshot),
                /* previous_next_unallocated_canister_index = */ None
            )
            .is_ok()
        );
        assert!(
            check_canister_id_allocation_invariants(
                &snapshot,
                &get_routing_table(&snapshot),
                /* previous_next_unallocated_canister_index = */ Some(0x200)
            )
            .is_ok()
        );
        assert!(
            check_canister_id_allocation_invariants(
                &snapshot,
                &get_routing_table(&snapshot),
                /* previous_next_unallocated_canister_index = */ Some(0x300)
            )
            .is_ok()
        );
    }

    #[test]
    fn test_routing_table_beyond_canister_id_allocation_fails_invariants_check() {
        // The routing table ends at 0x1ff, so every value up to (and including) 0x1ff is too low.
        for next_unallocated_canister_index in [0, 1, 2, 0xff, 0x100, 0x101, 0x1fe, 0x1ff] {
            let mut snapshot = new_snapshot_with_routing_table_up_to_0x1ff();
            insert_canister_id_allocation_to_snapshot(
                next_unallocated_canister_index,
                &mut snapshot,
            );

            let error = check_canister_id_allocation_invariants(
                &snapshot,
                &get_routing_table(&snapshot),
                /* previous_next_unallocated_canister_index = */ None,
            )
            .unwrap_err();

            assert!(error.msg.contains("at or above"), "{}", error.msg);
            assert!(
                error.msg.contains(&subnet_test_id(2).to_string()),
                "{}",
                error.msg
            );
        }
    }

    #[test]
    fn test_routing_table_beyond_canister_id_allocation_in_earlier_shard_fails_invariants_check() {
        // Step 1: Prepare the world. The shard with the larger key holds the lower range, which
        // the routing table invariants do not rule out. So the highest range, 0x200..=0x2ff, is in
        // the shard with the smaller key, and the last shard ends at 0x1ff.
        let mut snapshot = RegistrySnapshot::new();
        let shards = [
            (0x000, 0x200, 0x2ff, subnet_test_id(1)),
            (0x100, 0x100, 0x1ff, subnet_test_id(2)),
        ];
        for (shard_key, start, end, subnet_id) in shards {
            let range = CanisterIdRange {
                start: CanisterId::from(start),
                end: CanisterId::from(end),
            };
            let shard = RoutingTable::try_from(btreemap! { range => subnet_id }).unwrap();
            snapshot.insert(
                make_canister_ranges_key(CanisterId::from(shard_key)).into_bytes(),
                PbRoutingTable::from(shard).encode_to_vec(),
            );
        }
        // The bomb lies here: the table maxes out at 0x2ff,
        // so this needs to be at least 0x300.
        insert_canister_id_allocation_to_snapshot(0x200, &mut snapshot);

        // Step 2: Run the code under test.
        let result = check_canister_id_allocation_invariants(
            &snapshot,
            &get_routing_table(&snapshot),
            /* previous_next_unallocated_canister_index = */ None,
        );

        // Step 3: Verify result. The range 0x200..=0x2ff of subnet 1 must be detected.
        let error = result.unwrap_err();
        assert!(error.msg.contains("at or above"), "{}", error.msg);
        assert!(
            error.msg.contains(&subnet_test_id(1).to_string()),
            "{}",
            error.msg
        );
    }

    #[test]
    fn test_decreasing_canister_id_allocation_fails_invariants_check() {
        let mut snapshot = new_snapshot_with_routing_table_up_to_0x1ff();
        // On its own, 0x200 is valid: the routing table ends at 0x1ff. The check should fail only
        // because the previous value (0x300, passed below) is higher, i.e., this is a decrease.
        insert_canister_id_allocation_to_snapshot(0x200, &mut snapshot);

        let error = check_canister_id_allocation_invariants(
            &snapshot,
            &get_routing_table(&snapshot),
            /* previous_next_unallocated_canister_index = */ Some(0x300),
        )
        .unwrap_err();

        assert!(error.msg.contains("never decrease"), "{}", error.msg);
    }

    #[test]
    fn test_undecodable_canister_id_allocation_fails_invariants_check() {
        let mut snapshot = new_snapshot_with_routing_table_up_to_0x1ff();
        snapshot.insert(
            make_canister_id_allocation_key().into_bytes(),
            b"not a protobuf".to_vec(),
        );

        let error = check_canister_id_allocation_invariants(
            &snapshot,
            &get_routing_table(&snapshot),
            /* previous_next_unallocated_canister_index = */ None,
        )
        .unwrap_err();

        assert!(error.msg.contains("Unable to decode"), "{}", error.msg);
        assert!(error.source.is_some());
    }

    #[test]
    fn test_deleting_canister_id_allocation_fails_invariants_check() {
        let snapshot = new_snapshot_with_routing_table_up_to_0x1ff();

        let error = check_canister_id_allocation_invariants(
            &snapshot,
            &get_routing_table(&snapshot),
            /* previous_next_unallocated_canister_index = */ Some(0x200),
        )
        .unwrap_err();

        assert!(error.msg.contains("must not be deleted"), "{}", error.msg);
    }
}
