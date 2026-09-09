use crate::{
    invariants::{
        common::{InvariantCheckError, RegistrySnapshot},
        subnet::get_subnet_records_map,
    },
    mutations::common::normalized_canister_cycles_cost_schedule,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};

use ic_base_types::{CanisterId, SubnetId};
use ic_protobuf::registry::{
    routing_table::v1::{
        CanisterMigrations as pbCanisterMigrations, RoutingTable as pbRoutingTable,
    },
    subnet::v1::CanisterCyclesCostSchedule,
};
use ic_registry_keys::{
    make_canister_migrations_record_key, make_canister_ranges_key, make_subnet_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
use prost::Message;

/// Routing table invariants hold if reading and conversion succeed.
pub(crate) fn check_routing_table_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    get_routing_table(snapshot);
    Ok(())
}

/// Checks that the cycles cost schedule that a canister is charged under never
/// changes.
///
/// That schedule has to stay put for as long as the canister has calls in flight: the
/// cycles prepaid for a response execution are settled against the cycles that
/// execution requires, derived when the response is executed
/// (`CyclesAccountManager::adjust_prepayment_for_response_execution`), and the two
/// amounts are only comparable if both were derived under the same cost schedule. An
/// amount that is free under the free cost schedule has a zero real part but a
/// non-zero nominal one, so settling across a switch either forfeits the real part of
/// the prepayment or credits real cycles that were never withdrawn.
///
/// A canister is charged under the cost schedule of the subnet that the routing table
/// assigns its canister ID to, so this compares, for every canister ID hosted before
/// and after the mutations under check, the cost schedule of the subnet that hosted it
/// with the one of the subnet that hosts it now. That covers both ways of changing it,
/// in any combination, and hence every mutation that could:
///
/// - moving the canister to a subnet on a different cost schedule, be it with
///   `reroute_canister_ranges` (the second step of a canister migration),
///   `merge_subnets` or `do_migrate_canisters`. The latter two compare the cost
///   schedules themselves, as does `prepare_canister_migration`, on which
///   `reroute_canister_ranges` relies: rerouting compares nothing of its own, it only
///   reroutes ranges that an already validated canister migration covers. Those
///   comparisons report which subnets, or which canister, are at fault, whereas this
///   invariant only names the affected canister ID range;
/// - changing the cost schedule of the subnet hosting the canister, which
///   `check_subnet_cost_schedule_immutability` rules out outright.
///
/// The two routing tables are restricted to the canister ranges shards that the
/// mutations under check touch, as reading the whole routing table on every mutation
/// is not free. That is sound: a canister ID whose covering entry did not change is
/// still assigned to the same subnet, and the cost schedule of that subnet cannot have
/// changed either, which `check_subnet_cost_schedule_immutability` enforces. Note that
/// an entry can move between shards, e.g. when two adjacent ranges are merged into one,
/// which mutates the shard it leaves as well as the shard it lands in.
///
/// `previous_cost_schedules` maps the registry key of a subnet record to the cost
/// schedule that subnet had before the mutations under check were applied. A canister
/// ID whose cost schedule is unknown on either side is skipped: a subnet without a
/// record in the corresponding state hosts no canister.
///
/// # Limitation: canister IDs that pass through an unrouted state
///
/// An unrouted canister ID has no cost schedule, so this only covers the canister IDs
/// that are routed both before and after the mutations under check. A canister ID is
/// unrouted by `do_migrate_canisters` when the target subnet is absent from the
/// routing table, and by `remove_subnet_from_routing_table` when its subnet is
/// deleted; `do_migrate_canisters` then supports routing it to a subnet again, which
/// is how a canister whose subnet was deleted is migrated
/// (`test_migrate_canisters_succeeds_if_source_subnet_deleted`). Two such mutations in
/// a row move a canister ID between subnets on different cost schedules without either
/// this invariant or `Registry::validate_cost_schedules` ever seeing two schedules to
/// compare, and unrouting a canister ID does not destroy the canister state, callbacks
/// included.
///
/// Closing that gap would take either persistent knowledge of the cost schedule each
/// unrouted canister ID last had, or making unrouting terminal, which would break the
/// migration of a canister off a deleted subnet. It is left open: reaching it takes a
/// canister migration orchestrator that unroutes a canister and then routes it to a
/// subnet on a different cost schedule.
pub(crate) fn check_canister_cost_schedule_invariants(
    previous_routing_table: &RoutingTable,
    routing_table: &RoutingTable,
    previous_cost_schedules: &BTreeMap<Vec<u8>, CanisterCyclesCostSchedule>,
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let cost_schedules: BTreeMap<Vec<u8>, CanisterCyclesCostSchedule> =
        get_subnet_records_map(snapshot)
            .iter()
            .map(|(key, subnet_record)| {
                (
                    key.clone(),
                    normalized_canister_cycles_cost_schedule(subnet_record),
                )
            })
            .collect();
    let cost_schedule = |cost_schedules: &BTreeMap<Vec<u8>, CanisterCyclesCostSchedule>,
                         subnet_id: SubnetId| {
        cost_schedules
            .get(&make_subnet_record_key(subnet_id).into_bytes())
            .copied()
    };

    // The ranges of a routing table are disjoint and listed in ascending order, so a
    // single sweep over both routing tables finds every pair of overlapping ranges,
    // i.e. every set of canister IDs that is hosted in both states.
    let previous_entries = as_entries(previous_routing_table);
    let entries = as_entries(routing_table);
    let (mut previous_index, mut index) = (0, 0);
    while previous_index < previous_entries.len() && index < entries.len() {
        let (previous_range, previous_subnet_id) = previous_entries[previous_index];
        let (range, subnet_id) = entries[index];

        if previous_range.end < range.start {
            previous_index += 1;
            continue;
        }
        if range.end < previous_range.start {
            index += 1;
            continue;
        }

        // The two ranges overlap: the canisters in the intersection were hosted by
        // `previous_subnet_id` and are hosted by `subnet_id` as of this snapshot.
        if let Some(previous_cost_schedule) =
            cost_schedule(previous_cost_schedules, previous_subnet_id)
            && let Some(cost_schedule) = cost_schedule(&cost_schedules, subnet_id)
            && previous_cost_schedule != cost_schedule
        {
            // Only the intersection of the two ranges changes its cost schedule: the
            // rest of either range is hosted by the same subnet in both states, is
            // newly assigned, or is not hosted anymore.
            let affected_range = CanisterIdRange {
                start: previous_range.start.max(range.start),
                end: previous_range.end.min(range.end),
            };
            return Err(InvariantCheckError {
                msg: format!(
                    "canister ID range {affected_range:?} changes its cycles cost schedule \
                    from {previous_cost_schedule:?} on subnet {previous_subnet_id} to \
                    {cost_schedule:?} on subnet {subnet_id}"
                ),
                source: None,
            });
        }

        // Advance past the range that ends first: the other one may still overlap the
        // next range of the routing table it does not belong to.
        if previous_range.end <= range.end {
            previous_index += 1;
        } else {
            index += 1;
        }
    }

    Ok(())
}

/// Returns the routing table restricted to the given canister ranges shards, as held
/// by `snapshot`. A shard that the mutations under check deleted is simply absent.
///
/// The shards are given as a set: decoding one of them twice would produce duplicate
/// entries, which `RoutingTable` rejects.
pub(crate) fn canister_ranges_from_snapshot(
    shard_keys: &BTreeSet<Vec<u8>>,
    snapshot: &RegistrySnapshot,
) -> RoutingTable {
    let shards = shard_keys
        .iter()
        .filter_map(|key| snapshot.get(key))
        .map(|value| pbRoutingTable::decode(value.as_slice()).unwrap())
        .collect::<Vec<_>>();
    RoutingTable::try_from(shards).unwrap()
}

fn as_entries(routing_table: &RoutingTable) -> Vec<(CanisterIdRange, SubnetId)> {
    routing_table
        .iter()
        .map(|(range, subnet_id)| (*range, *subnet_id))
        .collect()
}

// Return routing table from snapshot
fn get_routing_table(snapshot: &RegistrySnapshot) -> RoutingTable {
    // If there are shards, they should match the routing table record.
    let shards = get_routing_table_shards(snapshot);
    RoutingTable::try_from(shards).unwrap()
}

fn get_routing_table_shards(snapshot: &RegistrySnapshot) -> Vec<pbRoutingTable> {
    let start = make_canister_ranges_key(CanisterId::from_u64(0)).into_bytes();
    let end = make_canister_ranges_key(CanisterId::from_u64(u64::MAX)).into_bytes();
    let mut shards = vec![];
    for (_, value) in snapshot.range(start..=end) {
        let routing_table_proto = pbRoutingTable::decode(value.as_slice()).unwrap();
        shards.push(routing_table_proto);
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
    use crate::mutations::common::normalized_canister_cycles_cost_schedule as normalized_cost_schedule;
    use ic_base_types::CanisterId;
    use ic_protobuf::registry::routing_table::v1::{
        CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
    };
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_keys::make_canister_migrations_record_key;
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;
    use std::convert::TryFrom;

    fn subnet_record(cost_schedule: CanisterCyclesCostSchedule) -> SubnetRecord {
        SubnetRecord {
            canister_cycles_cost_schedule: i32::from(cost_schedule),
            ..Default::default()
        }
    }

    fn insert_subnet_record_to_snapshot(
        subnet_id: SubnetId,
        cost_schedule: CanisterCyclesCostSchedule,
        snapshot: &mut RegistrySnapshot,
    ) {
        snapshot.insert(
            make_subnet_record_key(subnet_id).into_bytes(),
            subnet_record(cost_schedule).encode_to_vec(),
        );
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

    /// The cycles cost schedule a canister is charged under must not change, be it by
    /// moving the canister to a subnet on a different cost schedule or by changing the
    /// cost schedule of the subnet hosting it.
    #[test]
    fn canister_cost_schedule_is_immutable() {
        // Two subnets on the normal cost schedule and one on the free one, as a rental
        // subnet is.
        let normal_subnet_id = subnet_test_id(1);
        let other_normal_subnet_id = subnet_test_id(2);
        let free_subnet_id = subnet_test_id(3);

        // A subnet record that predates the field leaves it `Unspecified`, which means
        // the same as `Normal`.
        let cost_schedules = btreemap! {
            normal_subnet_id => CanisterCyclesCostSchedule::Normal,
            other_normal_subnet_id => CanisterCyclesCostSchedule::Unspecified,
            free_subnet_id => CanisterCyclesCostSchedule::Free,
        };
        let previous_cost_schedules = cost_schedules
            .iter()
            .map(|(subnet_id, cost_schedule)| {
                (
                    make_subnet_record_key(*subnet_id).into_bytes(),
                    normalized_cost_schedule(&subnet_record(*cost_schedule)),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut snapshot = RegistrySnapshot::new();
        for (subnet_id, cost_schedule) in &cost_schedules {
            insert_subnet_record_to_snapshot(*subnet_id, *cost_schedule, &mut snapshot);
        }

        let range = |start: u64, end: u64| CanisterIdRange {
            start: CanisterId::from(start),
            end: CanisterId::from(end),
        };
        let routing_table = |entries: Vec<(CanisterIdRange, SubnetId)>| {
            RoutingTable::try_from(entries.into_iter().collect::<BTreeMap<_, _>>()).unwrap()
        };
        let previous_routing_table = routing_table(vec![
            (range(0x0, 0xff), normal_subnet_id),
            (range(0x100, 0x1ff), free_subnet_id),
        ]);

        let check = |entries: Vec<(CanisterIdRange, SubnetId)>, snapshot: &RegistrySnapshot| {
            check_canister_cost_schedule_invariants(
                &previous_routing_table,
                &routing_table(entries),
                &previous_cost_schedules,
                snapshot,
            )
        };

        // Leaving the routing table alone is fine, ...
        check(
            vec![
                (range(0x0, 0xff), normal_subnet_id),
                (range(0x100, 0x1ff), free_subnet_id),
            ],
            &snapshot,
        )
        .unwrap();
        // ... as is moving a range to a subnet on the same cost schedule, splitting it
        // in the process, ...
        check(
            vec![
                (range(0x0, 0x7f), normal_subnet_id),
                (range(0x80, 0xff), other_normal_subnet_id),
                (range(0x100, 0x1ff), free_subnet_id),
            ],
            &snapshot,
        )
        .unwrap();
        // ... dropping a range, ...
        check(vec![(range(0x100, 0x1ff), free_subnet_id)], &snapshot).unwrap();
        // ... or assigning a range that was not hosted by any subnet before.
        check(
            vec![
                (range(0x0, 0xff), normal_subnet_id),
                (range(0x100, 0x1ff), free_subnet_id),
                (range(0x200, 0x2ff), free_subnet_id),
            ],
            &snapshot,
        )
        .unwrap();

        // Moving a range to a subnet on a different cost schedule is not, in either
        // direction, and neither is moving only a part of it. The reported range is the
        // part that actually changed its cost schedule, i.e. the intersection of the
        // range hosting the canisters before and the one hosting them now.
        for (entries, affected_range) in [
            (
                vec![
                    (range(0x0, 0xff), free_subnet_id),
                    (range(0x100, 0x1ff), free_subnet_id),
                ],
                range(0x0, 0xff),
            ),
            // Only the second half of the first range moves.
            (
                vec![
                    (range(0x0, 0x7f), normal_subnet_id),
                    (range(0x80, 0xff), free_subnet_id),
                    (range(0x100, 0x1ff), free_subnet_id),
                ],
                range(0x80, 0xff),
            ),
            (
                vec![
                    (range(0x0, 0xff), normal_subnet_id),
                    (range(0x100, 0x1ff), normal_subnet_id),
                ],
                range(0x100, 0x1ff),
            ),
            // The two ranges are merged into one hosted by the subnet that hosted the
            // second one all along, so only the first one changes its cost schedule.
            (vec![(range(0x0, 0x1ff), free_subnet_id)], range(0x0, 0xff)),
        ] {
            let err = check(entries, &snapshot)
                .expect_err("Expected the move across cost schedules to be rejected");
            assert!(
                err.msg.contains("changes its cycles cost schedule"),
                "unexpected error message: {}",
                err.msg
            );
            assert!(
                err.msg.contains(&format!("{affected_range:?}")),
                "expected {affected_range:?} to be reported: {}",
                err.msg
            );
        }

        // Neither is changing the cost schedule of the subnet hosting a range, even
        // with the routing table left alone.
        insert_subnet_record_to_snapshot(
            normal_subnet_id,
            CanisterCyclesCostSchedule::Free,
            &mut snapshot,
        );
        let err = check(
            vec![
                (range(0x0, 0xff), normal_subnet_id),
                (range(0x100, 0x1ff), free_subnet_id),
            ],
            &snapshot,
        )
        .expect_err("Expected the change of the cost schedule to be rejected");
        assert!(
            err.msg.contains("changes its cycles cost schedule"),
            "unexpected error message: {}",
            err.msg
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
