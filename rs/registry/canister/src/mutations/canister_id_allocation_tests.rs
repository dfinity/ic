use super::*;
use crate::mutations::routing_table::routing_table_into_registry_mutation;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_registry_routing_table::{
    CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable, routing_table_insert_subnet,
};
use ic_registry_transport::{delete, insert};
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::SubnetId;

const N: u64 = CANISTER_IDS_PER_SUBNET;

fn new_canister_id_range(start: u64, end: u64) -> CanisterIdRange {
    CanisterIdRange {
        start: CanisterId::from(start),
        end: CanisterId::from(end),
    }
}

/// Returns the ranges of `subnet_id` in the latest routing table, as (start, end) pairs.
fn get_subnet_ranges(registry: &Registry, subnet_id: SubnetId) -> Vec<(u64, u64)> {
    registry
        .get_routing_table_or_panic(registry.latest_version())
        .iter()
        .filter(|(_, owner)| **owner == subnet_id)
        .map(|(range, _)| {
            (
                canister_id_into_u64(range.start),
                canister_id_into_u64(range.end),
            )
        })
        .collect::<Vec<(u64, u64)>>()
}

fn add_subnet(registry: &mut Registry, subnet_id: SubnetId) {
    let mutations = registry.add_subnet_to_routing_table(registry.latest_version(), subnet_id);
    registry.apply_mutations_for_test(mutations);
}

fn remove_subnet(registry: &mut Registry, subnet_id: SubnetId) {
    let mutations = registry.remove_subnet_from_routing_table(registry.latest_version(), subnet_id);
    registry.apply_mutations_for_test(mutations);
}

/// Replaces the routing table by `routing_table`, without touching the CanisterIdAllocation. This
/// mimics the registry before the CanisterIdAllocation was introduced.
fn set_routing_table_without_canister_id_allocation(
    registry: &mut Registry,
    routing_table: RoutingTable,
) {
    let mutations = routing_table_into_registry_mutation(registry, routing_table);
    registry.apply_mutations_for_test(mutations);
}

#[test]
fn test_add_subnet_does_not_reuse_canister_ids_of_deleted_last_subnet() {
    // Step 1: Prepare the world: subnets 1 and 2 exist, and then subnet 2 (holding the last
    // range) is deleted.
    let mut registry = Registry::new();
    add_subnet(&mut registry, subnet_test_id(1));
    add_subnet(&mut registry, subnet_test_id(2));
    assert_eq!(
        get_subnet_ranges(&registry, subnet_test_id(2)),
        vec![(N, 2 * N - 1)]
    );
    remove_subnet(&mut registry, subnet_test_id(2));

    // Step 2: Run the code under test.
    add_subnet(&mut registry, subnet_test_id(3));

    // Step 3: Verify results.

    // Step 3.1: Subnet 3 got fresh canister IDs, not those of subnet 2.
    assert_eq!(
        get_subnet_ranges(&registry, subnet_test_id(3)),
        vec![(2 * N, 3 * N - 1)]
    );

    // Step 3.2: The CanisterIdAllocation accounts for subnet 3's range.
    assert_eq!(
        registry.get_next_unallocated_canister_index(registry.latest_version()),
        3 * N
    );
}

#[test]
fn test_add_subnet_without_canister_id_allocation_uses_history() {
    // Step 1: Prepare the world: a routing table written without a CanisterIdAllocation (as
    // before its introduction), in which subnet 2 (holding the last range) is then deleted.

    // Step 1.1: Insert a couple of subnets into routing_table.
    let mut routing_table = RoutingTable::new();
    let next_unallocated_canister_index = routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(1),
        /* next_unallocated_canister_index = */ 0,
    )
    .unwrap();
    routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(2),
        next_unallocated_canister_index,
    )
    .unwrap();

    // Step 1.2: Insert routing_table into Registry.
    let mut registry = Registry::new();
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table.clone());

    // Step 1.3: Remove subnet 2 from registry, but without updating CanisterIdAllocation.
    routing_table.remove_subnet(subnet_test_id(2));
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table);

    // Step 1.4: Verify setup: No CanisterIdAllocation record. Despite this,
    // subnet 2's canister IDs will not get recycled, because, subnet 2 is
    // still in history, even though it is not in the most recent snapshot.
    assert_eq!(
        registry.get(
            make_canister_id_allocation_key().as_bytes(),
            registry.latest_version()
        ),
        None
    );

    // Step 2: Run the code under test.
    add_subnet(&mut registry, subnet_test_id(3));

    // Step 3: Verify result: subnet 3 got fresh canister IDs, not those of subnet 2.
    assert_eq!(
        get_subnet_ranges(&registry, subnet_test_id(3)),
        vec![(2 * N, 3 * N - 1)]
    );
}

#[test]
fn test_compute_next_unallocated_canister_index_from_history() {
    // Step 1: Prepare the world: three routing table versions, the last of which no longer
    // contains subnet 2. This is like the previous test, except that it also stores a version in
    // which the routing table only contains subnet 1 (Step 1.1).

    // Step 1.1: Insert a routing table containing only subnet 1 into registry, and remember its
    // version. This is the one thing that the previous test does not do.
    let mut routing_table = RoutingTable::new();
    let next_unallocated_canister_index = routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(1),
        /* next_unallocated_canister_index = */ 0,
    )
    .unwrap();
    let mut registry = Registry::new();
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table.clone());
    let version_with_subnet_1 = registry.latest_version();

    // Step 1.2: Add subnet 2 to the routing table in registry.
    routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(2),
        next_unallocated_canister_index,
    )
    .unwrap();
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table.clone());

    // Step 1.3: Remove subnet 2 from registry, but without updating CanisterIdAllocation.
    routing_table.remove_subnet(subnet_test_id(2));
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table);

    // Step 2: Run the code under test.
    let at_latest_version =
        registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());
    let at_version_with_subnet_1 =
        registry.compute_next_unallocated_canister_index_from_history(version_with_subnet_1);

    // Step 3: Verify results.

    // Step 3.1: At the latest version, subnet 2's deleted range still counts.
    assert_eq!(at_latest_version, 2 * N);

    // Step 3.2: Versions after the requested one are ignored.
    assert_eq!(at_version_with_subnet_1, N);
}

#[test]
fn test_compute_next_unallocated_canister_index_from_history_without_routing_table() {
    // Step 1: Prepare the world: a registry that never had a routing table.
    let registry = Registry::new();

    // Step 2: Run the code under test.
    let next_unallocated_canister_index =
        registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());

    // Step 3: Verify result: nothing has been allocated.
    assert_eq!(next_unallocated_canister_index, 0);
}

#[test]
fn test_compute_next_unallocated_canister_index_from_history_includes_legacy_routing_table() {
    // Step 1: Prepare the world: the legacy single-key routing table held a range that is not in
    // any shard, and has since been deleted.

    // Step 1.1: Monolithic/legacy RoutingTable with one canister range/subnet.
    let mut legacy_routing_table = RoutingTable::new();
    legacy_routing_table
        .insert(new_canister_id_range(0, 5 * N - 1), subnet_test_id(1))
        .unwrap();

    // Step 1.2: Directly populate new Registry with legacy_routing_table.
    let mut registry = Registry::new();
    let legacy_key = make_routing_table_record_key();
    registry.apply_mutations_for_test(vec![insert(
        &legacy_key,
        pb::RoutingTable::from(legacy_routing_table).encode_to_vec(),
    )]);

    // Step 1.3: In a subsequent mutation, delete the whole routing table from registry.
    registry.apply_mutations_for_test(vec![delete(&legacy_key)]);

    // Step 1.4: Add a second subnet.
    add_subnet(&mut registry, subnet_test_id(2));

    // Step 2: Run the code under test.
    let next_unallocated_canister_index =
        registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());

    // Step 3: Verify result: the legacy range counts, and so does subnet 2, which was added after
    // it (and was therefore placed after it, too).
    assert_eq!(
        get_subnet_ranges(&registry, subnet_test_id(2)),
        vec![(5 * N, 6 * N - 1)]
    );
    assert_eq!(next_unallocated_canister_index, 6 * N);
}

#[test]
fn test_compute_next_unallocated_canister_index_from_history_includes_legacy_uint64_encoding() {
    // Step 1: Prepare the world: a deleted version of the legacy single-key routing table, in the
    // very old encoding where range ends were plain u64 canister indices. Today's
    // `pb::RoutingTable` would not see this range at all.

    // Step 1.1: Initial RoutingTable using the legacy schema.
    let legacy_routing_table = LegacyCompatibleRoutingTable {
        entries: vec![LegacyCompatibleRoutingTableEntry {
            range: Some(LegacyCompatibleCanisterIdRange {
                legacy_end: Some(7 * N - 1),
                end_canister_id: None,
            }),
        }],
    }
    .encode_to_vec();

    // Step 1.2: Verify that when encoding from LegacyCompatibleRoutingTable,
    // and decoding back to the current RoutingTable, we see no end
    // in the one range therein.
    assert_eq!(
        pb::RoutingTable::decode(legacy_routing_table.as_slice())
            .unwrap()
            .entries[0]
            .range
            .as_ref()
            .unwrap()
            .end_canister_id,
        None
    );

    // Step 1.3: Directly insert legacy_routing_table into fresh Registry.
    let mut registry = Registry::new();
    let legacy_key = make_routing_table_record_key();
    registry.apply_mutations_for_test(vec![insert(&legacy_key, legacy_routing_table)]);

    // Step 1.4: Delete the entire routing table from registry.
    registry.apply_mutations_for_test(vec![delete(&legacy_key)]);

    // Step 2: Run the code under test.
    let next_unallocated_canister_index =
        registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());

    // Step 3: Verify result: the legacy range counts.
    assert_eq!(next_unallocated_canister_index, 7 * N);
}

#[test]
fn test_backfill_canister_id_allocation() {
    // Step 1: Prepare the world: as in the registry before the CanisterIdAllocation was
    // introduced, subnet 2 (holding the last range) has been deleted.
    let mut registry = Registry::new();
    let mut routing_table = RoutingTable::new();
    let next_unallocated_canister_index = routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(1),
        /* next_unallocated_canister_index = */ 0,
    )
    .unwrap();
    routing_table_insert_subnet(
        &mut routing_table,
        subnet_test_id(2),
        next_unallocated_canister_index,
    )
    .unwrap();
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table.clone());
    routing_table.remove_subnet(subnet_test_id(2));
    set_routing_table_without_canister_id_allocation(&mut registry, routing_table);

    // Step 2: Run the code under test.
    let mutations = backfill_canister_id_allocation(&registry);

    // Step 3: Verify results.

    // Step 3.1: The backfill accounts for the deleted subnet's range.
    assert_eq!(mutations, vec![make_canister_id_allocation_mutation(2 * N)]);

    // Step 3.2: Once applied, a second backfill is a no-op.
    registry.apply_mutations_for_test(mutations);
    assert_eq!(backfill_canister_id_allocation(&registry), vec![]);
}

#[test]
fn test_backfill_canister_id_allocation_without_routing_table_is_a_noop() {
    // Step 1: Prepare the world: a registry that never had a routing table.
    let registry = Registry::new();

    // Step 2: Run the code under test.
    let mutations = backfill_canister_id_allocation(&registry);

    // Step 3: Verify result: nothing has been allocated, so there is nothing to record.
    assert_eq!(mutations, vec![]);
}

#[test]
#[should_panic(expected = "no canister index is left unallocated")]
fn test_compute_next_unallocated_canister_index_from_history_panics_on_range_ending_at_u64_max() {
    // Step 1: Prepare the world: a (deleted) version of the legacy single-key routing table with a
    // range that ends at the largest canister index.
    let legacy_routing_table = LegacyCompatibleRoutingTable {
        entries: vec![LegacyCompatibleRoutingTableEntry {
            range: Some(LegacyCompatibleCanisterIdRange {
                legacy_end: Some(u64::MAX),
                end_canister_id: None,
            }),
        }],
    }
    .encode_to_vec();
    let mut registry = Registry::new();
    let legacy_key = make_routing_table_record_key();
    registry.apply_mutations_for_test(vec![insert(&legacy_key, legacy_routing_table)]);
    registry.apply_mutations_for_test(vec![delete(&legacy_key)]);

    // Step 2: Run the code under test. Step 3: Verify result: it panics (see `should_panic`),
    // rather than wrapping around to 0.
    registry.compute_next_unallocated_canister_index_from_history(registry.latest_version());
}
