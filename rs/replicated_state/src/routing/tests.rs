use super::{find_canisters_not_in_routing_table, find_canisters_to_remove};
use crate::*;
use ic_base_types::{CanisterId, NumSeconds, SubnetId};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities::types::ids::subnet_test_id;
use ic_types::Cycles;
use proptest::prop_assert_eq;
use proptest::test_runner::TestRunner;
use std::convert::TryFrom;
use std::sync::Arc;

fn make_state(subnet_id: SubnetId) -> ReplicatedState {
    ReplicatedState::new_rooted_at(subnet_id, SubnetType::System, "NOT_USED".into())
}

fn add_canister(state: &mut ReplicatedState, canister_id: CanisterId) {
    state.canister_states.insert(
        canister_id,
        CanisterState {
            system_state: SystemState::new_running(
                /* canister_id: */ canister_id,
                /* controller: */ canister_id.into(),
                /* initial_cycles: */ Cycles::new(5_000_000_000_000),
                /* freeze_threshold: */ NumSeconds::new(3600),
            ),
            execution_state: None,
            scheduler_state: SchedulerState::default(),
        },
    );
}

fn add_route(state: &mut ReplicatedState, from: u64, to: u64, destination: SubnetId) {
    Arc::make_mut(&mut state.metadata.network_topology.routing_table)
        .insert(
            CanisterIdRange {
                start: CanisterId::from(from),
                end: CanisterId::from(to),
            },
            destination,
        )
        .expect("failed to insert a range into the routing table");
}

fn add_canister_migrations(
    state: &mut ReplicatedState,
    from: u64,
    to: u64,
    source: SubnetId,
    destination: SubnetId,
) {
    Arc::make_mut(&mut state.metadata.network_topology.canister_migrations)
        .insert_ranges(
            CanisterIdRanges::try_from(vec![CanisterIdRange {
                start: CanisterId::from(from),
                end: CanisterId::from(to),
            }])
            .expect("Canister ID ranges are not well formed"),
            source,
            destination,
        )
        .expect("failed to insert a range into the canister migrations");
}

#[test]
fn canisters_not_in_rt_empty_rt() {
    let canister_ids: Vec<_> = vec![
        CanisterId::from(0),
        CanisterId::from(1),
        CanisterId::from(2),
        CanisterId::from(u64::MAX),
    ];
    let state = {
        let mut state = make_state(subnet_test_id(1));
        for canister_id in canister_ids.iter() {
            add_canister(&mut state, *canister_id);
        }
        state
    };
    assert_eq!(
        find_canisters_not_in_routing_table(&state, subnet_test_id(1)),
        canister_ids
    );
}

#[test]
fn canisters_not_in_rt_random_interval_assignment() {
    // In this test, we roll a dice multiple times.  Each roll determines
    // whether the canister with the corresponding numeric id belongs to the
    // state according to the routing table or not (0 - not in the table, 1..6 -
    // in the table).
    //
    // We then setup the state and the routing table accordingly, and validate
    // that find_canisters_not_in_routing_table detects the unlucky canisters.
    let mut runner = TestRunner::default();
    let strategy = proptest::collection::vec(/* element: */ 0..6u8, /* size: */ 1..100);
    runner
        .run(&strategy, |rolls: Vec<u8>| {
            let mut state = make_state(subnet_test_id(1));
            for (i, b) in rolls.iter().enumerate() {
                add_canister(&mut state, CanisterId::from(i as u64));
                let subnet = if *b == 0 { 2 } else { 1 };
                add_route(&mut state, i as u64, i as u64, subnet_test_id(subnet));
            }
            // Merge contiguous ranges in the routing table.
            Arc::make_mut(&mut state.metadata.network_topology.routing_table).optimize();

            let expected_canister_ids: Vec<_> = rolls
                .iter()
                .enumerate()
                .filter_map(|(n, b)| (*b == 0).then(|| CanisterId::from(n as u64)))
                .collect();
            prop_assert_eq!(
                find_canisters_not_in_routing_table(&state, subnet_test_id(1)),
                expected_canister_ids
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn canisters_to_remove_with_empty_cm() {
    let mut runner = TestRunner::default();
    let strategy = proptest::collection::vec(/* element: */ 0..6u8, /* size: */ 1..100);
    runner
        .run(&strategy, |rolls: Vec<u8>| {
            let mut state = make_state(subnet_test_id(1));
            for (i, b) in rolls.iter().enumerate() {
                add_canister(&mut state, CanisterId::from(i as u64));
                let subnet = if *b == 0 { 2 } else { 1 };
                add_route(&mut state, i as u64, i as u64, subnet_test_id(subnet));
            }
            // Merge contiguous ranges in the routing table.
            Arc::make_mut(&mut state.metadata.network_topology.routing_table).optimize();

            // Without canister migrations entry we expect `find_canisters_not_in_routing_table`
            // and `find_canisters_to_remove` to behave the same.
            prop_assert_eq!(
                find_canisters_not_in_routing_table(&state, subnet_test_id(1)),
                find_canisters_to_remove(&no_op_logger(), &state, subnet_test_id(1))
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn canisters_to_remove_with_random_cm() {
    let mut runner = TestRunner::default();
    let strategy = proptest::collection::vec(/* element: */ 0..6u8, /* size: */ 1..100);
    runner
        .run(&strategy, |rolls: Vec<u8>| {
            let mut state = make_state(subnet_test_id(1));
            for (i, b) in rolls.iter().enumerate() {
                add_canister(&mut state, CanisterId::from(i as u64));
                // Canisters with `*b % 2 == 0` are assigned to subnet 2.
                let subnet = if *b % 2 == 0 { 2 } else { 1 };
                add_route(&mut state, i as u64, i as u64, subnet_test_id(subnet));
                // Canisters with `*b % 4 == 0` are in the migration trace and they are not supposed to be removed.
                if b % 4 == 0 {
                    add_canister_migrations(
                        &mut state,
                        i as u64,
                        i as u64,
                        subnet_test_id(1),
                        subnet_test_id(subnet),
                    );
                }
            }
            // Merge contiguous ranges in the routing table.
            Arc::make_mut(&mut state.metadata.network_topology.routing_table).optimize();

            // Canisters are expected to be removed if they are assigned to subnet 2 and are not in the migration trace.
            let expected_canister_ids: Vec<_> = rolls
                .iter()
                .enumerate()
                .filter_map(|(n, b)| {
                    (*b % 2 == 0 && *b % 4 != 0).then(|| CanisterId::from(n as u64))
                })
                .collect();
            prop_assert_eq!(
                find_canisters_to_remove(&no_op_logger(), &state, subnet_test_id(1)),
                expected_canister_ids
            );
            Ok(())
        })
        .unwrap();
}
