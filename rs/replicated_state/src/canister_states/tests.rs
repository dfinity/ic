use super::*;
use crate::canister_state::canister_snapshots::CanisterSnapshots;
use crate::{CanisterState, ExecutionTask, InputQueueType, SchedulerState, SystemState};
use ic_base_types::NumSeconds;
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities_types::ids::canister_test_id;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::RequestOrResponse;
use ic_types_cycles::Cycles;
use std::sync::Arc;

fn make_canister(id: u64) -> Arc<CanisterState> {
    let canister_id = canister_test_id(id);
    let system_state = SystemState::new_running_for_testing(
        canister_id,
        canister_test_id(999).get(),
        Cycles::new(1 << 36),
        NumSeconds::new(100_000),
    );
    Arc::new(CanisterState::new(
        system_state,
        None,
        SchedulerState::default(),
        CanisterSnapshots::default(),
    ))
}

fn push_input(canister: &mut Arc<CanisterState>) {
    let msg: RequestOrResponse = RequestBuilder::default()
        .sender(canister_test_id(999))
        .receiver(canister.canister_id())
        .build()
        .into();
    let mut available_guaranteed_response_memory = i64::MAX / 2;
    Arc::make_mut(canister)
        .push_input(
            msg,
            &mut available_guaranteed_response_memory,
            SubnetType::Application,
            InputQueueType::RemoteSubnet,
        )
        .unwrap();
}

fn hot_canister(id: u64) -> Arc<CanisterState> {
    let mut canister = make_canister(id);
    push_input(&mut canister);
    canister
}

fn cold_canister(id: u64) -> Arc<CanisterState> {
    make_canister(id)
}

#[test]
fn fresh_canister_is_cold() {
    let canister = cold_canister(1);
    assert!(canister.is_cold());
}

#[test]
fn canister_with_input_is_not_cold() {
    let mut canister = make_canister(1);
    push_input(&mut canister);
    assert!(!canister.is_cold());
}

#[test]
fn canister_with_pending_task_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister)
        .system_state
        .task_queue
        .enqueue(ExecutionTask::Heartbeat);
    assert!(!canister.is_cold());
}

#[test]
fn new_classifies_each_canister() {
    let cold = cold_canister(1);
    let hot = hot_canister(2);

    let mut canisters = std::collections::BTreeMap::new();
    canisters.insert(cold.canister_id(), Arc::clone(&cold));
    canisters.insert(hot.canister_id(), Arc::clone(&hot));

    let states = CanisterStates::new(canisters);
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);
    assert!(states.cold.contains_key(&cold.canister_id()));
    assert!(states.hot.contains_key(&hot.canister_id()));
}

#[test]
fn merged_iter_yields_sorted_order() {
    let c1 = cold_canister(1);
    let c2 = hot_canister(2);
    let c3 = cold_canister(3);

    let mut canisters = std::collections::BTreeMap::new();
    canisters.insert(c3.canister_id(), Arc::clone(&c3));
    canisters.insert(c2.canister_id(), Arc::clone(&c2));
    canisters.insert(c1.canister_id(), Arc::clone(&c1));

    let states = CanisterStates::new(canisters);
    let ids: Vec<CanisterId> = states.all_keys().copied().collect();
    assert_eq!(
        ids,
        vec![c1.canister_id(), c2.canister_id(), c3.canister_id()]
    );
}

#[test]
fn insert_classifies_on_the_fly() {
    let mut states = CanisterStates::default();
    let cold = cold_canister(1);
    let hot = hot_canister(2);

    assert!(states.insert(cold).is_none());
    assert!(states.insert(hot).is_none());

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);
}

#[test]
fn insert_replaces_existing_canister() {
    let mut states = CanisterStates::default();
    let cold = cold_canister(1);

    // Initial insert: lands in cold.
    assert!(states.insert(Arc::clone(&cold)).is_none());
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    // Replace with a hot version of the same canister: returns the cold one,
    // partition is updated.
    let hot = hot_canister(1);
    let prev = states.insert(Arc::clone(&hot)).expect("upsert");
    assert!(Arc::ptr_eq(&prev, &cold));
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);

    // Replace again with a cold version: partition flips back.
    let cold_again = cold_canister(1);
    let prev = states.insert(Arc::clone(&cold_again)).expect("upsert");
    assert!(Arc::ptr_eq(&prev, &hot));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
}

#[test]
fn get_mut_heats_a_cold_canister() {
    let mut states = CanisterStates::default();
    let canister = cold_canister(1);
    states.insert(Arc::clone(&canister));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    let _ = states.get_mut(&canister.canister_id()).unwrap();

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);
}

#[test]
fn remove_takes_canister_from_either_pool() {
    let mut states = CanisterStates::default();
    let canister = cold_canister(1);
    states.insert(Arc::clone(&canister));
    assert_eq!(states.cold.len(), 1);

    states.remove(&canister.canister_id());
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 0);
}

#[test]
fn try_cool_moves_hot_back_to_cold_when_cold_again() {
    let mut states = CanisterStates::default();
    let canister = cold_canister(1);
    states.insert(Arc::clone(&canister));

    // Heat it (e.g. via get_mut).
    let _ = states.get_mut(&canister.canister_id());
    assert_eq!(states.hot.len(), 1);

    // The canister is still cold by predicate (we didn't mutate it), so try_cool
    // should demote it.
    assert!(states.try_cool(&canister.canister_id()));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
}

#[test]
fn try_cool_leaves_non_cold_in_hot() {
    let mut states = CanisterStates::default();
    let canister = hot_canister(1);
    states.insert(canister.clone());

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);

    assert!(!states.try_cool(&canister.canister_id()));

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);
}

#[test]
fn try_cool_all_compacts_hot_into_cold() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = cold_canister(2);
    let c3 = hot_canister(3);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    states.insert(Arc::clone(&c3));

    // Force them into hot.
    let _ = states.get_mut(&c1.canister_id());
    let _ = states.get_mut(&c2.canister_id());
    assert_eq!(states.hot.len(), 3);
    assert_eq!(states.cold.len(), 0);

    states.try_cool_all();

    // c3 is actually hot.
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 2);
}

#[test]
fn for_each_mut_visits_every_canister_and_repartitions() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = cold_canister(2);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    // Force c2 into hot so the closure has to visit both pools.
    let _ = states.get_mut(&c2.canister_id());
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);

    // Enqueue an input for the canister currently in `cold` (c1). This
    // mutation flips c1 from cold to non-cold.
    let mut visited = Vec::new();
    states.for_each_mut(|id, canister| {
        visited.push(*id);
        if *id == c1.canister_id() {
            push_input(canister);
        }
    });

    // Every canister was visited, hot canisters first.
    assert_eq!(visited, vec![c2.canister_id(), c1.canister_id()]);
    // Partition was re-established: c2 is still cold-eligible (untouched),
    // c1 is non-cold because of the enqueued input.
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);
    assert!(states.hot.contains_key(&c1.canister_id()));
    assert!(states.cold.contains_key(&c2.canister_id()));
}

#[test]
fn for_each_mut_demotes_a_hot_canister_that_became_cold() {
    let mut states = CanisterStates::default();

    // c1: hot (has an input message).
    let c1 = hot_canister(1);
    // c2: already cold, kept untouched as a partition witness.
    let c2 = cold_canister(2);

    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);

    // Drain c1's input queue inside the closure: this flips c1 from non-cold
    // back to cold. `for_each_mut` must demote it as part of its final
    // `try_cool_all` pass.
    let mut visited = Vec::new();
    states.for_each_mut(|id, canister| {
        visited.push(*id);
        if *id == c1.canister_id() {
            Arc::make_mut(canister)
                .pop_input()
                .expect("c1 has an input");
        }
    });
    assert_eq!(visited, vec![c1.canister_id(), c2.canister_id()]);

    // Both canisters end up in cold.
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 2);
}

#[test]
fn try_for_each_mut_visits_every_canister_and_repartitions_on_ok() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = cold_canister(2);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    // Force c2 into hot so the closure has to visit both pools.
    let _ = states.get_mut(&c2.canister_id());
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);

    let mut visited = Vec::new();
    let res: Result<(), ()> = states.try_for_each_mut(|id, canister| {
        visited.push(*id);
        if *id == c1.canister_id() {
            push_input(canister);
        }
        Ok(())
    });

    assert_eq!(res, Ok(()));
    // Every canister visited, hot pool first.
    assert_eq!(visited, vec![c2.canister_id(), c1.canister_id()]);
    // Partition re-established: c2 cooled back down (untouched), c1 promoted
    // because the closure flipped it to non-cold.
    assert!(states.hot.contains_key(&c1.canister_id()));
    assert!(states.cold.contains_key(&c2.canister_id()));
}

#[test]
fn try_for_each_mut_short_circuits_on_hot_error() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = hot_canister(2);
    let c3 = hot_canister(3);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    states.insert(Arc::clone(&c3));
    assert_eq!(states.hot.len(), 2);
    assert_eq!(states.cold.len(), 1);

    let mut visited = Vec::new();
    let res: Result<(), &'static str> = states.try_for_each_mut(|id, canister| {
        visited.push(*id);
        if *id == c3.canister_id() {
            Err("boom")
        } else {
            Arc::make_mut(canister).pop_input().unwrap();
            Ok(())
        }
    });

    assert_eq!(res, Err("boom"));
    // Iteration stopped at the second hot canister; c1 (cold) was never visited.
    assert_eq!(visited, vec![c2.canister_id(), c3.canister_id()]);
    // c2 is now cold.
    assert!(states.cold.contains_key(&c1.canister_id()));
    assert!(states.cold.contains_key(&c2.canister_id()));
    assert!(states.hot.contains_key(&c3.canister_id()));
}

#[test]
fn try_for_each_mut_short_circuits_on_cold_error_and_promotes_visited() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = cold_canister(2);
    let c3 = cold_canister(3);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    states.insert(Arc::clone(&c3));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 3);

    let mut visited = Vec::new();
    let res: Result<(), &'static str> = states.try_for_each_mut(|id, canister| {
        visited.push(*id);
        if *id == c1.canister_id() {
            // Mutate (promotes c1 from cold to hot) and return Ok.
            push_input(canister);
            Ok(())
        } else if *id == c2.canister_id() {
            // Mutate AND return Err on the same canister: c2's mutation must
            // still be reflected in the partition.
            push_input(canister);
            Err("boom")
        } else {
            unreachable!("c3 must not be visited after the error on c2");
        }
    });

    assert_eq!(res, Err("boom"));
    // Iteration stopped at c2; c3 never visited.
    assert_eq!(visited, vec![c1.canister_id(), c2.canister_id()]);
    // c1 and c2 both became non-cold during iteration: both end up in hot.
    // c3 remains in cold.
    assert!(states.hot.contains_key(&c1.canister_id()));
    assert!(states.hot.contains_key(&c2.canister_id()));
    assert!(states.cold.contains_key(&c3.canister_id()));
}

#[test]
fn retain_drops_canisters_from_both_pools() {
    let mut states = CanisterStates::default();
    let c1 = cold_canister(1);
    let c2 = cold_canister(2);
    let c3 = hot_canister(3);
    let c4 = hot_canister(4);
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    states.insert(Arc::clone(&c3));
    states.insert(Arc::clone(&c4));
    assert_eq!(states.hot.len(), 2);
    assert_eq!(states.cold.len(), 2);

    let keep = [c1.canister_id(), c3.canister_id()];
    states.retain(|id, _| keep.contains(id));

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);
    assert!(states.contains_key(&c1.canister_id()));
    assert!(!states.contains_key(&c2.canister_id()));
    assert!(states.contains_key(&c3.canister_id()));
    assert!(!states.contains_key(&c4.canister_id()));
}

#[test]
fn validate_strict_split_accepts_canonical_partition() {
    let mut states = CanisterStates::default();
    states.insert(cold_canister(1));
    states.insert(hot_canister(2));
    states.insert(cold_canister(3));

    // A freshly built `CanisterStates` is always strict by construction.
    assert_eq!(states.validate_strict_split(), Ok(()));
}

#[test]
fn validate_strict_split_rejects_stale_hot_canister() {
    let mut states = CanisterStates::default();
    let c = cold_canister(1);
    states.insert(Arc::clone(&c));
    // `get_mut` promotes c to hot without actually mutating anything, so c
    // ends up cold-by-predicate but in the `hot` pool — exactly the stale
    // state that `try_cool_all` is supposed to clean up.
    let _ = states.get_mut(&c.canister_id());
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);

    let err = states.validate_strict_split().unwrap_err();
    assert!(
        err.contains(&format!("canister {}", c.canister_id())) && err.contains("`hot` pool"),
        "unexpected error: {err}",
    );
}

#[test]
fn validate_strict_split_rejects_stale_cold_canister() {
    let mut states = CanisterStates::default();
    let c = cold_canister(1);
    states.insert(Arc::clone(&c));
    // Bypass the public mutation entry points: mutate the cold pool directly,
    // simulating a bug or lack of encapsulation.
    push_input(states.cold.get_mut(&c.canister_id()).unwrap());
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    let err = states.validate_strict_split().unwrap_err();
    assert!(
        err.contains(&format!("canister {}", c.canister_id())) && err.contains("`cold` pool"),
        "unexpected error: {err}",
    );
}
