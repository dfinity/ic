use super::*;
use crate::canister_state::canister_snapshots::CanisterSnapshots;
use crate::canister_state::execution_state::{
    CustomSection, CustomSectionType, WasmBinary, WasmMetadata,
};
use crate::canister_state::system_state::testing::{OutputRequestBuilder, SystemStateTesting};
use crate::{
    CallContextManager, CanisterState, CanisterStatus, ExecutionState, ExecutionTask,
    ExportedFunctions, InputQueueType, Memory, SchedulerState, SystemState,
};
use ic_base_types::NumSeconds;
use ic_management_canister_types_private::{CanisterChangeDetails, CanisterChangeOrigin};
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities_types::ids::canister_test_id;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::{NO_DEADLINE, RequestOrResponse};
use ic_types::methods::{SystemMethod, WasmMethod};
use ic_types::time::{CoarseTime, UNIX_EPOCH};
use ic_types::{CanisterTimer, ComputeAllocation, NumBytes, NumInstructions, Time};
use ic_types_cycles::Cycles;
use ic_wasm_types::CanisterModule;
use maplit::{btreemap, btreeset};
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
    push_input_with_deadline(canister, NO_DEADLINE);
}

fn push_input_with_deadline(canister: &mut Arc<CanisterState>, deadline: CoarseTime) {
    let msg: RequestOrResponse = RequestBuilder::default()
        .sender(canister_test_id(999))
        .receiver(canister.canister_id())
        .deadline(deadline)
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

fn push_output(canister: &mut Arc<CanisterState>) {
    let request = OutputRequestBuilder::default()
        .sender(canister.canister_id())
        .receiver(canister_test_id(999))
        .build();
    Arc::make_mut(canister)
        .push_output_request(request, UNIX_EPOCH)
        .unwrap();
}

fn set_compute_allocation(canister: &mut Arc<CanisterState>, percentage: u64) {
    Arc::make_mut(canister).system_state.compute_allocation =
        ComputeAllocation::try_from(percentage).unwrap();
}

fn hot_canister(id: u64) -> Arc<CanisterState> {
    let mut canister = make_canister(id);
    push_input(&mut canister);
    canister
}

fn cold_canister(id: u64) -> Arc<CanisterState> {
    make_canister(id)
}

/// Builds a canister that satisfies [`CanisterState::is_cold`] but holds an
/// input-slot reservation for an outstanding guaranteed-response request. Such
/// canisters contribute to `cold_stats.guaranteed_response_message_memory`.
fn cold_canister_with_guaranteed_response_reservation(id: u64) -> Arc<CanisterState> {
    let mut canister = make_canister(id);
    // Push an output request, making an input queue slot reservation.
    let request = crate::testing::OutputRequestBuilder::default()
        .sender(canister.canister_id())
        .receiver(canister_test_id(999))
        .build();
    Arc::make_mut(&mut canister)
        .push_output_request(request, UNIX_EPOCH)
        .unwrap();
    // Drain the output queue to leave only the reservation behind.
    let _ = Arc::make_mut(&mut canister).output_into_iter().count();
    canister
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
fn canister_with_output_is_not_cold() {
    let mut canister = make_canister(1);
    push_output(&mut canister);
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
fn canister_with_heartbeat_method_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister).execution_state = Some(ExecutionState::new(
        WasmBinary::new(CanisterModule::new(vec![1, 2, 3])),
        None,
        ExportedFunctions::new(btreeset![WasmMethod::System(
            SystemMethod::CanisterHeartbeat,
        )]),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        vec![],
        WasmMetadata::default(),
    ));
    assert!(!canister.is_cold());
}

#[test]
fn canister_with_active_global_timer_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister).system_state.global_timer =
        CanisterTimer::Active(Time::from_nanos_since_unix_epoch(1));
    assert!(!canister.is_cold());
}

#[test]
fn stopping_canister_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister)
        .system_state
        .set_status(CanisterStatus::Stopping {
            call_context_manager: CallContextManager::default(),
            stop_contexts: vec![],
        });
    assert!(!canister.is_cold());
}

#[test]
fn canister_with_unexpired_callback_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister).system_state.with_callback(
        canister_test_id(999),
        CoarseTime::from_secs_since_unix_epoch(1),
    );
    assert!(!canister.is_cold());
}

#[test]
fn canister_with_expired_callback_is_cold() {
    // A `NO_DEADLINE` (i.e. guaranteed-response) callback never enters the
    // `unexpired_callbacks` set, so it does not by itself prevent the canister
    // from being classified as cold.
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister)
        .system_state
        .with_callback(canister_test_id(999), NO_DEADLINE);
    assert!(canister.is_cold());
}

#[test]
fn canister_with_heap_delta_debit_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister)
        .scheduler_state
        .heap_delta_debit = NumBytes::new(1);
    assert!(!canister.is_cold());
}

#[test]
fn canister_with_install_code_debit_is_not_cold() {
    let mut canister = make_canister(1);
    Arc::make_mut(&mut canister)
        .scheduler_state
        .install_code_debit = NumInstructions::new(1);
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
fn insert_replaces_existing_canister_and_updates_cold_stats() {
    let mut states = CanisterStates::default();

    // Initial insert: lands in cold.
    let mut cold = cold_canister(1);
    set_compute_allocation(&mut cold, 42);
    assert!(states.insert(Arc::clone(&cold)).is_none());
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
    assert_eq!(states.cold_stats.total_compute_allocation_percent, 42);

    // Replace with a hot version of the same canister: returns the cold one,
    // `cold_stats` reflects the new (empty) cold pool.
    let mut hot = hot_canister(1);
    set_compute_allocation(&mut hot, 42);
    let prev = states.insert(Arc::clone(&hot)).expect("upsert");
    assert!(Arc::ptr_eq(&prev, &cold));
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);
    assert_eq!(states.cold_stats.total_compute_allocation_percent, 0);

    // Replace again with a cold version: cold_stats picks it back up.
    let mut cold_again = cold_canister(1);
    set_compute_allocation(&mut cold_again, 42);
    let prev = states.insert(Arc::clone(&cold_again)).expect("upsert");
    assert!(Arc::ptr_eq(&prev, &hot));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
    assert_eq!(states.cold_stats.total_compute_allocation_percent, 42);
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
fn remove_updates_cold_stats() {
    let mut states = CanisterStates::default();
    let canister = cold_canister(1);
    states.insert(Arc::clone(&canister));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    states.remove(&canister.canister_id());
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 0);
}

#[test]
fn remove_takes_canister_from_hot_pool() {
    let mut states = CanisterStates::default();
    let canister = hot_canister(1);
    states.insert(Arc::clone(&canister));
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);

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
fn try_cool_leaves_cold_in_cold() {
    let mut states = CanisterStates::default();
    let canister = cold_canister(1);
    states.insert(canister.clone());

    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    assert!(!states.try_cool(&canister.canister_id()));

    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
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

    // c1: hot (has an input message). Tag it with a distinguishable compute
    // allocation so that we can verify it lands in `cold_stats` after demotion.
    let mut c1 = hot_canister(1);
    set_compute_allocation(&mut c1, 42);
    // c2: already cold, kept untouched as a partition witness.
    let c2 = cold_canister(2);

    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);

    // c1 is in hot, so its 42% compute allocation is not yet in `cold_stats`.
    assert_eq!(states.cold_stats.total_compute_allocation_percent, 0);
    assert_eq!(states.total_compute_allocation(), 42);

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

    // Both canisters end up in cold; cold_stats picks up c1's 42% compute.
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 2);
    assert_eq!(states.cold_stats.total_compute_allocation_percent, 42);
    assert_eq!(states.total_compute_allocation(), 42);
}

#[test]
fn for_each_mut_updates_cold_stats_in_place() {
    let mut states = CanisterStates::default();
    let c = cold_canister(1);
    states.insert(c);
    // Sanity: c is cold and contributes 0% compute allocation.
    assert_eq!(states.cold.len(), 1);
    assert_eq!(states.total_compute_allocation(), 0);

    // Mutate `compute_allocation` on the cold canister without affecting
    // `is_cold()`. The in-place iteration must update `cold_stats` accordingly.
    states.for_each_mut(|_id, canister| {
        set_compute_allocation(canister, 42);
    });

    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);
    assert_eq!(states.total_compute_allocation(), 42);
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
            // still be reflected in the partition / cold_stats.
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
    // c3 remains in cold. `debug_assert_invariants` (run inside
    // `try_for_each_mut`) covers the matching `cold_stats` invariant.
    assert!(states.hot.contains_key(&c1.canister_id()));
    assert!(states.hot.contains_key(&c2.canister_id()));
    assert!(states.cold.contains_key(&c3.canister_id()));
}

#[test]
fn try_for_each_mut_short_circuits_on_cold_error_for_canister_that_stays_cold() {
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
    let res: Result<(), &'static str> = states.try_for_each_mut(|id, _canister| {
        visited.push(*id);
        if *id == c2.canister_id() {
            // Return `Err` without mutating: the canister stays cold.
            // The error must still propagate and iteration must stop here.
            Err("boom")
        } else {
            // No-op on c1 and c3: they stay cold.
            Ok(())
        }
    });

    assert_eq!(res, Err("boom"));
    // Iteration must stop at c2; c3 must not be visited.
    assert_eq!(visited, vec![c1.canister_id(), c2.canister_id()]);
    // No canister was mutated, so all three remain in `cold`.
    assert!(states.cold.contains_key(&c1.canister_id()));
    assert!(states.cold.contains_key(&c2.canister_id()));
    assert!(states.cold.contains_key(&c3.canister_id()));
    assert!(states.hot.is_empty());
}

#[test]
fn retain_updates_cold_stats_for_removed_cold_canisters() {
    let mut states = CanisterStates::default();
    let mut c1 = cold_canister(1);
    let mut c2 = cold_canister(2);
    let mut c3 = hot_canister(3);
    let mut c4 = hot_canister(4);
    // Give every canister a distinguishable compute allocation so we can spot
    // bookkeeping errors via `total_compute_allocation()`.
    for (i, canister) in [&mut c1, &mut c2, &mut c3, &mut c4].into_iter().enumerate() {
        set_compute_allocation(canister, 10 + 10 * i as u64);
    }
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    states.insert(Arc::clone(&c3));
    states.insert(Arc::clone(&c4));
    assert_eq!(states.hot.len(), 2);
    assert_eq!(states.cold.len(), 2);
    // 10% + 20% + 30% + 40% = 100%.
    assert_eq!(states.total_compute_allocation(), 100);

    let keep = [c1.canister_id(), c3.canister_id()];
    states.retain(|id, _| keep.contains(id));

    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);
    assert!(states.contains_key(&c1.canister_id()));
    assert!(!states.contains_key(&c2.canister_id()));
    assert!(states.contains_key(&c3.canister_id()));
    assert!(!states.contains_key(&c4.canister_id()));
    // 10% (c1) + 30% (c3) = 40%.
    assert_eq!(states.total_compute_allocation(), 40);
}

// Helper for the memory aggregators tests. Takes two canisters, one hot, one
// cold; populates various parts of their states; and validates the aggregators.
fn memory_aggregators_combine_hot_and_cold_impl(
    mut c1: Arc<CanisterState>,
    mut c2: Arc<CanisterState>,
) {
    // Distinguishable memory allocation reservations so that `execution`
    // depends visibly on both canisters.
    Arc::make_mut(&mut c1).system_state.memory_allocation = NumBytes::new(10_000_000).into();
    Arc::make_mut(&mut c2).system_state.memory_allocation = NumBytes::new(20_000_000).into();
    // Also populate custom sections.
    Arc::make_mut(&mut c1).execution_state = Some(ExecutionState::new(
        WasmBinary::new(CanisterModule::new(vec![1, 2, 3])),
        None,
        ExportedFunctions::new(btreeset![]),
        Memory::new_for_testing(),
        Memory::new_for_testing(),
        Vec::new(),
        WasmMetadata::new(btreemap! {
            "private".to_string() => CustomSection::new(CustomSectionType::Private, vec![0, 1]),
            "public".to_string() => CustomSection::new(CustomSectionType::Public, vec![0, 2]),
        }),
    ));
    // And a canister history change.
    Arc::make_mut(&mut c2).system_state.add_canister_change(
        Time::from_nanos_since_unix_epoch(1000),
        CanisterChangeOrigin::from_canister(c1.canister_id().get(), Some(1)),
        CanisterChangeDetails::CanisterCodeUninstall,
    );

    let mut states = CanisterStates::default();
    states.insert(Arc::clone(&c1));
    states.insert(Arc::clone(&c2));
    // Both pools must be exercised, otherwise this test does not cover the
    // hot-iteration + cold-aggregate combination.
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 1);

    // Expected values, computed by summing over every canister independently
    // of the hot/cold split.
    let canisters = [&c1, &c2];
    let expected_memory_usage: NumBytes = canisters
        .iter()
        .map(|c| c.memory_usage() + c.message_memory_usage().total())
        .sum();
    let expected_guaranteed: NumBytes = canisters
        .iter()
        .map(|c| c.system_state.guaranteed_response_message_memory_usage())
        .sum();
    let expected_best_effort: NumBytes = canisters
        .iter()
        .map(|c| c.system_state.best_effort_message_memory_usage())
        .sum();
    let expected_execution: NumBytes = canisters.iter().map(|c| c.memory_allocated_bytes()).sum();
    let expected_wasm_sections: NumBytes = canisters
        .iter()
        .map(|c| c.wasm_custom_sections_memory_usage())
        .sum();
    let expected_history: NumBytes = canisters
        .iter()
        .map(|c| c.canister_history_memory_usage())
        .sum();

    // Sanity checks: the various amounts are all non-zero; otherwise a broken
    // aggregator returning 0 could trivially pass.

    // The hot canister contributes non-zero guaranteed-response message memory
    // (from `push_input`) andn non-zero best-effort message memory (explicit push).
    assert!(expected_guaranteed > NumBytes::new(0));
    assert!(expected_best_effort > NumBytes::new(0));
    // Both canisters contribute to `execution` (from `memory_allocation`).
    assert!(expected_execution == NumBytes::new(30_000_000));
    // Non-zero (actual)execution memory usage (from canister history).
    let execution_memory: NumBytes = canisters.iter().map(|c| c.memory_usage()).sum();
    assert!(execution_memory > NumBytes::new(0));
    // And non-zero message memory usage.
    let total_message_memory: NumBytes = canisters
        .iter()
        .map(|c| c.message_memory_usage().total())
        .sum();
    assert!(total_message_memory > NumBytes::new(0));
    // Adding up to the expected memory usage.
    assert_eq!(
        expected_memory_usage,
        execution_memory + total_message_memory
    );
    // Non-zero Wasm custom sections and canister history memory usage.
    assert!(expected_wasm_sections > NumBytes::new(0));
    assert!(expected_history > NumBytes::new(0));

    // Test the individual getters().
    assert_eq!(states.total_canister_memory_usage(), expected_memory_usage);
    assert_eq!(
        states.guaranteed_response_message_memory_taken(),
        expected_guaranteed
    );
    assert_eq!(
        states.best_effort_message_memory_taken(),
        expected_best_effort
    );

    // Test the combined `memory_taken()`.
    let mt = states.memory_taken();
    assert_eq!(mt.execution, expected_execution);
    assert_eq!(mt.guaranteed_response_messages, expected_guaranteed);
    assert_eq!(mt.best_effort_messages, expected_best_effort);
    assert_eq!(mt.wasm_custom_sections, expected_wasm_sections);
    assert_eq!(mt.canister_history, expected_history);
}

#[test]
fn memory_aggregators_combine_hot_and_cold() {
    let cold = cold_canister(1);
    let mut hot = hot_canister(2);
    // Also enqueue a best-effort message.
    push_input_with_deadline(&mut hot, CoarseTime::from_secs_since_unix_epoch(1));

    memory_aggregators_combine_hot_and_cold_impl(Arc::clone(&cold), Arc::clone(&hot));
    memory_aggregators_combine_hot_and_cold_impl(Arc::clone(&hot), Arc::clone(&cold));
}
/// A cold canister holding a guaranteed-response slot reservation must still
/// contribute its reservation memory to
/// `guaranteed_response_message_memory_taken` and `memory_taken`.
#[test]
fn cold_canister_with_guaranteed_response_reservation_is_aggregated() {
    let canister = cold_canister_with_guaranteed_response_reservation(1);
    // Sanity: the test fixture is what it claims to be.
    assert!(canister.is_cold());
    let guaranteed_response_message_memory = canister
        .system_state
        .guaranteed_response_message_memory_usage();
    assert!(guaranteed_response_message_memory > NumBytes::new(0),);

    let mut states = CanisterStates::default();
    states.insert(Arc::clone(&canister));
    assert_eq!(states.hot.len(), 0);
    assert_eq!(states.cold.len(), 1);

    // The canister sits in `cold` but contributes a non-zero amount to both
    // `guaranteed_response_message_memory_taken` and `memory_taken`.
    assert_eq!(
        states.guaranteed_response_message_memory_taken(),
        guaranteed_response_message_memory,
    );
    assert_eq!(
        states.memory_taken().guaranteed_response_messages,
        guaranteed_response_message_memory,
    );

    // Promoting the canister to `hot` (e.g. via `get_mut`) must not change the
    // aggregate.
    let _ = states.get_mut(&canister.canister_id());
    assert_eq!(states.hot.len(), 1);
    assert_eq!(states.cold.len(), 0);
    assert_eq!(
        states.guaranteed_response_message_memory_taken(),
        guaranteed_response_message_memory,
    );
}

#[test]
fn callback_count_combines_hot_and_cold() {
    let callee = canister_test_id(999);

    // A canister with only guaranteed-response (never-expiring) callbacks is
    // still cold by definition (see `CanisterState::is_cold`), which lets us
    // exercise the `cold_stats.callback_count` aggregate.
    let mut cold = cold_canister(1);
    Arc::make_mut(&mut cold)
        .system_state
        .with_callback(callee, NO_DEADLINE);
    assert!(cold.is_cold());

    // A hot canister with two callbacks (one guaranteed, one best-effort).
    let mut hot = hot_canister(2);
    Arc::make_mut(&mut hot)
        .system_state
        .with_callback(callee, NO_DEADLINE);
    Arc::make_mut(&mut hot)
        .system_state
        .with_callback(callee, CoarseTime::from_secs_since_unix_epoch(1));
    assert!(!hot.is_cold());

    let mut states = CanisterStates::default();
    states.insert(cold);
    states.insert(hot);

    // Total = 1 (cold contribution, via cold_stats) + 2 (hot, via iteration).
    assert_eq!(states.cold_stats.callback_count, 1);
    assert_eq!(states.callback_count(), 3);
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
