//! Tests for subnet message execution.

use super::super::test_utilities::{
    SchedulerTest, SchedulerTestBuilder, TestInstallCode, ingress, instructions,
};
use super::super::*;
use super::zero_instruction_overhead_config;
use candid::Encode;
use ic_config::subnet_config::SchedulerConfig;
use ic_management_canister_types_private::{
    CanisterIdRecord, EmptyBlob, FetchCanisterLogsRequest, Method, Payload as _,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::testing::{CanisterQueuesTesting, ReplicatedStateTesting};
use ic_test_utilities_metrics::{HistogramStats, fetch_histogram_vec_stats, labels};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::time::UNIX_EPOCH;
use ic_types_cycles::CompoundCycles;
use ic_types_test_utils::ids::canister_test_id;

#[test]
fn test_drain_subnet_messages_with_some_long_running_canisters() {
    let instructions_per_slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(instructions_per_slice),
            max_instructions_per_message: NumInstructions::from(instructions_per_slice * 100),
            max_instructions_per_slice: NumInstructions::from(instructions_per_slice),
            max_instructions_per_install_code_slice: NumInstructions::from(instructions_per_slice),
            ..zero_instruction_overhead_config()
        })
        .build();

    let mut local_canisters = vec![];
    let mut remote_canisters = vec![];
    let add_messages = |test: &mut SchedulerTest, canisters: &mut Vec<CanisterId>| {
        for _ in 0..2 {
            let canister = test.create_canister();
            canisters.push(canister);
        }
    };
    add_messages(&mut test, &mut local_canisters);
    add_messages(&mut test, &mut remote_canisters);

    // Start a long execution on `local_canisters[1]` and `remote_canisters[0]`.
    for canister_id in [&local_canisters[1], &remote_canisters[0]] {
        test.send_ingress(*canister_id, ingress(instructions_per_slice * 100));
        test.execute_round(ExecutionRoundType::OrdinaryRound);
    }

    // Add 3 local subnet input messages.
    // Canister `local_canisters[1]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(local_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StartCanister,
        arg1.clone(),
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(10),
        InputQueueType::LocalSubnet,
    );

    let arg2 = Encode!(&CanisterIdRecord::from(local_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(11),
        InputQueueType::LocalSubnet,
    );

    // Add 2 remote subnet input messages.
    // Canister `remote_canisters[0]` is in the long running list.
    let arg1 = Encode!(&CanisterIdRecord::from(remote_canisters[0])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg1,
        Cycles::zero(),
        canister_test_id(12),
        InputQueueType::RemoteSubnet,
    );
    let arg2 = Encode!(&CanisterIdRecord::from(remote_canisters[1])).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        arg2,
        Cycles::zero(),
        canister_test_id(13),
        InputQueueType::RemoteSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 6);

    let new_state = test.drain_subnet_messages();
    // Left messages that were not able to be executed due to other long running messages
    // belong to `local_canisters[1]` and `remote_canisters[0]` canisters.
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 2);
}

#[test]
fn test_drain_subnet_messages_no_long_running_canisters() {
    let mut test = SchedulerTestBuilder::new().build();

    let add_messages = |test: &mut SchedulerTest, input_type: InputQueueType| {
        for id in 0..2 {
            let local_canister = test.create_canister_with(
                Cycles::new(1_000_000_000_000),
                ComputeAllocation::zero(),
                MemoryAllocation::default(),
                None,
                None,
                None,
            );
            let arg = Encode!(&CanisterIdRecord::from(local_canister)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(id),
                input_type,
            );
        }
    };
    add_messages(&mut test, InputQueueType::LocalSubnet);
    add_messages(&mut test, InputQueueType::RemoteSubnet);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let new_state = test.drain_subnet_messages();
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
}

#[test]
fn test_drain_subnet_messages_all_long_running_canisters() {
    let instructions_per_slice = 100;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(instructions_per_slice),
            max_instructions_per_message: NumInstructions::from(instructions_per_slice * 100),
            max_instructions_per_slice: NumInstructions::from(instructions_per_slice),
            max_instructions_per_install_code_slice: NumInstructions::from(instructions_per_slice),
            ..zero_instruction_overhead_config()
        })
        .build();

    let add_messages = |test: &mut SchedulerTest, input_type: InputQueueType| {
        for i in 0..2 {
            let canister_id = test.create_canister();
            // Start a long execution.
            test.send_ingress(canister_id, ingress(instructions_per_slice * 100));
            test.execute_round(ExecutionRoundType::OrdinaryRound);

            let arg = Encode!(&CanisterIdRecord::from(canister_id)).unwrap();
            test.inject_call_to_ic00(
                Method::StopCanister,
                arg.clone(),
                Cycles::zero(),
                canister_test_id(i),
                input_type,
            );
        }
    };
    add_messages(&mut test, InputQueueType::LocalSubnet);
    add_messages(&mut test, InputQueueType::RemoteSubnet);
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 4);

    let new_state = test.drain_subnet_messages();
    assert_eq!(new_state.subnet_queues().input_queues_message_count(), 4);
}

#[test]
fn scheduler_executes_postponed_raw_rand_requests() {
    let canister_id = canister_test_id(2);
    let mut test = SchedulerTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    test.advance_to_round(ExecutionRound::new(2));
    let last_round = test.last_round();

    // Inject fake request to be able to create a response.
    let canister = get_running_canister(canister_id);
    test.inject_call_to_ic00(
        Method::RawRand,
        EmptyBlob.encode(),
        Cycles::new(0),
        canister_id,
        InputQueueType::LocalSubnet,
    );
    let state = test.state_mut();
    state.put_canister_state(canister);
    state.pop_subnet_input();
    state
        .metadata
        .subnet_call_context_manager
        .push_raw_rand_request(
            RequestBuilder::new().sender(canister_id).build(),
            last_round,
            UNIX_EPOCH,
        );
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );

    // Execute the postponed `raw_rand` messages.
    test.execute_round(ExecutionRoundType::OrdinaryRound);
    assert_eq!(
        test.state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        0
    );

    assert_eq!(
        fetch_histogram_vec_stats(test.metrics_registry(), "execution_round_phase_messages")
            .get(&labels(&[("phase", "raw_rand")])),
        Some(&HistogramStats { sum: 1.0, count: 1 })
    );

    assert_eq!(
        fetch_histogram_vec_stats(
            test.metrics_registry(),
            "execution_round_phase_instructions",
        )
        .get(&labels(&[("phase", "raw_rand")])),
        Some(&HistogramStats { count: 1, sum: 0.0 })
    );
}

/// `drain_subnet_queues` skips the input queues with subnet calls that count
/// toward the round limit, after the instruction limit was reached.
#[test]
fn drain_subnet_queues_skips_heavy_subnet_calls_when_instructions_reached() {
    const SLICE: u64 = 100;

    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            max_instructions_per_round: NumInstructions::from(SLICE),
            max_instructions_per_message: NumInstructions::from(SLICE),
            max_instructions_per_slice: NumInstructions::from(SLICE),
            max_instructions_per_install_code_slice: NumInstructions::from(SLICE),
            ..zero_instruction_overhead_config()
        })
        .build();

    let canister = test.create_canister();

    let xnet_canister_id = test.xnet_canister_id();
    let remote_canister_1 = canister_test_id(169);
    let remote_canister_2 = canister_test_id(2197);

    // CanisterStatus — counts_toward_round_limit: false.
    fn inject_canister_status_call(
        test: &mut SchedulerTest,
        caller: CanisterId,
        target: CanisterId,
    ) {
        test.inject_call_to_ic00(
            Method::CanisterStatus,
            CanisterIdRecord::from(target).encode(),
            Cycles::zero(),
            caller,
            InputQueueType::RemoteSubnet,
        );
    }

    // Two management canister calls from `xnet_canister_id`.
    //
    // The `InstallCode` counts toward the round limit, but gets executed while the
    // `100 / 16` instruction budget is fully available. It consumes the entire
    // budget, so no other messages that count toward the round limit get executed.
    // The `CanisterStatus` does not count toward the round limit, so it gets
    // executed regardless of the instruction budget.
    let install_code = TestInstallCode::Reinstall {
        init: instructions(SLICE / SUBNET_MESSAGES_LIMIT_FRACTION + 1),
    };
    test.inject_install_code_call_to_ic00(canister, install_code);
    inject_canister_status_call(&mut test, xnet_canister_id, canister);

    // Two calls from `remote_canister_1`.
    //
    // The `FetchCanisterLogs` counts toward the round limit, so the whole input
    // queue gets skipped. The `CanisterStatus` does not count toward the round
    // limit but never gets executed because the queue got skipped.
    test.inject_call_to_ic00(
        Method::FetchCanisterLogs,
        FetchCanisterLogsRequest::new(canister).encode(),
        Cycles::zero(),
        remote_canister_1,
        InputQueueType::RemoteSubnet,
    );
    // CanisterStatus — counts_toward_round_limit: false.
    inject_canister_status_call(&mut test, remote_canister_1, canister);

    // Two calls from `remote_canister_2`.
    //
    // Neither counts toward the round limit, so both should get executed.
    inject_canister_status_call(&mut test, remote_canister_2, canister);
    inject_canister_status_call(&mut test, remote_canister_2, canister);

    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 6);

    let mut new_state = test.drain_subnet_messages();

    let queues = new_state.subnet_queues_mut();
    // The two calls from `remote_canister_2` were not executed.
    assert_eq!(queues.input_queues_message_count(), 2);
    // The other 4 calls were executed.
    assert_eq!(queues.output_queues_message_count(), 4);
    assert!(queues.pop_canister_output(&xnet_canister_id).is_some());
    assert!(queues.pop_canister_output(&xnet_canister_id).is_some());
    assert!(queues.pop_canister_output(&remote_canister_2).is_some());
    assert!(queues.pop_canister_output(&remote_canister_2).is_some());
}

/// Subnet messages with `does_not_run_on_aborted_canister` are skipped when
/// the target canister has an `AbortedExecution` in its task queue.
/// Messages without the flag execute normally.
#[test]
fn drain_subnet_queues_skips_messages_targeting_aborted_canister() {
    const SLICE: u64 = 10;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(SLICE),
            max_instructions_per_message: NumInstructions::from(SLICE * 10),
            max_instructions_per_slice: NumInstructions::from(SLICE),
            max_instructions_per_install_code_slice: NumInstructions::from(SLICE),
            ..zero_instruction_overhead_config()
        })
        .build();
    let canister = test.create_canister();

    let xnet_caller_1 = canister_test_id(10);
    let xnet_caller_2 = canister_test_id(11);
    let xnet_caller_3 = canister_test_id(12);

    // Make all 3 callers controllers, so the calls don't fail because of it.
    let controllers = &mut test.canister_state_mut(canister).system_state.controllers;
    controllers.insert(xnet_caller_1.get());
    controllers.insert(xnet_caller_2.get());
    controllers.insert(xnet_caller_3.get());

    // Start and immediately abort a long execution.
    test.send_ingress(canister, ingress(SLICE * 10));
    test.execute_round(ExecutionRoundType::CheckpointRound);

    // StopCanister — does_not_run_on_aborted_canister: true → skipped.
    let canister_id_payload = Encode!(&CanisterIdRecord::from(canister)).unwrap();
    test.inject_call_to_ic00(
        Method::StopCanister,
        canister_id_payload.clone(),
        Cycles::zero(),
        xnet_caller_1,
        InputQueueType::RemoteSubnet,
    );

    // FetchCanisterLogs — does_not_run_on_aborted_canister: true → skipped.
    test.inject_call_to_ic00(
        Method::FetchCanisterLogs,
        FetchCanisterLogsRequest::new(canister).encode(),
        Cycles::zero(),
        xnet_caller_2,
        InputQueueType::RemoteSubnet,
    );

    // Now enqueue a `CanisterStatus` call from each of the three remote callers.
    // The first two should be skipped, because we skip whole input queues, not just
    // individual messages. The third one should be executed.
    for caller in [xnet_caller_1, xnet_caller_2, xnet_caller_3] {
        // CanisterStatus — does_not_run_on_aborted_canister: false.
        test.inject_call_to_ic00(
            Method::CanisterStatus,
            canister_id_payload.clone(),
            Cycles::zero(),
            caller,
            InputQueueType::RemoteSubnet,
        );
    }
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 5);

    let mut new_state = test.drain_subnet_messages();

    let queues = new_state.subnet_queues_mut();
    // All calls from `xnet_caller_1` and `xnet_caller_2` were skipped.
    assert_eq!(queues.input_queues_message_count(), 4);
    // The call from `xnet_caller_3` was executed.
    assert_eq!(queues.output_queues_message_count(), 1);
    assert!(queues.pop_canister_output(&xnet_caller_3).is_some());
}

/// `drain_subnet_queues` breaks the loop when an (install code) execution is
/// paused.
#[test]
fn drain_subnet_queues_breaks_on_paused_execution() {
    const SLICE: u64 = 10;
    let mut test = SchedulerTestBuilder::new()
        .with_scheduler_config(SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_message: NumInstructions::from(100),
            max_instructions_per_slice: NumInstructions::from(SLICE),
            max_instructions_per_install_code: NumInstructions::new(100),
            max_instructions_per_install_code_slice: NumInstructions::new(SLICE),
            ..zero_instruction_overhead_config()
        })
        .build();
    let canister = test.create_canister();

    // Install code that needs more than one DTS slice → will be paused.
    test.inject_install_code_call_to_ic00(
        canister,
        TestInstallCode::Reinstall {
            init: instructions(SLICE * 3),
        },
    );
    // A second message from a different sender (in a different input queue).
    test.inject_call_to_ic00(
        Method::CanisterStatus,
        Encode!(&CanisterIdRecord::from(canister)).unwrap(),
        Cycles::zero(),
        canister_test_id(42),
        InputQueueType::RemoteSubnet,
    );
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 2);

    test.execute_round(ExecutionRoundType::OrdinaryRound);

    // The install code was popped and paused after one slice.
    assert!(
        test.state()
            .canister_state(&canister)
            .unwrap()
            .has_paused_install_code()
    );
    // The loop broke immediately, so the other message was not executed.
    assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
}

mod can_execute_subnet_msg_tests {
    use super::*;
    use candid::CandidType;
    use ic_management_canister_types_private::TakeCanisterSnapshotArgs;
    use ic_replicated_state::canister_state::system_state::PausedExecutionId;
    use ic_types::messages::{CanisterMessageOrTask, CanisterTask};

    /// Fixture for testing `can_execute_subnet_msg()`. By default, tests are run
    /// with no instructions left and a paused install code on a third party local
    /// canister, i.e. the most restrictive case.
    struct CanExecuteSubnetMsgTest {
        test: SchedulerTest,
        canister: CanisterId,
    }

    impl CanExecuteSubnetMsgTest {
        /// Creates a fixture witn no istructions left and a paused install code (on a
        /// third party local canister).
        fn new() -> Self {
            Self::with_instruction_limit(0)
        }

        /// Creates a fixture with the given instruction limit and a paused install code
        /// (on a third party local canister).
        fn with_instruction_limit(instructions: u64) -> Self {
            let mut test = SchedulerTestBuilder::new()
                .with_scheduler_config(SchedulerConfig {
                    // Ensure that `RoundLimits::instructions_reached()` is immediately true iff `instructions == 0`.
                    max_instructions_per_round: NumInstructions::from(
                        instructions * SUBNET_MESSAGES_LIMIT_FRACTION + 1,
                    ),
                    ..SchedulerConfig::application_subnet()
                })
                .build();
            let canister = test.create_canister();

            // Have a paused install code for a different local canister.
            let other_canister = test.create_canister();
            test.canister_state_mut(other_canister)
                .system_state
                .task_queue
                .enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));

            Self { test, canister }
        }

        fn inject_call<S: ToString, T: CandidType>(&mut self, method_name: S, method_payload: &T) {
            self.test.inject_call_to_ic00(
                method_name,
                Encode!(method_payload).unwrap(),
                Cycles::zero(),
                self.test.xnet_canister_id(),
                InputQueueType::RemoteSubnet,
            );
        }

        fn inject_canister_status_call(&mut self, target: CanisterId) {
            self.inject_call(Method::CanisterStatus, &CanisterIdRecord::from(target));
        }

        fn inject_install_code_call_to_ic00(&mut self, target: CanisterId) {
            self.test.inject_install_code_call_to_ic00(
                target,
                TestInstallCode::Reinstall {
                    init: instructions(1),
                },
            );
        }

        fn state(&self) -> &ReplicatedState {
            self.test.state()
        }

        fn enqueue_task(&mut self, task: ExecutionTask) {
            self.test
                .canister_state_mut(self.canister)
                .system_state
                .task_queue
                .enqueue(task);
        }

        fn drain_subnet_messages(&mut self) -> ReplicatedState {
            self.test.drain_subnet_messages()
        }
    }

    #[test]
    fn no_effective_canister_id_is_executed() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.inject_call(Method::SubnetInfo, &EmptyBlob);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }

    #[test]
    fn missing_effective_canister_state_is_executed() {
        let mut test = CanExecuteSubnetMsgTest::new();

        let nonexistent = canister_test_id(999);
        assert!(test.state().canister_state(&nonexistent).is_none());
        test.inject_install_code_call_to_ic00(nonexistent);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }

    #[test]
    fn invalid_method_name_is_executed() {
        let mut test = CanExecuteSubnetMsgTest::new();
        test.inject_call("bogus_method", &EmptyBlob);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }

    #[test]
    fn effective_canister_with_paused_execution_is_skipped() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.enqueue_task(ExecutionTask::PausedExecution {
            id: PausedExecutionId(0),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });
        test.inject_canister_status_call(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 1);
    }

    #[test]
    fn effective_canister_with_paused_install_code_is_skipped() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.enqueue_task(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));
        test.inject_canister_status_call(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 1);
    }

    #[test]
    fn method_that_counts_toward_round_limit_is_skipped_when_instructions_reached() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.inject_call(
            Method::TakeCanisterSnapshot,
            &TakeCanisterSnapshotArgs::new(test.canister, None, None, None),
        );

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 1);
    }

    #[test]
    fn method_that_does_not_count_toward_round_limit_is_executed_when_instructions_reached() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.inject_canister_status_call(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }

    #[test]
    fn flagged_method_is_skipped_for_target_with_aborted_execution() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.enqueue_task(ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
            prepaid_execution_cycles: CompoundCycles::new(
                Cycles::zero(),
                CanisterCyclesCostSchedule::Normal,
            ),
        });
        test.inject_call(Method::StopCanister, &CanisterIdRecord::from(test.canister));

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 1);
    }

    #[test]
    fn unflagged_method_is_executed_for_target_with_aborted_execution() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.enqueue_task(ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
            prepaid_execution_cycles: CompoundCycles::new(
                Cycles::zero(),
                CanisterCyclesCostSchedule::Normal,
            ),
        });
        test.inject_canister_status_call(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }

    #[test]
    fn install_code_is_skipped_with_ongoing_long_install_code() {
        let mut test = CanExecuteSubnetMsgTest::with_instruction_limit(1_000_000_000);

        test.inject_install_code_call_to_ic00(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 1);
    }

    #[test]
    fn normal_execution() {
        let mut test = CanExecuteSubnetMsgTest::new();

        test.inject_canister_status_call(test.canister);

        assert_eq!(test.state().subnet_queues().input_queues_message_count(), 1);
        let new_state = test.drain_subnet_messages();
        assert_eq!(new_state.subnet_queues().input_queues_message_count(), 0);
    }
}
