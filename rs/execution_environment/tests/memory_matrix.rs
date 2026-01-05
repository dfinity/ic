/*!

This module contains matrix tests for canister memory usage/allocation, reserved cycles,
and subnet available memory.

It defines multiple *scenarios* and their expectations in terms of memory usage change
and performs multiple *runs* of every scenarios with various initial parameters.

The runs ensure the following properties for every scenario:
- reserved cycles and subnet available memory are updated properly in both successful and failed executions;
- the execution fails if the subnet memory capacity would be exceeded;
- the execution fails if the reserved cycles limit would be exceeded;
- the execution fails if the canister would become frozen;
- the execution fails if the canister does not have sufficient balance to reserve storage cycles;
- the execution does not allocate additional memory for canisters with memory allocation.

Every memory matrix test has the following components:
- a "setup" function takes `&mut ExecutionTest` and `CanisterId` of an empty canister in that `ExecutionTest`,
  performs a setup of that canister, and returns arbitrary data of choice (could also be `()` if no data are needed)
  that are relayed to the "operation" function;
- an "operation" function takes `&mut ExecutionTest`, `CanisterId` of the canister set up before, and
  the data produced by the "setup" function before;
- an instance of `ScenarioParams` also containing `Scenario` and `MemoryUsageChange` describing
  the kind of scenario and its expectations in terms of canister memory usage change;
- an actual invokation of the matrix test suite implemented by the function `test_memory_suite`.

The existing scenarios cover the following:
- growing WASM/stable memory in canister (update) entry point;
- growing WASM/stable memory in canister reply/cleanup callback;
- taking a canister snapshot (both growing and shrinking canister memory usage);
- taking a canister snapshot and uninstalling code atomically;
- replacing a canister snapshot by a snapshot of the same size;
- loading a canister snapshot (both growing and shrinking canister memory usage);
- deleting a canister snapshot;
- installing code;
- upgrading code with growing/shrinking memory and temporary memory growth in pre-upgrade;
- reinstalling code with growing/shrinking memory;
- uploading new chunk and uploading the same chunk again;
- clearing the chunk store;
- creating a new canister snapshot by uploading its metadata (both growing and shrinking canister memory usage);
- uploading canister WASM module to its snapshot;
- uploading canister WASM chunk to its snapshot;
- increasing/decreasing canister memory allocation;
- uninstalling code.

*/

use ic_base_types::{CanisterId, NumBytes, PrincipalId, SnapshotId};
use ic_cycles_account_manager::ResourceSaturation;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    BoundedVec, CanisterSettingsArgsBuilder, CanisterSnapshotDataOffset, CanisterSnapshotResponse,
    ClearChunkStoreArgs, DeleteCanisterSnapshotArgs, LoadCanisterSnapshotArgs, LogVisibilityV2,
    Method, Payload as _, ReadCanisterSnapshotMetadataArgs, ReadCanisterSnapshotMetadataResponse,
    TakeCanisterSnapshotArgs, UpdateSettingsArgs, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadCanisterSnapshotMetadataResponse, UploadChunkArgs,
};
use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;
use ic_test_utilities::universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder, get_reply};
use ic_types::Cycles;
use ic_types::ingress::IngressState;
use ic_types::messages::{MessageId, Payload};
use num_traits::ops::saturating::SaturatingSub;
use std::cmp::max;

const T: u128 = 1_000_000_000_000;

const KIB: u64 = 1 << 10;
const GIB: u64 = 1 << 30;

/// High amount of cycles that a canister under test is created with
/// to ensure that it has enough cycles for any setup.
const CANISTER_CREATION_CYCLES: u128 = 200_000 * T;

/// Default amount of cycles before running the operation under test,
/// i.e., after running the setup for the operation under test.
const DEFAULT_INITIAL_CYCLES: u128 = 100_000 * T;

/// Long freezing threshold so that the freezing limit in cycles exceeds
/// the number of reserved cycles.
const LONG_FREEZING_THRESHOLD_DAYS: u64 = 365 * 10; // 10 years
const LONG_FREEZING_THRESHOLD_SECS: u64 = LONG_FREEZING_THRESHOLD_DAYS * 24 * 3600;

/// Short freezing threshold so that the number of reserved cycles
/// exceeds the freezing limit in cycles.
const SHORT_FREEZING_THRESHOLD_DAYS: u64 = 1;
const SHORT_FREEZING_THRESHOLD_SECS: u64 = SHORT_FREEZING_THRESHOLD_DAYS * 24 * 3600;

/// The total subnet available memory and threshold at which cycles reservation kicks in.
const SUBNET_EXECUTION_MEMORY: u64 = 200 * GIB;
const SUBNET_MEMORY_THRESHOLD: u64 = 100 * GIB;

/// Default subnet memory usage before running the operation under test.
/// It is strictly above the subnet memory threshold so that cycles are reserved
/// if memory usage increases after running the operation under test.
const DEFAULT_SUBNET_MEMORY_USAGE_BEFORE_OP: u64 =
    SUBNET_MEMORY_THRESHOLD / 4 + 3 * SUBNET_EXECUTION_MEMORY / 4;

enum Scenario {
    /// Update method.
    CanisterEntryPoint,
    /// Reply callback.
    CanisterReplyCallback(Payload),
    /// Cleanup callback.
    CanisterCleanupCallback(Payload),
    /// Management canister method `install_code`.
    InstallCode,
    /// Management canister method `update_settings` increasing memory allocation.
    IncreaseMemoryAllocation,
    /// Management canister method `update_settings` decreasing memory allocation.
    DecreaseMemoryAllocation,
    /// Other management canister method.
    OtherManagement,
}

enum MemoryUsageChange {
    /// Memory usage strictly increases after running the operation under test.
    Increase,
    /// Memory usage does not change after running the operation under test.
    None,
    /// Memory usage strictly decreases after running the operation under test.
    Decrease,
}

struct ScenarioParams<F, G> {
    scenario: Scenario,
    /// Expectation (to be asserted) on memory usage change after running the operation under test.
    memory_usage_change: MemoryUsageChange,
    /// The setup for the operation under test;
    /// property checks apply only to the operation under test!
    setup: F,
    /// The operation under test.
    op: G,
}

#[derive(Clone, Copy)]
enum FreezingThreshold {
    /// Short freezing threshold so that the number of reserved cycles
    /// exceeds the freezing limit in cycles.
    Short,
    /// Long freezing threshold so that the freezing limit in cycles exceeds
    /// the number of reserved cycles.
    Long,
}

impl FreezingThreshold {
    fn get(&self) -> u64 {
        match self {
            FreezingThreshold::Short => SHORT_FREEZING_THRESHOLD_SECS,
            FreezingThreshold::Long => LONG_FREEZING_THRESHOLD_SECS,
        }
    }
}

#[derive(Clone, Copy)]
enum MemoryAllocation {
    /// Memory allocation of 0.
    BestEffort,
    /// Small non-zero memory allocation.
    Small,
    /// Memory allocation that is "crossed" during the test, i.e.,
    /// the memory usage is strictly below the memory allocation
    /// before running the operation under test
    /// and the memory usage is strictly above the memory allocation
    /// after running the operation under test or vice-versa.
    CrossedDuringTest,
    /// Large memory allocation covering the memory usage of the canister at all times
    /// (this property is also asserted in the tests).
    Large,
}

/// The following parameters apply before running the operation under test.
#[derive(Clone)]
struct RunParams {
    initial_cycles: Cycles,
    freezing_threshold: FreezingThreshold,
    memory_allocation: MemoryAllocation,
    reserved_cycles_limit: Cycles,
    subnet_memory_usage: NumBytes,
}

struct RunResult {
    /// Error when running the operation under test.
    /// `None` if the operation under test succeeded.
    err: Option<UserError>,
    /// The number of additional allocated bytes after running the operation under test.
    allocated_bytes: NumBytes,
    /// The number of additional reserved cycles after running the operation under test.
    reserved_cycles: Cycles,
    /// The minimum amount of initial cycles before running the operation under test.
    /// Only applicable if `allocated_bytes` is not zero.
    minimum_initial_cycles: Cycles,
}

#[must_use]
fn run<F, G, H>(scenario_params: &ScenarioParams<F, G>, run_params: RunParams) -> RunResult
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError>,
{
    let scaling = 4;
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(scaling * SUBNET_EXECUTION_MEMORY)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(scaling * SUBNET_MEMORY_THRESHOLD)
        .with_resource_saturation_scaling(scaling as usize)
        .with_manual_execution()
        .build();

    let initial_subnet_available_memory = test.subnet_available_memory();

    // Create and setup the canister under test.
    let canister_id = test.create_canister(CANISTER_CREATION_CYCLES.into());
    let setup_res = (scenario_params.setup)(&mut test, canister_id);
    let memory_usage_after_setup = test.canister_state(canister_id).memory_usage();
    let memory_allocation = match run_params.memory_allocation {
        MemoryAllocation::BestEffort => 0,
        MemoryAllocation::Small => 1,
        MemoryAllocation::CrossedDuringTest => {
            // Things to consider when chosing offset:
            // - chunk store changes memory usage by 1MiB at most
            // - canister logging changes memory by 3 OS-pages of 4 KiB (12 KiB)
            let memory_allocation_crossed_offset = 6 * KIB;
            match scenario_params.memory_usage_change {
                MemoryUsageChange::Increase => {
                    // What increases memory usage: chunk upload, installing code (canister logs).
                    memory_usage_after_setup.get() + memory_allocation_crossed_offset
                }
                MemoryUsageChange::None => match scenario_params.scenario {
                    Scenario::IncreaseMemoryAllocation => {
                        assert!(memory_usage_after_setup.get() >= GIB);
                        memory_usage_after_setup.get() - GIB
                    }
                    Scenario::DecreaseMemoryAllocation => memory_usage_after_setup.get() + GIB,
                    _ => memory_usage_after_setup.get(),
                },
                MemoryUsageChange::Decrease => {
                    // What decreases memory usage: clearning chunk store, uninstalling/deleting canister (canister logs).
                    assert!(memory_usage_after_setup.get() >= memory_allocation_crossed_offset);
                    memory_usage_after_setup.get() - memory_allocation_crossed_offset
                }
            }
        }
        MemoryAllocation::Large => 80 * GIB,
    };
    let settings = CanisterSettingsArgsBuilder::new()
        .with_freezing_threshold(run_params.freezing_threshold.get())
        .with_memory_allocation(memory_allocation)
        .with_reserved_cycles_limit(run_params.reserved_cycles_limit.get())
        .build();
    test.update_settings(canister_id, settings).unwrap();
    // Refund for response transmission is credited before running the operation under test
    // and thus we subtract it from the initial cycles before running the operation under test.
    let refund_for_response_transmission = match &scenario_params.scenario {
        Scenario::CanisterReplyCallback(response) | Scenario::CanisterCleanupCallback(response) => {
            test.refund_for_response_transmission(response)
        }
        _ => Cycles::zero(),
    };
    assert!(run_params.initial_cycles >= refund_for_response_transmission);
    let initial_cycles = run_params.initial_cycles - refund_for_response_transmission;
    let consume_cycles = test.canister_state(canister_id).system_state.balance() - initial_cycles;
    test.consume_cycles(canister_id, consume_cycles);
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_cycles
    );

    // Deploy a dummy canister to fill the subnet memory up to the provided subnet memory usage.
    let dummy_canister_initial_cycles: Cycles = DEFAULT_INITIAL_CYCLES.into();
    let memory_allocated_bytes_after_setup =
        test.canister_state(canister_id).memory_allocated_bytes();
    assert!(memory_allocated_bytes_after_setup <= run_params.subnet_memory_usage);
    let dummy_canister_memory_allocation =
        run_params.subnet_memory_usage - memory_allocated_bytes_after_setup;
    let dummy_canister_settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(dummy_canister_memory_allocation.get())
        .with_reserved_cycles_limit(dummy_canister_initial_cycles.get())
        .build();
    let dummy_canister_id = test
        .create_canister_with_settings(dummy_canister_initial_cycles, dummy_canister_settings)
        .unwrap();

    // Capture the subnet memory saturation before running the operation.
    let subnet_memory_saturation = test.subnet_memory_saturation();
    let expected_subnet_memory_saturation = ResourceSaturation::new(
        run_params.subnet_memory_usage.get(),
        SUBNET_MEMORY_THRESHOLD,
        SUBNET_EXECUTION_MEMORY,
    );
    assert_eq!(subnet_memory_saturation, expected_subnet_memory_saturation);

    // Checks before running the operation.
    let reserved_balance = |test: &ExecutionTest| {
        test.canister_state(canister_id)
            .system_state
            .reserved_balance()
    };
    // No cycles should be reserved before running the operation under test.
    assert_eq!(reserved_balance(&test), Cycles::zero());
    // A large memory allocation should cover the canister's memory usage at all times
    // (in particular, now before running the operation under test).
    if let MemoryAllocation::Large = run_params.memory_allocation {
        let memory_usage = test.canister_state(canister_id).memory_usage();
        assert!(memory_usage.get() <= memory_allocation);
    }
    // Ensure that memory allocation is "crossed" if applicable.
    if let MemoryAllocation::CrossedDuringTest = run_params.memory_allocation {
        let current_memory_usage = test.canister_state(canister_id).memory_usage().get();
        match scenario_params.memory_usage_change {
            MemoryUsageChange::Increase => assert!(current_memory_usage < memory_allocation),
            MemoryUsageChange::None => match scenario_params.scenario {
                Scenario::IncreaseMemoryAllocation => {
                    assert!(current_memory_usage > memory_allocation)
                }
                Scenario::DecreaseMemoryAllocation => {
                    assert!(current_memory_usage < memory_allocation)
                }
                _ => assert_eq!(current_memory_usage, memory_allocation),
            },
            MemoryUsageChange::Decrease => assert!(current_memory_usage > memory_allocation),
        }
    }

    // Run the operation under test.
    let initial_history_memory_usage = test
        .canister_state(canister_id)
        .canister_history_memory_usage();
    let initial_memory_usage = test.canister_state(canister_id).memory_usage();
    let initial_allocated_bytes = test.canister_state(canister_id).memory_allocated_bytes();
    let initial_executed_instructions = test.canister_executed_instructions(canister_id);
    // To test cleanup callback, we must make the operation fail (we do so by trapping with the message "This is an expected trap!"),
    // but we do not report such a failure unless the cleanup callback itself failed.
    let err = match scenario_params.scenario {
        Scenario::CanisterCleanupCallback(_) => {
            let err = (scenario_params.op)(&mut test, canister_id, setup_res).unwrap();
            assert!(err.description().contains("This is an expected trap!"));
            if err.description().contains("call_on_cleanup also failed") {
                Some(err)
            } else {
                None
            }
        }
        _ => (scenario_params.op)(&mut test, canister_id, setup_res),
    };
    let final_executed_instructions = test.canister_executed_instructions(canister_id);
    let final_history_memory_usage = test
        .canister_state(canister_id)
        .canister_history_memory_usage();
    let final_memory_usage = match scenario_params.scenario {
        // Canister history memory usage is not properly accounted by most management canister methods.
        Scenario::OtherManagement => {
            test.canister_state(canister_id).memory_usage() - final_history_memory_usage
                + initial_history_memory_usage
        }
        _ => test.canister_state(canister_id).memory_usage(),
    };
    // We cannot use `CanisterState::memory_allocated_bytes` here because of canister history memory usage.
    let final_allocated_bytes = test
        .canister_state(canister_id)
        .memory_allocation()
        .allocated_bytes(final_memory_usage);
    let newly_allocated_bytes = final_allocated_bytes.saturating_sub(&initial_allocated_bytes);
    // Note. The cycles prepayment in `install_code` is refunded before cycles are reserved
    // and freezing threshold checked and thus we can ignore it here.
    // The cycles prepayment for response callback execution is charged during setup
    // and thus we can also ignore it here.
    let unused_cycles_prepayment = match scenario_params.scenario {
        Scenario::CanisterEntryPoint => {
            let used_instructions = final_executed_instructions - initial_executed_instructions;
            let limit = test.max_instructions_per_message();
            let unused_instructions = limit - used_instructions;
            test.convert_instructions_to_cycles(unused_instructions, WasmExecutionMode::Wasm32)
        }
        _ => Cycles::zero(),
    };
    // Note. We checked that reserved balance is zero before running the operation under test
    // and thus the reserved balance after running the operation is equal to
    // the newly reserved cycles during the operation under test.
    let newly_reserved_cycles = reserved_balance(&test);
    // We also derive the freezing limit in cycles after running the operation under test.
    let idle_cycles_burned_per_day =
        test.idle_cycles_burned_per_day_for_memory_usage(canister_id, final_memory_usage);
    let freezing_limit_cycles =
        idle_cycles_burned_per_day * (run_params.freezing_threshold.get() / (24 * 3600));

    // Checks after running the operation.
    // Cycles are reserved if and only if new bytes are allocated
    // (this is a property of this test suite, not a general protocol property).
    assert_eq!(
        newly_reserved_cycles.get() > 0,
        newly_allocated_bytes.get() > 0
    );
    if err.is_none() {
        // The newly reserved cycles correspond to the newly allocated bytes
        // at the subnet memory saturation before running the operation under test.
        let expected_reserved_cycles = test
            .expected_storage_reservation_cycles(&subnet_memory_saturation, newly_allocated_bytes);
        assert_eq!(newly_reserved_cycles, expected_reserved_cycles);
        // The memory usage changed as expected.
        match scenario_params.memory_usage_change {
            MemoryUsageChange::Increase => assert!(initial_memory_usage < final_memory_usage),
            MemoryUsageChange::None => assert_eq!(initial_memory_usage, final_memory_usage),
            MemoryUsageChange::Decrease => assert!(initial_memory_usage > final_memory_usage),
        };
        if newly_allocated_bytes.get() > 0 {
            // The freezing threshold has the property that either
            // freezing limit in cycles or reserved cycles dominate.
            match run_params.freezing_threshold {
                FreezingThreshold::Long => {
                    assert!(freezing_limit_cycles > newly_reserved_cycles);
                }
                FreezingThreshold::Short => {
                    assert!(newly_reserved_cycles > freezing_limit_cycles);
                }
            };
        }
        match scenario_params.memory_usage_change {
            MemoryUsageChange::Increase => {
                assert!(initial_allocated_bytes <= final_allocated_bytes);
                // New bytes are *allocated* if and only if the memory usage is not covered
                // by memory allocation, i.e., if memory allocation is "large".
                assert_eq!(
                    newly_allocated_bytes.get() > 0,
                    !matches!(run_params.memory_allocation, MemoryAllocation::Large)
                )
            }
            // If memory usage does not change, then allocated bytes
            // only change if memory allocation changes.
            MemoryUsageChange::None => match scenario_params.scenario {
                Scenario::IncreaseMemoryAllocation => {
                    assert!(initial_allocated_bytes < final_allocated_bytes)
                }
                Scenario::DecreaseMemoryAllocation => {
                    // If memory usage exceeds memory allocation, then
                    // no bytes are deallocated when memory allocation decreases.
                    if initial_memory_usage.get() > memory_allocation {
                        assert_eq!(initial_allocated_bytes, final_allocated_bytes);
                    } else {
                        assert!(initial_allocated_bytes > final_allocated_bytes);
                    }
                }
                _ => assert_eq!(initial_allocated_bytes, final_allocated_bytes),
            },
            MemoryUsageChange::Decrease => {
                assert!(initial_allocated_bytes >= final_allocated_bytes)
            }
        };
        // Ensure that memory allocation is "crossed" if applicable.
        if let MemoryAllocation::CrossedDuringTest = run_params.memory_allocation {
            let current_memory_usage = test.canister_state(canister_id).memory_usage().get();
            let current_memory_allocation = test
                .canister_state(canister_id)
                .system_state
                .memory_allocation
                .pre_allocated_bytes()
                .get();
            match scenario_params.memory_usage_change {
                MemoryUsageChange::Increase => {
                    assert!(
                        current_memory_usage > current_memory_allocation,
                        "current_memory_usage: {}, current_memory_allocation: {}",
                        current_memory_usage,
                        current_memory_allocation
                    )
                }
                MemoryUsageChange::None => match scenario_params.scenario {
                    Scenario::IncreaseMemoryAllocation => {
                        assert!(current_memory_usage < current_memory_allocation)
                    }
                    Scenario::DecreaseMemoryAllocation => {
                        assert!(current_memory_usage > current_memory_allocation)
                    }
                    _ => {
                        // Memory allocation is set to match the memory usage after setup,
                        // but canister history memory usage can increase even in case of `MemoryUsageChange::None`.
                        let canister_history_memory_usage_increase =
                            final_history_memory_usage - initial_history_memory_usage;
                        assert_eq!(
                            current_memory_usage,
                            current_memory_allocation
                                + canister_history_memory_usage_increase.get()
                        );
                    }
                },
                MemoryUsageChange::Decrease => {
                    assert!(
                        current_memory_usage < current_memory_allocation,
                        "current_memory_usage: {}, current_memory_allocation: {}",
                        current_memory_usage,
                        current_memory_allocation
                    )
                }
            }
        }
    } else {
        // No changes if the operation under test failed.
        assert_eq!(newly_reserved_cycles, Cycles::zero());
        assert_eq!(initial_memory_usage, final_memory_usage);
        assert_eq!(initial_allocated_bytes, final_allocated_bytes);
    }
    // A large memory allocation should cover the canister's memory usage at all times
    // (in particular, now after running the operation under test).
    if let MemoryAllocation::Large = run_params.memory_allocation {
        let memory_usage = test.canister_state(canister_id).memory_usage();
        assert!(memory_usage.get() <= memory_allocation);
    }

    // Check that subnet available memory has been updated properly
    // after running the operation under test.
    let canister_allocated_bytes = test.canister_state(canister_id).memory_allocated_bytes();
    let dummy_canister_allocated_bytes = test
        .canister_state(dummy_canister_id)
        .memory_allocated_bytes();
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
            + canister_allocated_bytes.get() as i64
            + dummy_canister_allocated_bytes.get() as i64
    );

    // Refund for response execution is credited after running the operation under test
    // and thus we add it to the initial cycles before running the operation under test
    // when checking that the total amount of cycles did not increase.
    let refund_for_response_execution = match &scenario_params.scenario {
        Scenario::CanisterReplyCallback(_) | Scenario::CanisterCleanupCallback(_) => {
            test.prepayment_for_response_execution(WasmExecutionMode::Wasm32)
        }
        _ => Cycles::zero(),
    };
    // Check that the total amount of cycles did not increase.
    let total_cycles_balance =
        test.canister_state(canister_id).system_state.balance() + newly_reserved_cycles;
    assert!(run_params.initial_cycles + refund_for_response_execution >= total_cycles_balance);

    // Return result.
    let cycles_used = run_params.initial_cycles - total_cycles_balance;
    let minimum_initial_cycles =
        cycles_used + max(newly_reserved_cycles, freezing_limit_cycles) + unused_cycles_prepayment;
    RunResult {
        err,
        allocated_bytes: newly_allocated_bytes,
        reserved_cycles: newly_reserved_cycles,
        minimum_initial_cycles,
    }
}

fn test_subnet_memory_capacity<F, G, H>(
    scenario_params: &ScenarioParams<F, G>,
    default_run_params: RunParams,
    allocated_bytes: NumBytes,
) where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    let maximum_subnet_memory_usage = NumBytes::from(SUBNET_EXECUTION_MEMORY) - allocated_bytes;

    // Test that the operation succeeds if the subnet is as close as possible to its memory capacity.
    let run_params = RunParams {
        subnet_memory_usage: maximum_subnet_memory_usage,
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    assert!(res.err.is_none());

    if allocated_bytes > NumBytes::from(0) {
        // Test that the operation fails if the subnet is too close to its memory capacity.
        let run_params = RunParams {
            subnet_memory_usage: maximum_subnet_memory_usage + NumBytes::from(1),
            ..default_run_params
        };
        let res = run(scenario_params, run_params);
        let err = res.err.unwrap();
        match scenario_params.scenario {
            Scenario::CanisterEntryPoint | Scenario::CanisterReplyCallback(_) => {
                assert!(
                    err.code() == ErrorCode::CanisterOutOfMemory
                        || (err.code() == ErrorCode::CanisterCalledTrap
                            && err.description().contains("ic0.stable64_grow failed"))
                );
            }
            Scenario::CanisterCleanupCallback(_) => {
                assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
                assert!(
                    err.description()
                        .contains("Canister cannot grow its memory usage.")
                        || err.description().contains("ic0.stable64_grow failed")
                );
            }
            _ => assert_eq!(err.code(), ErrorCode::SubnetOversubscribed),
        };
    }
}

fn test_reserved_cycles_limit<F, G, H>(
    scenario_params: &ScenarioParams<F, G>,
    default_run_params: RunParams,
    reserved_cycles_limit: Cycles,
) where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    // Test that the operation succeeds if the canister is as close as possible to its reserved cycles limit.
    let run_params = RunParams {
        reserved_cycles_limit,
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    assert!(res.err.is_none());

    // Test that the operation fails if the canister would exceed its reserved cycles limit.
    let run_params = RunParams {
        reserved_cycles_limit: Cycles::from(1_u128),
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    let err = res.err.unwrap();
    match scenario_params.scenario {
        Scenario::IncreaseMemoryAllocation => assert_eq!(
            err.code(),
            ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation
        ),
        Scenario::CanisterCleanupCallback(_) => {
            assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
            assert!(
                err.description()
                    .contains("due to its reserved cycles limit")
            );
        }
        _ => assert_eq!(
            err.code(),
            ErrorCode::ReservedCyclesLimitExceededInMemoryGrow
        ),
    };
}

fn test_freezing_threshold<F, G, H>(
    scenario_params: &ScenarioParams<F, G>,
    default_run_params: RunParams,
    minimum_initial_cycles: Cycles,
) where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    // Test that the operation succeeds if the canister is as close as possible to its freezing threshold.
    let run_params = RunParams {
        initial_cycles: minimum_initial_cycles,
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    assert!(res.err.is_none());

    // Test that the operation fails if the canister is too close to its freezing threshold.
    let run_params = RunParams {
        initial_cycles: minimum_initial_cycles - Cycles::from(1_u128),
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    // Freezing threshold is not checked in canister response callbacks.
    if matches!(
        scenario_params.scenario,
        Scenario::CanisterReplyCallback(_) | Scenario::CanisterCleanupCallback(_)
    ) {
        assert!(res.err.is_none());
    } else {
        let err = res.err.unwrap();
        match scenario_params.scenario {
            Scenario::IncreaseMemoryAllocation => {
                assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryAllocation)
            }
            Scenario::OtherManagement => {
                assert!(
                    err.code() == ErrorCode::CanisterOutOfCycles
                        || err.code() == ErrorCode::InsufficientCyclesInMemoryGrow
                );
            }
            Scenario::CanisterCleanupCallback(_) => {
                assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
                assert!(err.description().contains("cannot grow memory"));
            }
            _ => assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow),
        };
        assert!(err.description().contains("least 1 additional cycles"));
    }
}

fn test_minimum_cycles_balance<F, G, H>(
    scenario_params: &ScenarioParams<F, G>,
    default_run_params: RunParams,
    minimum_initial_cycles: Cycles,
) where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    // Test that the operation succeeds if the canister is still able to reserve cycles.
    let run_params = RunParams {
        initial_cycles: minimum_initial_cycles,
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    assert!(res.err.is_none());

    // Test that the operation fails if the canister cannot reserve cycles
    // due to its insufficient cycles balance.
    let run_params = RunParams {
        initial_cycles: minimum_initial_cycles - Cycles::from(1_u128),
        ..default_run_params
    };
    let res = run(scenario_params, run_params);
    let err = res.err.unwrap();
    match scenario_params.scenario {
        Scenario::IncreaseMemoryAllocation => {
            assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryAllocation)
        }
        Scenario::CanisterCleanupCallback(_) => {
            assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
            assert!(err.description().contains("cannot grow memory"));
        }
        _ => assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow),
    };
    assert!(err.description().contains("least 1 additional cycles"));
}

fn test_memory_suite<F, G, H>(scenario_params: ScenarioParams<F, G>)
where
    F: Fn(&mut ExecutionTest, CanisterId) -> H + Copy,
    G: Fn(&mut ExecutionTest, CanisterId, H) -> Option<UserError> + Copy,
{
    for freezing_threshold in [FreezingThreshold::Long, FreezingThreshold::Short] {
        for memory_allocation in [
            MemoryAllocation::BestEffort,
            MemoryAllocation::Small,
            MemoryAllocation::CrossedDuringTest,
            MemoryAllocation::Large,
        ] {
            // Best-effort memory allocation (equal to zero) cannot be further decreased.
            if let Scenario::DecreaseMemoryAllocation = scenario_params.scenario
                && let MemoryAllocation::BestEffort = memory_allocation
            {
                continue;
            }

            let default_run_params = RunParams {
                initial_cycles: DEFAULT_INITIAL_CYCLES.into(),
                reserved_cycles_limit: DEFAULT_INITIAL_CYCLES.into(),
                subnet_memory_usage: DEFAULT_SUBNET_MEMORY_USAGE_BEFORE_OP.into(),
                memory_allocation,
                freezing_threshold,
            };

            // (Successful) dry-run to collect stats and check that
            // subnet available memory is updated properly
            // after running the operation under test.
            let run_params = default_run_params.clone();
            let res = run(&scenario_params, run_params);
            assert!(res.err.is_none());

            test_subnet_memory_capacity(
                &scenario_params,
                default_run_params.clone(),
                res.allocated_bytes,
            );

            if res.allocated_bytes > NumBytes::from(0) {
                test_reserved_cycles_limit(
                    &scenario_params,
                    default_run_params.clone(),
                    res.reserved_cycles,
                );

                match freezing_threshold {
                    FreezingThreshold::Long => test_freezing_threshold(
                        &scenario_params,
                        default_run_params.clone(),
                        res.minimum_initial_cycles,
                    ),
                    FreezingThreshold::Short => test_minimum_cycles_balance(
                        &scenario_params,
                        default_run_params.clone(),
                        res.minimum_initial_cycles,
                    ),
                }
            }
        }
    }
}

fn memory_grow_payload(heap_pages: u64, stable_pages: u64, reply: bool) -> Vec<u8> {
    let mut payload = wasm()
        .wasm_memory_grow(heap_pages.try_into().unwrap())
        .stable64_grow(stable_pages)
        .int64_to_blob()
        .trap_if_eq(u64::MAX.to_le_bytes(), "ic0.stable64_grow failed");
    if reply {
        payload = payload.reply();
    }
    payload.build()
}

fn setup_universal_canister(test: &mut ExecutionTest, canister_id: CanisterId) {
    test.install_canister_with_args(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        // we push equal bytes onto the stack so that enough working memory is reserved during setup
        // and simple stack operations do not accidentally increase memory usage
        wasm().push_equal_bytes(0, 1024).build(),
    )
    .unwrap();
}

fn setup_universal_canister_with_much_memory(test: &mut ExecutionTest, canister_id: CanisterId) {
    let payload = memory_grow_payload(GIB >> 16, GIB >> 16, false);
    test.install_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
        .unwrap();
}

/// Setups a fixed memory canister with no custom sections.
/// Custom section size matters in canister snapshot tests
/// since it is accounted for in canister memory usage,
/// but not in canister snapshot memory usage.
fn setup_fixed_memory_canister(test: &mut ExecutionTest, canister_id: CanisterId) {
    const FIXED_MEMORY_WAT: &str = r#"
    (module
        (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
        (func $init
            (drop (call $stable64_grow (i64.const 1024))))
        (memory $memory 1024)
        (export "canister_init" (func $init))
    )"#;
    let fixed_memory_wasm = wat::parse_str(FIXED_MEMORY_WAT).unwrap();
    test.install_canister(canister_id, fixed_memory_wasm)
        .unwrap();
}

fn test_memory_suite_grow_memory_entry_point_(payload: Vec<u8>) {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let msg_id = test.ingress_raw(canister_id, "update", payload.clone()).0;
        test.execute_all();
        test.ingress_result(&msg_id).err()
    };
    let params = ScenarioParams {
        scenario: Scenario::CanisterEntryPoint,
        memory_usage_change: MemoryUsageChange::Increase,
        setup: setup_universal_canister,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_grow_memory_entry_point() {
    for payload in [
        memory_grow_payload(GIB >> 16, 0, true), // wasm memory
        memory_grow_payload(0, GIB >> 16, true), // stable memory
    ] {
        test_memory_suite_grow_memory_entry_point_(payload);
    }
}

fn test_memory_suite_grow_memory_callback(call_args: CallArgs, scenario: Scenario) {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let payload = wasm()
            .call_simple(canister_id, "update", call_args.clone())
            .build();
        let msg_id = test.ingress_raw(canister_id, "update", payload).0;
        // Execute the entry point of the update call.
        test.execute_message(canister_id);
        // Induct the inter-canister call.
        test.induct_messages();
        // Execute the inter-canister call.
        test.execute_message(canister_id);
        // Induct the response.
        test.induct_messages();
        msg_id
    };
    let op = |test: &mut ExecutionTest, canister_id, msg_id: MessageId| {
        // The update call is still processing before executing the response.
        assert!(matches!(
            test.ingress_state(&msg_id),
            IngressState::Processing
        ));
        // Execute the response (reply/cleanup callback).
        test.execute_message(canister_id);
        test.ingress_result(&msg_id).err()
    };
    let params = ScenarioParams {
        scenario,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_grow_memory_reply_callback() {
    for grow_payload in [
        memory_grow_payload(GIB >> 16, 0, true), // wasm memory
        memory_grow_payload(0, GIB >> 16, true), // stable memory
    ] {
        let call_args = CallArgs::default()
            .other_side(wasm().reply().build())
            .on_reply(grow_payload);
        let response = Payload::Data(vec![]);
        let scenario = Scenario::CanisterReplyCallback(response);
        test_memory_suite_grow_memory_callback(call_args, scenario);
    }
}

#[test]
fn test_memory_suite_grow_memory_cleanup_callback() {
    for grow_payload in [
        memory_grow_payload(GIB >> 16, 0, false), // wasm memory
        memory_grow_payload(0, GIB >> 16, false), // stable memory
    ] {
        let call_args = CallArgs::default()
            .other_side(wasm().reply().build())
            .on_reply(wasm().trap_with_blob(b"This is an expected trap!").build())
            .on_cleanup(grow_payload);
        let response = Payload::Data(vec![]);
        let scenario = Scenario::CanisterCleanupCallback(response);
        test_memory_suite_grow_memory_callback(call_args, scenario);
    }
}

#[test]
fn test_memory_suite_take_snapshot_growing_memory_usage() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Increase,
        setup: setup_universal_canister,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_take_snapshot_shrinking_memory_usage() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister_with_much_memory(test, canister_id);
        // Take a "large" canister snapshot.
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id;
        // Reinstall the canister so that its memory usage is small and
        // taking a new ("small") snapshot while replacing the "large" snapshot
        // decreases the canister memory usage overall.
        test.reinstall_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id), None, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_replace_snapshot() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id), None, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::None,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_take_snapshot_and_uninstall_code() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_fixed_memory_canister(test, canister_id);
        // We upload a chunk to test that its memory usage is accounted for
        // after uninstalling the canister.
        let upload_chunk_args = UploadChunkArgs {
            canister_id: canister_id.get(),
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(Method::UploadChunk, upload_chunk_args.encode())
            .unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, Some(true), None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_load_snapshot_growing_memory_usage() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id;
        test.uninstall_code(canister_id).unwrap();
        snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let load_canister_snapshot_args =
            LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
        test.subnet_message(
            Method::LoadCanisterSnapshot,
            load_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_load_snapshot_shrinking_memory_usage() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        // Take a "small" snapshot.
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id;
        // Grow the memory usage of the canister so that loading the "small" snapshot later
        // decreases the canister memory usage.
        let grow_payload = memory_grow_payload(GIB >> 16, GIB >> 16, true);
        let msg_id = test.ingress_raw(canister_id, "update", grow_payload).0;
        test.execute_all();
        // Ensure that the update call to grow memory succeeded.
        test.ingress_result(&msg_id).unwrap();
        snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let load_canister_snapshot_args =
            LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
        test.subnet_message(
            Method::LoadCanisterSnapshot,
            load_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_delete_snapshot() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister_with_much_memory(test, canister_id);
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
        let res = test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        );
        CanisterSnapshotResponse::decode(&get_reply(res))
            .unwrap()
            .id
    };
    let op = |test: &mut ExecutionTest, canister_id, snapshot_id| {
        let delete_canister_snapshot_args =
            DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
        test.subnet_message(
            Method::DeleteCanisterSnapshot,
            delete_canister_snapshot_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_install_code() {
    let setup = |_test: &mut ExecutionTest, _canister_id: CanisterId| {};
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload(GIB >> 16, GIB >> 16, false);
        test.install_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::InstallCode,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

// This test grows memory in both pre- and post-upgrade.
#[test]
fn test_memory_suite_upgrade_code_and_grow_memory() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let pre_upgrade_grow_payload = memory_grow_payload(GIB >> 16, GIB >> 16, false);
        let msg_id = test
            .ingress_raw(
                canister_id,
                "update",
                wasm()
                    .set_pre_upgrade(pre_upgrade_grow_payload)
                    .reply()
                    .build(),
            )
            .0;
        test.execute_all();
        // Ensure that setting code to execute in pre-upgrade succeeded.
        test.ingress_result(&msg_id).unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload((2 * GIB) >> 16, (2 * GIB) >> 16, false);
        test.upgrade_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::InstallCode,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

// This test grows memory in pre-upgrade, but shrinks memory in post-upgrade to less memory than before pre-upgrade.
// Before pre-upgrade: ~2GiB.
// After pre-upgrade: ~3GiB.
// After post-uprade: ~1GiB (stable memory).
#[test]
fn test_memory_suite_upgrade_code_and_shrink_memory() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        let payload = memory_grow_payload(GIB >> 16, GIB >> 16, false);
        test.install_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .unwrap();
        let pre_upgrade_grow_payload = memory_grow_payload(GIB >> 16, 0, false);
        let msg_id = test
            .ingress_raw(
                canister_id,
                "update",
                wasm()
                    .set_pre_upgrade(pre_upgrade_grow_payload)
                    .reply()
                    .build(),
            )
            .0;
        test.execute_all();
        // Ensure that setting code to execute in pre-upgrade succeeded.
        test.ingress_result(&msg_id).unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::InstallCode,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_reinstall_code_and_grow_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        let payload = memory_grow_payload(GIB >> 16, GIB >> 16, false);
        test.reinstall_canister_with_args(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), payload)
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::InstallCode,
        memory_usage_change: MemoryUsageChange::Increase,
        setup: setup_universal_canister,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_reinstall_code_and_shrink_memory() {
    let op = |test: &mut ExecutionTest, canister_id, ()| {
        test.reinstall_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::InstallCode,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup: setup_universal_canister_with_much_memory,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_upload_chunk() {
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        let upload_chunk_args = UploadChunkArgs {
            canister_id: canister_id.get(),
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(Method::UploadChunk, upload_chunk_args.encode())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Increase,
        setup: setup_universal_canister,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_upload_chunk_idempotent() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let upload_chunk_args = UploadChunkArgs {
            canister_id: canister_id.get(),
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(Method::UploadChunk, upload_chunk_args.encode())
            .unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        let upload_chunk_args = UploadChunkArgs {
            canister_id: canister_id.get(),
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(Method::UploadChunk, upload_chunk_args.encode())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::None,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_clear_chunk_store() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        let upload_chunk_args = UploadChunkArgs {
            canister_id: canister_id.get(),
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(Method::UploadChunk, upload_chunk_args.encode())
            .unwrap();
    };
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        let clear_chunk_store_args = ClearChunkStoreArgs {
            canister_id: canister_id.get(),
        };
        test.subnet_message(Method::ClearChunkStore, clear_chunk_store_args.encode())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

fn take_snapshot_and_read_metadata(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
) -> (SnapshotId, ReadCanisterSnapshotMetadataResponse) {
    let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
    let res = test.subnet_message(
        Method::TakeCanisterSnapshot,
        take_canister_snapshot_args.encode(),
    );
    let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
        .unwrap()
        .id;
    let snapshot_metadata_args = ReadCanisterSnapshotMetadataArgs {
        canister_id: canister_id.get(),
        snapshot_id,
    };
    let res = test.subnet_message(
        Method::ReadCanisterSnapshotMetadata,
        snapshot_metadata_args.encode(),
    );
    let bytes = get_reply(res);
    let metadata = ReadCanisterSnapshotMetadataResponse::decode(&bytes).unwrap();
    (snapshot_id, metadata)
}

fn metadata_upload_payload(
    canister_id: CanisterId,
    metadata: ReadCanisterSnapshotMetadataResponse,
    replace_snapshot: Option<SnapshotId>,
) -> UploadCanisterSnapshotMetadataArgs {
    UploadCanisterSnapshotMetadataArgs {
        canister_id: canister_id.get(),
        replace_snapshot,
        wasm_module_size: metadata.wasm_module_size,
        globals: metadata.globals,
        wasm_memory_size: metadata.wasm_memory_size,
        stable_memory_size: metadata.stable_memory_size,
        certified_data: metadata.certified_data,
        global_timer: metadata.global_timer,
        on_low_wasm_memory_hook_status: metadata.on_low_wasm_memory_hook_status,
    }
}

#[test]
fn test_memory_suite_upload_canister_snapshot_metadata_growing_memory_usage() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        take_snapshot_and_read_metadata(test, canister_id).1
    };
    let op = |test: &mut ExecutionTest,
              canister_id: CanisterId,
              metadata: ReadCanisterSnapshotMetadataResponse| {
        test.subnet_message(
            Method::UploadCanisterSnapshotMetadata,
            metadata_upload_payload(canister_id, metadata, None).encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_upload_canister_snapshot_metadata_shrinking_memory_usage() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister_with_much_memory(test, canister_id);
        // Take a "large" snapshot and read its metadata.
        let (snapshot_id, mut metadata) = take_snapshot_and_read_metadata(test, canister_id);
        // Update the metadata to make the snapshot "small"
        // so that uploading the metadata while replacing the "large" snapshot
        // decreases the canister memory usage overall.
        metadata.wasm_memory_size = 0;
        metadata.stable_memory_size = 0;
        (snapshot_id, metadata)
    };
    let op =
        |test: &mut ExecutionTest,
         canister_id: CanisterId,
         (snapshot_id, metadata): (SnapshotId, ReadCanisterSnapshotMetadataResponse)| {
            test.subnet_message(
                Method::UploadCanisterSnapshotMetadata,
                metadata_upload_payload(canister_id, metadata, Some(snapshot_id)).encode(),
            )
            .err()
        };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_upload_canister_snapshot_data_wasm_module() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let metadata = take_snapshot_and_read_metadata(test, canister_id).1;
        let res = test.subnet_message(
            Method::UploadCanisterSnapshotMetadata,
            metadata_upload_payload(canister_id, metadata, None).encode(),
        );
        UploadCanisterSnapshotMetadataResponse::decode(&get_reply(res))
            .unwrap()
            .snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, snapshot_id: SnapshotId| {
        let upload_canister_snapshot_data_args = UploadCanisterSnapshotDataArgs {
            canister_id: canister_id.get(),
            snapshot_id,
            kind: CanisterSnapshotDataOffset::WasmModule { offset: 0 },
            chunk: vec![42; 1 << 10],
        };
        test.subnet_message(
            Method::UploadCanisterSnapshotData,
            upload_canister_snapshot_data_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::None,
        setup,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_upload_canister_snapshot_data_wasm_chunk() {
    let setup = |test: &mut ExecutionTest, canister_id: CanisterId| {
        setup_universal_canister(test, canister_id);
        let metadata = take_snapshot_and_read_metadata(test, canister_id).1;
        let res = test.subnet_message(
            Method::UploadCanisterSnapshotMetadata,
            metadata_upload_payload(canister_id, metadata, None).encode(),
        );
        UploadCanisterSnapshotMetadataResponse::decode(&get_reply(res))
            .unwrap()
            .snapshot_id
    };
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, snapshot_id: SnapshotId| {
        let upload_canister_snapshot_data_args = UploadCanisterSnapshotDataArgs {
            canister_id: canister_id.get(),
            snapshot_id,
            kind: CanisterSnapshotDataOffset::WasmChunk,
            chunk: vec![42; 1 << 20],
        };
        test.subnet_message(
            Method::UploadCanisterSnapshotData,
            upload_canister_snapshot_data_args.encode(),
        )
        .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Increase,
        setup,
        op,
    };
    test_memory_suite(params);
}

fn update_memory_allocation_args(
    canister_id: CanisterId,
    memory_allocation: u64,
) -> UpdateSettingsArgs {
    // We also set log visibility to many selected principals
    // to make the payload of `update_settings` large enough
    // and thereby ensure that ingress fee is forcibly charged.
    // See `MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE` for more details.
    let allowed_viewers: Vec<_> = (0..10).map(|i| PrincipalId::new(29, [i; 29])).collect();
    let log_visibility = LogVisibilityV2::AllowedViewers(BoundedVec::new(allowed_viewers));
    let settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(memory_allocation)
        .with_log_visibility(log_visibility)
        .build();
    UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings,
        sender_canister_version: None,
    }
}

#[test]
fn test_memory_suite_increase_memory_allocation() {
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        let current_memory_allocation = test
            .canister_state(canister_id)
            .memory_allocation()
            .pre_allocated_bytes();
        let update_settings_args =
            update_memory_allocation_args(canister_id, current_memory_allocation.get() + 3 * GIB);
        test.subnet_message(Method::UpdateSettings, update_settings_args.encode())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::IncreaseMemoryAllocation,
        memory_usage_change: MemoryUsageChange::None,
        setup: setup_universal_canister_with_much_memory,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_decrease_memory_allocation() {
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        let current_memory_allocation = test
            .canister_state(canister_id)
            .memory_allocation()
            .pre_allocated_bytes();
        let update_settings_args = update_memory_allocation_args(
            canister_id,
            current_memory_allocation.get().saturating_sub(2 * GIB),
        );
        test.subnet_message(Method::UpdateSettings, update_settings_args.encode())
            .err()
    };
    let params = ScenarioParams {
        scenario: Scenario::DecreaseMemoryAllocation,
        memory_usage_change: MemoryUsageChange::None,
        setup: setup_universal_canister_with_much_memory,
        op,
    };
    test_memory_suite(params);
}

#[test]
fn test_memory_suite_uninstall_code() {
    let op = |test: &mut ExecutionTest, canister_id: CanisterId, ()| {
        test.uninstall_code(canister_id).err()
    };
    let params = ScenarioParams {
        scenario: Scenario::OtherManagement,
        memory_usage_change: MemoryUsageChange::Decrease,
        setup: setup_universal_canister_with_much_memory,
        op,
    };
    test_memory_suite(params);
}
